#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux Control Agent - coleta métricas e inventário de um servidor Linux e envia ao Linux Control Hub.
Executa apenas ações pré-aprovadas (catálogo fixo neste arquivo). Sem dependências externas:
somente a biblioteca padrão do Python 3.6+.

Uso:
  linux-control-agent.py            roda em loop (modo serviço)
  linux-control-agent.py --once     coleta tudo e imprime o JSON (não envia)
  linux-control-agent.py --test     coleta e envia uma única vez
"""
import calendar
import glob
import json
import os
import platform
import pwd
import queue
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib import error as urlerror
from urllib import request as urlrequest

VERSION = "0.1.0"
CONF_PATH = os.environ.get("LCTL_CONF", "/etc/linux-control/agent.conf")
MAX_OUTPUT = 64 * 1024
ENV_C = dict(os.environ, LC_ALL="C", LANG="C")


# ---------------------------------------------------------------- utilidades

def log(msg):
    sys.stderr.write("[linux-control-agent] %s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    sys.stderr.flush()


def load_conf():
    conf = {
        "HUB_URL": "",
        "TOKEN": "",
        "INTERVAL": "30",
        "INVENTORY_EVERY": "600",
        "PACKAGES_EVERY": "21600",
        "ACTIONS": "all",  # all | readonly | none
        "INSECURE_TLS": "0",
    }
    if os.path.exists(CONF_PATH):
        try:
            with open(CONF_PATH) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    conf[k.strip()] = v.strip().strip('"').strip("'")
        except PermissionError:
            log("sem permissão para ler %s" % CONF_PATH)
    for k in list(conf.keys()):
        if ("LCTL_" + k) in os.environ:
            conf[k] = os.environ["LCTL_" + k]
    return conf


def run(cmd, timeout=20, merge=True, shell=False, env=None):
    """Executa um comando e devolve (código, saída). Nunca levanta exceção."""
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge else subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            shell=shell,
            env=env or ENV_C,
        )
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        out = e.output or b""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return 124, out + "\n[tempo limite de %ss excedido]" % timeout
    except (FileNotFoundError, PermissionError):
        name = cmd if isinstance(cmd, str) else cmd[0]
        return 127, "comando não encontrado: %s" % name
    except Exception as e:  # pragma: no cover
        return 1, str(e)


def which(name):
    for extra in ("", "/usr/sbin/", "/sbin/", "/usr/local/sbin/"):
        p = shutil.which(extra + name) if extra else shutil.which(name)
        if p:
            return p
    return None


def read(path, default=""):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return default


def safe(fn, default=None):
    try:
        return fn()
    except Exception as e:
        log("coletor %s falhou: %s" % (getattr(fn, "__name__", "?"), e))
        return default


# Mascara senhas/tokens em linhas de comando e cron antes de enviar ao hub.
SECRET_RE = re.compile(r"(?i)((?:--?|\b)(?:pass(?:word)?|passwd|pwd|requirepass|secret|token|api[_-]?key|access[_-]?key|auth|credentials?)(?:\s*[=:]\s*|\s+))(\"[^\"]*\"|'[^']*'|\S+)")
ENV_SECRET_RE = re.compile(r"(?i)\b([A-Z0-9_]*(?:PASS(?:WORD)?|PWD|TOKEN|SECRET|API_?KEY)[A-Z0-9_]*=)(\S+)")
URL_CRED_RE = re.compile(r"(://[^/\s:@]+:)[^@\s/]+@")


def mask_secrets(text):
    text = URL_CRED_RE.sub(r"\1***@", text)
    text = ENV_SECRET_RE.sub(r"\1***", text)
    return SECRET_RE.sub(r"\1***", text)


# ---------------------------------------------------------------- métricas

REAL_FS = {
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "jfs", "reiserfs", "vfat", "exfat",
    "ntfs", "ntfs3", "f2fs", "nfs", "nfs4", "cifs", "fuseblk", "bcachefs",
}
SKIP_MOUNT_PREFIX = ("/snap/", "/var/lib/docker/", "/run/", "/proc/", "/sys/", "/var/lib/containers/")
VIRT_IF = re.compile(r"^(lo|veth|docker|br-|virbr|cni|flannel|cali|vxlan|kube|tunl)")


class Collector(object):
    def __init__(self):
        self.prev_cpu = None
        self.prev_net = None
        self.prev_proc = {}
        self.prev_total = None
        self.ncpu = os.cpu_count() or 1
        self.page = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
        self.users = {}

    def cpu_times(self):
        with open("/proc/stat") as f:
            vals = [int(x) for x in f.readline().split()[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        total = sum(vals[:8])
        return total, idle

    def cpu_percent(self):
        total, idle = self.cpu_times()
        pct = 0.0
        if self.prev_cpu:
            dt = total - self.prev_cpu[0]
            di = idle - self.prev_cpu[1]
            pct = 100.0 * (dt - di) / dt if dt > 0 else 0.0
        else:
            time.sleep(0.5)
            t2, i2 = self.cpu_times()
            dt, di = t2 - total, i2 - idle
            pct = 100.0 * (dt - di) / dt if dt > 0 else 0.0
            total, idle = t2, i2
        self.prev_cpu = (total, idle)
        return round(pct, 1)

    def meminfo(self):
        m = {}
        for line in read("/proc/meminfo").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                m[parts[0].rstrip(":")] = int(parts[1]) * 1024
        total = m.get("MemTotal", 0)
        avail = m.get("MemAvailable", m.get("MemFree", 0) + m.get("Cached", 0))
        st, sf = m.get("SwapTotal", 0), m.get("SwapFree", 0)
        return {
            "total": total,
            "available": avail,
            "used": total - avail,
            "pct": round(100.0 * (total - avail) / total, 1) if total else 0,
            "swap_total": st,
            "swap_used": st - sf,
            "swap_pct": round(100.0 * (st - sf) / st, 1) if st else 0,
        }

    def disks(self):
        out, seen = [], set()
        for line in read("/proc/mounts").splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            dev, mnt, fs = parts[0], parts[1].replace("\\040", " "), parts[2]
            if fs not in REAL_FS or mnt.startswith(SKIP_MOUNT_PREFIX):
                continue
            if dev in seen:
                continue
            seen.add(dev)
            try:
                st = os.statvfs(mnt)
            except Exception:
                continue
            total = st.f_blocks * st.f_frsize
            if total <= 0:
                continue
            free = st.f_bavail * st.f_frsize
            used = total - st.f_bfree * st.f_frsize
            ipct = round(100.0 * (st.f_files - st.f_ffree) / st.f_files, 1) if st.f_files else 0
            out.append({
                "mount": mnt, "device": dev, "fs": fs, "total": total, "used": used, "free": free,
                "pct": round(100.0 * used / (used + free), 1) if (used + free) else 0,
                "inode_pct": ipct,
            })
        return out

    def net(self):
        rx = tx = 0
        for line in read("/proc/net/dev").splitlines()[2:]:
            name, _, data = line.partition(":")
            name = name.strip()
            if VIRT_IF.match(name):
                continue
            f = data.split()
            if len(f) >= 9:
                rx += int(f[0])
                tx += int(f[8])
        now = time.time()
        rate = {"rx": 0, "tx": 0}
        if self.prev_net:
            dt = now - self.prev_net[0]
            if dt > 0:
                rate = {"rx": max(0, (rx - self.prev_net[1]) / dt), "tx": max(0, (tx - self.prev_net[2]) / dt)}
        self.prev_net = (now, rx, tx)
        return {"rx_bps": round(rate["rx"]), "tx_bps": round(rate["tx"]), "rx_total": rx, "tx_total": tx}

    def username(self, uid):
        if uid not in self.users:
            try:
                self.users[uid] = pwd.getpwuid(uid).pw_name
            except KeyError:
                self.users[uid] = str(uid)
        return self.users[uid]

    def processes(self, mem_total):
        total_now = self.cpu_times()[0]
        procs, cur = [], {}
        for pid_dir in glob.glob("/proc/[0-9]*"):
            pid = int(pid_dir[6:])
            try:
                stat = read(pid_dir + "/stat")
                if not stat:
                    continue
                rest = stat[stat.rfind(")") + 2:].split()
                ticks = int(rest[11]) + int(rest[12])
                rss = int(rest[21]) * self.page
                cur[pid] = ticks
                uid = os.stat(pid_dir).st_uid
                procs.append((pid, ticks, rss, uid, rest[0]))
            except Exception:
                continue
        dt = (total_now - self.prev_total) if self.prev_total else 0
        res = []
        for pid, ticks, rss, uid, state in procs:
            cpu = 0.0
            if dt > 0 and pid in self.prev_proc:
                cpu = 100.0 * (ticks - self.prev_proc[pid]) / dt
            res.append({"pid": pid, "cpu": round(cpu, 1), "rss": rss,
                        "mem": round(100.0 * rss / mem_total, 1) if mem_total else 0,
                        "uid": uid, "state": state})
        self.prev_proc, self.prev_total = cur, total_now
        top = sorted(res, key=lambda p: -p["cpu"])[:15]
        ids = {p["pid"] for p in top}
        top += [p for p in sorted(res, key=lambda p: -p["rss"])[:15] if p["pid"] not in ids]
        for p in top:
            p["user"] = self.username(p.pop("uid"))
            p["name"] = read("/proc/%d/comm" % p["pid"]).strip()
            cmd = read("/proc/%d/cmdline" % p["pid"]).replace("\x00", " ").strip()
            p["cmd"] = mask_secrets(cmd)[:300] or "[%s]" % p["name"]
        return {"count": len(res), "top": top,
                "zombies": sum(1 for p in res if p["state"] == "Z")}

    def metrics(self):
        mem = self.meminfo()
        la = read("/proc/loadavg").split()
        up = read("/proc/uptime").split()
        return {
            "ts": int(time.time()),
            "cpu": self.cpu_percent(),
            "ncpu": self.ncpu,
            "load": [float(x) for x in la[:3]] if len(la) >= 3 else [0, 0, 0],
            "mem": mem,
            "disks": safe(self.disks, []),
            "net": safe(self.net, {}),
            "uptime": int(float(up[0])) if up else 0,
            "procs": safe(lambda: self.processes(mem["total"]), {"count": 0, "top": []}),
        }


# ---------------------------------------------------------------- inventário

def os_release():
    d = {}
    for line in read("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k] = v.strip().strip('"')
    return d


def system_info():
    osr = os_release()
    cpu_model = ""
    for line in read("/proc/cpuinfo").splitlines():
        if line.lower().startswith(("model name", "hardware", "cpu model")):
            cpu_model = line.split(":", 1)[1].strip()
            break
    ips = []
    rc, out = run(["ip", "-o", "addr", "show"], merge=False)
    if rc == 0:
        for line in out.splitlines():
            f = line.split()
            if len(f) >= 4 and f[1] != "lo" and f[2] in ("inet", "inet6") and not f[3].startswith("fe80"):
                ips.append({"iface": f[1], "addr": f[3]})
    virt = run(["systemd-detect-virt"], merge=False)[1].strip() or "desconhecido"
    tz = run(["timedatectl", "show", "-p", "Timezone", "--value"], merge=False)[1].strip() or read("/etc/timezone").strip()
    ntp = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], merge=False)[1].strip()
    up = read("/proc/uptime").split()
    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os": osr.get("PRETTY_NAME") or platform.platform(),
        "os_id": osr.get("ID", ""),
        "os_like": osr.get("ID_LIKE", ""),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu_model": cpu_model,
        "cores": os.cpu_count(),
        "virt": virt,
        "timezone": tz,
        "ntp_synced": {"yes": True, "no": False}.get(ntp),
        "boot_time": int(time.time() - float(up[0])) if up else None,
        "ips": ips,
        "python": platform.python_version(),
        "is_root": os.geteuid() == 0,
    }


def services():
    if not which("systemctl"):
        return {"available": False, "units": []}
    rc, out = run(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend"], merge=False)
    enabled = {}
    rc2, out2 = run(["systemctl", "list-unit-files", "--type=service", "--no-pager", "--plain", "--no-legend"], merge=False)
    for line in out2.splitlines():
        f = line.split()
        if len(f) >= 2:
            enabled[f[0]] = f[1]
    units = []
    for line in out.splitlines():
        f = line.split(None, 4)
        if len(f) < 4 or f[1] == "not-found":
            continue
        units.append({"name": f[0], "load": f[1], "active": f[2], "sub": f[3],
                      "desc": f[4] if len(f) > 4 else "", "enabled": enabled.get(f[0], "")})
    return {"available": True, "units": units}


def ports():
    rc, out = run(["ss", "-tulpnH"], merge=False)
    res = []
    if rc != 0:
        return res
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        local = f[4]
        addr, _, port = local.rpartition(":")
        procs = re.findall(r'\("([^"]+)",pid=(\d+)', line)
        res.append({"proto": f[0], "addr": addr, "port": int(port) if port.isdigit() else port,
                    "process": ", ".join(sorted({p[0] for p in procs})),
                    "pid": int(procs[0][1]) if procs else None})
    res.sort(key=lambda r: (r["port"] if isinstance(r["port"], int) else 99999, r["proto"]))
    return res


def docker():
    if not which("docker"):
        return None
    rc, out = run(["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"], timeout=15, merge=False)
    if rc != 0:
        return {"available": True, "error": "docker não respondeu (daemon parado ou sem permissão)", "containers": []}
    containers = []
    for line in out.splitlines():
        try:
            c = json.loads(line)
        except ValueError:
            continue
        containers.append({"id": c.get("ID", "")[:12], "name": c.get("Names"), "image": c.get("Image"),
                           "state": c.get("State"), "status": c.get("Status"), "ports": c.get("Ports"),
                           "created": c.get("CreatedAt")})
    stats = {}
    if any(c["state"] == "running" for c in containers):
        rc, out = run(["docker", "stats", "--no-stream", "--format", "{{json .}}"], timeout=20, merge=False)
        for line in out.splitlines():
            try:
                s = json.loads(line)
                stats[s.get("Name")] = {"cpu": s.get("CPUPerc"), "mem": s.get("MemUsage"), "mem_pct": s.get("MemPerc")}
            except ValueError:
                pass
    for c in containers:
        c["stats"] = stats.get(c["name"])
    return {"available": True, "containers": containers}


KNOWN_SOFTWARE = [
    ("Nginx", "nginx", ["-v"]), ("Apache", "apache2", ["-v"]), ("Apache (httpd)", "httpd", ["-v"]),
    ("Caddy", "caddy", ["version"]), ("HAProxy", "haproxy", ["-v"]), ("Traefik", "traefik", ["version"]),
    ("MySQL", "mysqld", ["--version"]), ("MariaDB", "mariadbd", ["--version"]), ("PostgreSQL", "psql", ["--version"]),
    ("Redis", "redis-server", ["--version"]), ("MongoDB", "mongod", ["--version"]), ("Memcached", "memcached", ["-V"]),
    ("Docker", "docker", ["--version"]), ("Podman", "podman", ["--version"]), ("Kubernetes (kubectl)", "kubectl", ["version", "--client"]),
    ("K3s", "k3s", ["--version"]), ("Node.js", "node", ["--version"]), ("PM2", "pm2", None), ("PHP", "php", ["-v"]),
    ("PHP-FPM", "php-fpm", ["-v"]), ("Python 3", "python3", ["--version"]), ("Java", "java", ["-version"]),
    ("Go", "go", ["version"]), (".NET", "dotnet", ["--version"]), ("Ruby", "ruby", ["--version"]),
    ("Git", "git", ["--version"]), ("Certbot", "certbot", ["--version"]), ("Fail2ban", "fail2ban-client", ["--version"]),
    ("UFW", "ufw", ["--version"]), ("Cloudflared", "cloudflared", ["--version"]), ("Tailscale", "tailscale", ["version"]),
    ("WireGuard", "wg", ["--version"]), ("OpenVPN", "openvpn", ["--version"]), ("Postfix", "postconf", ["mail_version"]),
    ("Samba", "smbd", ["-V"]), ("Zabbix Agent", "zabbix_agentd", ["-V"]), ("Webmin", "webmin", None),
    ("Coolify", None, None), ("cPanel", None, None),
]


def software():
    res = []
    for label, binary, args in KNOWN_SOFTWARE:
        path, version = None, ""
        if binary:
            path = which(binary)
            if not path:
                continue
            if args is not None:
                rc, out = run([path] + args, timeout=6)
                version = (out.strip().splitlines() or [""])[0][:140]
            res.append({"name": label, "path": os.path.realpath(path), "version": version})
        elif label == "Coolify" and os.path.isdir("/data/coolify"):
            res.append({"name": label, "path": "/data/coolify", "version": ""})
        elif label == "cPanel" and os.path.isdir("/usr/local/cpanel"):
            res.append({"name": label, "path": "/usr/local/cpanel", "version": read("/usr/local/cpanel/version").strip()})
    return res


def packages():
    """Lista de pacotes instalados e atualizações pendentes."""
    pm, items, updates = None, [], []
    if which("dpkg-query"):
        pm = "apt"
        rc, out = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Package}\t${Version}\n"], timeout=30, merge=False)
        for line in out.splitlines():
            f = line.split("\t")
            if len(f) == 3 and f[0].startswith("ii"):
                items.append([f[1], f[2]])
        rc, out = run(["apt", "list", "--upgradable"], timeout=60, merge=False)
        for line in out.splitlines():
            m = re.match(r"^([^/\s]+)/(\S+)\s+(\S+)\s+\S+(?:\s+\[upgradable from: ([^\]]+)\])?", line)
            if m:
                updates.append({"name": m.group(1), "source": m.group(2), "new": m.group(3),
                                "current": m.group(4) or "", "security": "security" in m.group(2)})
    elif which("rpm"):
        pm = "dnf" if which("dnf") else "yum"
        rc, out = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=30, merge=False)
        items = [l.split("\t") for l in out.splitlines() if "\t" in l]
        sec = set()
        rc, out = run([pm, "-C", "-q", "updateinfo", "list", "security"], timeout=90, merge=False)
        for line in out.splitlines():
            f = line.split()
            if len(f) >= 3:
                sec.add(f[-1].rsplit("-", 2)[0])
        rc, out = run([pm, "-C", "-q", "check-update"], timeout=90, merge=False)
        for line in out.splitlines():
            f = line.split()
            if len(f) == 3 and "." in f[0] and not line.startswith(" "):
                name = f[0].rsplit(".", 1)[0]
                updates.append({"name": name, "source": f[2], "new": f[1], "current": "", "security": name in sec})
    elif which("apk"):
        pm = "apk"
        rc, out = run(["apk", "info", "-v"], timeout=30, merge=False)
        for line in out.splitlines():
            m = re.match(r"^(.+)-(\d[^-]*-r\d+)$", line.strip())
            if m:
                items.append([m.group(1), m.group(2)])
        rc, out = run(["apk", "version", "-l", "<"], timeout=30, merge=False)
        for line in out.splitlines()[1:]:
            f = line.split()
            if f:
                updates.append({"name": f[0], "source": "", "new": f[-1] if len(f) > 2 else "", "current": "", "security": False})
    items.sort(key=lambda x: x[0])
    return {"manager": pm, "installed": items, "updates": updates, "collected_at": int(time.time())}


def websites():
    sites = []
    patterns = [("nginx", "/etc/nginx/sites-enabled/*"), ("nginx", "/etc/nginx/conf.d/*.conf"),
                ("apache", "/etc/apache2/sites-enabled/*"), ("apache", "/etc/httpd/conf.d/*.conf")]
    for kind, pat in patterns:
        for path in sorted(glob.glob(pat)):
            text = read(path)
            if not text:
                continue
            if kind == "nginx":
                names = re.findall(r"^\s*server_name\s+([^;]+);", text, re.M)
                listens = re.findall(r"^\s*listen\s+([^;]+);", text, re.M)
                roots = re.findall(r"^\s*root\s+([^;]+);", text, re.M)
                proxies = re.findall(r"^\s*proxy_pass\s+([^;]+);", text, re.M)
            else:
                names = re.findall(r"^\s*Server(?:Name|Alias)\s+(.+)$", text, re.M | re.I)
                listens = re.findall(r"<VirtualHost\s+([^>]+)>", text, re.I)
                roots = re.findall(r"^\s*DocumentRoot\s+(.+)$", text, re.M | re.I)
                proxies = re.findall(r"^\s*ProxyPass\s+\S+\s+(\S+)", text, re.M | re.I)
            domains = sorted({d for n in names for d in n.split() if d not in ("_", "localhost")})
            if domains or listens:
                sites.append({"server": kind, "file": path, "domains": domains,
                              "listen": sorted({l.strip() for l in listens})[:10],
                              "root": sorted({r.strip() for r in roots})[:5],
                              "proxy": sorted({p.strip() for p in proxies})[:10]})
    return sites


def certificates():
    certs = []
    if not which("openssl"):
        return certs
    for path in sorted(glob.glob("/etc/letsencrypt/live/*/cert.pem")):
        rc, out = run(["openssl", "x509", "-enddate", "-subject", "-noout", "-in", path], timeout=5, merge=False)
        m = re.search(r"notAfter=(.+)", out)
        if not m:
            continue
        try:
            exp = calendar.timegm(time.strptime(m.group(1).strip().replace("  ", " "), "%b %d %H:%M:%S %Y %Z"))
        except ValueError:
            continue
        certs.append({"name": path.split("/")[-2], "path": path, "expires": int(exp),
                      "days_left": int((exp - time.time()) // 86400)})
    return certs


def cron_jobs():
    jobs = []
    files = ["/etc/crontab"] + sorted(glob.glob("/etc/cron.d/*")) + sorted(glob.glob("/var/spool/cron/crontabs/*")) \
        + sorted(p for p in glob.glob("/var/spool/cron/*") if os.path.isfile(p))
    for path in files:
        for line in read(path).splitlines():
            s = line.strip()
            if not s or s.startswith("#") or re.match(r"^[A-Z_]+\s*=", s):
                continue
            jobs.append({"file": path, "line": mask_secrets(s)[:400]})
    rc, out = run(["systemctl", "list-timers", "--all", "--no-pager"], merge=False)
    return {"cron": jobs, "timers": out.strip() if rc == 0 else ""}


def users():
    res, sudo = [], set()
    for g in ("sudo", "wheel", "admin"):
        rc, out = run(["getent", "group", g], merge=False)
        if rc == 0 and out.count(":") >= 3:
            sudo.update(x for x in out.strip().split(":")[3].split(",") if x)
    for p in pwd.getpwall():
        if (p.pw_uid == 0 or 1000 <= p.pw_uid < 65534) and not p.pw_shell.endswith(("nologin", "false")):
            res.append({"name": p.pw_name, "uid": p.pw_uid, "home": p.pw_dir, "shell": p.pw_shell,
                        "sudo": p.pw_name in sudo or p.pw_uid == 0,
                        "ssh_keys": len([l for l in read(os.path.join(p.pw_dir, ".ssh/authorized_keys")).splitlines()
                                         if l.strip() and not l.startswith("#")])})
    rc, out = run(["last", "-n", "15", "-w"], merge=False)
    return {"accounts": res, "last_logins": out.strip()}


def security():
    sec = {}
    # SSH
    ssh = {}
    rc, out = run(["sshd", "-T"], timeout=5, merge=False) if which("sshd") else (1, "")
    if rc == 0:
        for line in out.splitlines():
            k, _, v = line.partition(" ")
            if k in ("port", "permitrootlogin", "passwordauthentication", "pubkeyauthentication", "x11forwarding", "maxauthtries"):
                ssh[k] = v
    else:
        for line in read("/etc/ssh/sshd_config").splitlines():
            f = line.strip().split()
            if len(f) >= 2 and not f[0].startswith("#"):
                k = f[0].lower()
                if k in ("port", "permitrootlogin", "passwordauthentication", "pubkeyauthentication") and k not in ssh:
                    ssh[k] = f[1]
    sec["ssh"] = ssh
    # Tentativas de login falhas (24h)
    failed, ips = 0, {}
    if which("journalctl"):
        rc, out = run(["journalctl", "-q", "--since=-24h", "--no-pager", "-o", "cat",
                       "_COMM=sshd", "+", "_COMM=sshd-session"], timeout=20, merge=False)
        lines = out.splitlines()
    else:
        lines = (read("/var/log/auth.log") or read("/var/log/secure")).splitlines()[-20000:]
    for line in lines:
        if "Failed password" in line or "Invalid user" in line or "authentication failure" in line:
            failed += 1
            m = re.search(r"from (\S+)", line)
            if m:
                ips[m.group(1)] = ips.get(m.group(1), 0) + 1
    sec["failed_logins_24h"] = failed
    sec["top_attackers"] = sorted(ips.items(), key=lambda x: -x[1])[:10]
    # Firewall
    fw = {"type": None, "active": False, "summary": ""}
    if which("ufw"):
        rc, out = run(["ufw", "status", "verbose"], timeout=10, merge=False)
        if rc == 0:
            fw = {"type": "ufw", "active": "Status: active" in out, "summary": out.strip()[:4000]}
    if not fw["active"] and which("firewall-cmd"):
        rc, out = run(["firewall-cmd", "--state"], timeout=10, merge=False)
        if out.strip() == "running":
            rc, lst = run(["firewall-cmd", "--list-all"], timeout=10, merge=False)
            fw = {"type": "firewalld", "active": True, "summary": lst.strip()[:4000]}
    if not fw["active"] and which("nft"):
        rc, out = run(["nft", "list", "ruleset"], timeout=10, merge=False)
        rules = [l for l in out.splitlines() if l.strip() and not l.strip().startswith(("table", "chain", "}", "type"))]
        if rc == 0 and rules:
            fw = {"type": "nftables", "active": True, "summary": "%d regras nftables" % len(rules)}
    if not fw["active"] and which("iptables"):
        rc, out = run(["iptables", "-S"], timeout=10, merge=False)
        rules = [l for l in out.splitlines() if l.startswith("-A")]
        if rc == 0 and rules:
            fw = {"type": "iptables", "active": True, "summary": "%d regras iptables" % len(rules)}
    sec["firewall"] = fw
    # Fail2ban
    if which("fail2ban-client"):
        rc, out = run(["fail2ban-client", "status"], timeout=10)
        sec["fail2ban"] = out.strip() if rc == 0 else "instalado, mas não respondeu"
    # Reinício pendente / atualizações automáticas
    sec["reboot_required"] = os.path.exists("/var/run/reboot-required")
    sec["reboot_pkgs"] = read("/var/run/reboot-required.pkgs").split()
    if which("needs-restarting"):
        rc, _ = run(["needs-restarting", "-r"], timeout=20)
        sec["reboot_required"] = sec["reboot_required"] or rc == 1
    auto = read("/etc/apt/apt.conf.d/20auto-upgrades")
    if auto:
        sec["auto_updates"] = bool(re.search(r'Unattended-Upgrade\s+"1"', auto))
    elif os.path.exists("/etc/dnf/automatic.conf"):
        sec["auto_updates"] = run(["systemctl", "is-enabled", "dnf-automatic.timer"], merge=False)[1].strip() == "enabled"
    return sec


# ---------------------------------------------------------------- ações

UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@_.:\\-]{0,199}$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

# Catálogo fixo: o hub só consegue pedir o que estiver aqui. Nada de shell livre.
ACTIONS = [
    # --- Saúde
    {"id": "health.overview", "group": "Saúde", "label": "Diagnóstico rápido", "mut": False,
     "desc": "Uptime, memória, discos e processos que mais consomem.",
     "sh": "uptime; echo; free -h; echo; df -hT -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null; echo; "
           "ps -eo pid,user,%cpu,%mem,etime,comm --sort=-%cpu | head -20"},
    {"id": "health.failed_services", "group": "Saúde", "label": "Serviços com falha", "mut": False,
     "desc": "Lista serviços systemd em estado de falha.", "sh": "systemctl --failed --no-pager"},
    {"id": "health.journal_errors", "group": "Saúde", "label": "Erros do sistema (24h)", "mut": False,
     "desc": "Últimos 200 erros registrados no journal nas últimas 24 horas.",
     "sh": "journalctl -p err --since=-24h --no-pager -n 200"},
    {"id": "health.disk_hogs", "group": "Saúde", "label": "O que ocupa o disco", "mut": False,
     "desc": "Maiores pastas na raiz e em /var, e arquivos acima de 500 MB.", "timeout": 300,
     "sh": "echo '== Maiores pastas em / =='; du -xh --max-depth=1 / 2>/dev/null | sort -rh | head -15; "
           "echo; echo '== Maiores pastas em /var =='; du -xh --max-depth=2 /var 2>/dev/null | sort -rh | head -15; "
           "echo; echo '== Arquivos > 500 MB =='; find / -xdev -type f -size +500M -exec ls -lh {} + 2>/dev/null | awk '{print $5, $9}' | sort -rh | head -20"},
    {"id": "health.memory_detail", "group": "Saúde", "label": "Detalhe de memória", "mut": False,
     "desc": "Uso de memória por processo (RSS) e swap.",
     "sh": "free -m; echo; ps -eo pid,user,rss,%mem,comm --sort=-rss | head -25 | awk 'NR==1{print;next}{printf \"%s %s %.0fMB %s %s\\n\",$1,$2,$3/1024,$4,$5}'"},
    {"id": "health.connections", "group": "Saúde", "label": "Conexões de rede ativas", "mut": False,
     "desc": "Resumo de conexões TCP e principais IPs remotos.",
     "sh": "ss -s; echo; echo '== Top IPs remotos =='; ss -tnH state established | awk '{print $4}' | sed 's/:[0-9]*$//' | sort | uniq -c | sort -rn | head -20"},
    # --- Limpeza
    {"id": "cleanup.packages", "group": "Limpeza", "label": "Limpar cache de pacotes", "mut": True,
     "desc": "Remove pacotes órfãos e limpa o cache do gerenciador de pacotes.", "timeout": 600,
     "sh": "df -h / | tail -1; if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get -y autoremove --purge && apt-get clean; "
           "elif command -v dnf >/dev/null; then dnf -y autoremove && dnf clean all; elif command -v yum >/dev/null; then yum clean all; "
           "elif command -v apk >/dev/null; then apk cache clean; fi; echo; df -h / | tail -1"},
    {"id": "cleanup.journal", "group": "Limpeza", "label": "Reduzir logs do journal", "mut": True,
     "desc": "Mantém só os últimos 7 dias (máx. 500 MB) de logs do systemd.",
     "sh": "journalctl --disk-usage; journalctl --vacuum-time=7d --vacuum-size=500M; journalctl --disk-usage"},
    {"id": "cleanup.tmp", "group": "Limpeza", "label": "Limpar /tmp antigo", "mut": True,
     "desc": "Apaga arquivos em /tmp e /var/tmp sem acesso há mais de 7 dias.",
     "sh": "find /tmp /var/tmp -xdev -type f -atime +7 -print -delete 2>/dev/null | tail -50; echo concluído"},
    {"id": "cleanup.old_logs", "group": "Limpeza", "label": "Apagar logs rotacionados", "mut": True,
     "desc": "Remove logs compactados antigos (*.gz, *.1) em /var/log.",
     "sh": "du -sh /var/log; find /var/log -type f \\( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \\) -mtime +7 -print -delete | tail -50; du -sh /var/log"},
    {"id": "cleanup.docker", "group": "Limpeza", "label": "Limpar Docker", "mut": True,
     "desc": "Remove containers parados, imagens sem uso e cache de build (volumes são preservados).", "timeout": 900,
     "sh": "docker system df; docker system prune -af; docker builder prune -af; echo; docker system df"},
    # --- Segurança
    {"id": "security.updates", "group": "Segurança", "label": "Ver atualizações pendentes", "mut": False,
     "desc": "Atualiza o índice de pacotes e lista o que pode ser atualizado.", "timeout": 300,
     "sh": "if command -v apt-get >/dev/null; then apt-get update -qq && apt list --upgradable 2>/dev/null; "
           "elif command -v dnf >/dev/null; then dnf -q check-update; dnf -q updateinfo list security; "
           "elif command -v yum >/dev/null; then yum -q check-update; elif command -v apk >/dev/null; then apk update && apk version -l '<'; fi; true"},
    {"id": "security.apply_security", "group": "Segurança", "label": "Aplicar atualizações de segurança", "mut": True,
     "desc": "Instala somente as atualizações de segurança.", "timeout": 1800,
     "sh": "if command -v unattended-upgrade >/dev/null; then apt-get update -qq && unattended-upgrade -v; "
           "elif command -v apt-get >/dev/null; then apt-get update -qq && apt list --upgradable 2>/dev/null | grep -- -security | cut -d/ -f1 | xargs -r env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade; "
           "elif command -v dnf >/dev/null; then dnf -y upgrade --security; elif command -v yum >/dev/null; then yum -y update --security; fi; "
           "[ -f /var/run/reboot-required ] && echo '>> REINÍCIO NECESSÁRIO' || true"},
    {"id": "security.apply_all", "group": "Segurança", "label": "Aplicar todas as atualizações", "mut": True, "danger": True,
     "desc": "Atualiza todos os pacotes do sistema. Pode reiniciar serviços.", "timeout": 3600,
     "sh": "if command -v apt-get >/dev/null; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade; "
           "elif command -v dnf >/dev/null; then dnf -y upgrade; elif command -v yum >/dev/null; then yum -y update; elif command -v apk >/dev/null; then apk upgrade; fi; "
           "[ -f /var/run/reboot-required ] && echo '>> REINÍCIO NECESSÁRIO' || true"},
    {"id": "security.failed_logins", "group": "Segurança", "label": "Tentativas de invasão SSH", "mut": False,
     "desc": "Últimas tentativas de login SSH que falharam e os IPs de origem.",
     "sh": "(journalctl -q --since=-48h --no-pager -o short _COMM=sshd + _COMM=sshd-session 2>/dev/null || cat /var/log/auth.log /var/log/secure 2>/dev/null) "
           "| grep -E 'Failed password|Invalid user' | tail -60; echo; echo '== IPs que mais tentaram =='; "
           "(journalctl -q --since=-48h --no-pager -o cat _COMM=sshd + _COMM=sshd-session 2>/dev/null || cat /var/log/auth.log /var/log/secure 2>/dev/null) "
           "| grep -E 'Failed password|Invalid user' | grep -oE 'from [0-9a-fA-F.:]+' | sort | uniq -c | sort -rn | head -15"},
    {"id": "security.listening", "group": "Segurança", "label": "Portas abertas", "mut": False,
     "desc": "Todos os serviços escutando na rede, com o processo responsável.", "sh": "ss -tulpn"},
    {"id": "security.users_audit", "group": "Segurança", "label": "Auditoria de usuários", "mut": False,
     "desc": "Contas com shell, quem tem sudo, chaves SSH e últimos acessos.",
     "sh": "echo '== Contas com shell =='; awk -F: '($3==0||$3>=1000)&&$7!~/(nologin|false)$/{print $1, \"uid=\"$3, $6, $7}' /etc/passwd; "
           "echo; echo '== Grupos sudo/wheel =='; getent group sudo wheel admin; echo; echo '== Sudoers extras =='; ls -la /etc/sudoers.d 2>/dev/null; "
           "echo; echo '== Chaves SSH autorizadas =='; for h in /root /home/*; do f=$h/.ssh/authorized_keys; [ -f $f ] && echo \"$f: $(grep -cv '^#' $f) chave(s)\"; done; "
           "echo; echo '== Últimos acessos =='; last -n 20 -w 2>/dev/null"},
    {"id": "security.firewall", "group": "Segurança", "label": "Regras de firewall", "mut": False,
     "desc": "Mostra as regras ativas (ufw, firewalld, nftables ou iptables).",
     "sh": "if command -v ufw >/dev/null && ufw status | grep -q active; then ufw status numbered verbose; "
           "elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then firewall-cmd --list-all-zones; "
           "elif command -v nft >/dev/null; then nft list ruleset; else iptables -S; fi"},
    {"id": "security.suid_scan", "group": "Segurança", "label": "Arquivos SUID", "mut": False, "timeout": 300,
     "desc": "Binários com permissão SUID/SGID (úteis para auditoria de escalonamento de privilégio).",
     "sh": "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -exec ls -l {} + 2>/dev/null | awk '{print $1, $3, $9}'"},
    # --- Serviços
    {"id": "service.status", "group": "Serviços", "label": "Status de um serviço", "mut": False, "param": "service",
     "desc": "Estado detalhado de um serviço systemd."},
    {"id": "service.logs", "group": "Serviços", "label": "Logs de um serviço", "mut": False, "param": "service",
     "desc": "Últimas 200 linhas de log de um serviço."},
    {"id": "service.restart", "group": "Serviços", "label": "Reiniciar serviço", "mut": True, "param": "service",
     "desc": "Reinicia um serviço systemd."},
    {"id": "service.start", "group": "Serviços", "label": "Iniciar serviço", "mut": True, "param": "service",
     "desc": "Inicia um serviço systemd parado."},
    {"id": "service.stop", "group": "Serviços", "label": "Parar serviço", "mut": True, "danger": True, "param": "service",
     "desc": "Para um serviço systemd."},
    {"id": "docker.restart", "group": "Serviços", "label": "Reiniciar container", "mut": True, "param": "container",
     "desc": "Reinicia um container Docker."},
    {"id": "docker.logs", "group": "Serviços", "label": "Logs de container", "mut": False, "param": "container",
     "desc": "Últimas 200 linhas de log de um container Docker."},
    # --- Sistema
    {"id": "agent.refresh", "group": "Sistema", "label": "Atualizar inventário agora", "mut": False,
     "desc": "Força o agente a recoletar serviços, pacotes, segurança e software.", "internal": True},
    {"id": "system.reboot", "group": "Sistema", "label": "Reiniciar servidor", "mut": True, "danger": True,
     "desc": "Reinicia o servidor em 1 minuto.", "sh": "shutdown -r +1 'Reinício solicitado pelo Linux Control' && echo 'Reinício agendado para daqui a 1 minuto.'"},
]
ACTIONS_BY_ID = {a["id"]: a for a in ACTIONS}


def allowed_actions(mode):
    if mode == "none":
        return []
    return [a for a in ACTIONS if mode == "all" or not a.get("mut")]


def action_catalog(mode):
    keys = ("id", "group", "label", "desc", "mut", "danger", "param", "timeout")
    return [{k: a.get(k) for k in keys if a.get(k) is not None} for a in allowed_actions(mode)]


def execute_action(cmd, mode, agent_state):
    aid, param = cmd.get("action"), str(cmd.get("param") or "").strip()
    a = ACTIONS_BY_ID.get(aid)
    if not a or a not in allowed_actions(mode):
        return 126, "ação não permitida neste servidor: %s (modo de ações: %s)" % (aid, mode)
    timeout = int(a.get("timeout", 120))
    if a.get("internal"):
        agent_state["force_inventory"] = True
        return 0, "inventário será recoletado e enviado no próximo ciclo."
    if a.get("param") == "service":
        if not UNIT_RE.match(param):
            return 2, "nome de serviço inválido"
        # Só unidades .service: impede "reboot.target", "poweroff.target" etc.
        unit = param if param.endswith(".service") else param + ".service"
        if aid == "service.logs":
            return run(["journalctl", "--no-pager", "-n", "200", "--unit=" + unit], timeout=timeout)
        if aid == "service.status":
            return run(["systemctl", "status", "--no-pager", "-l", "--", unit], timeout=timeout)
        verb = aid.split(".")[1]
        rc, out = run(["systemctl", verb, "--", unit], timeout=timeout)
        rc2, st = run(["systemctl", "status", "--no-pager", "-l", "-n", "15", "--", unit], timeout=20)
        return rc, (out + "\n" + st).strip()
    if a.get("param") == "container":
        if not CONTAINER_RE.match(param):
            return 2, "nome de container inválido"
        if aid == "docker.logs":
            return run(["docker", "logs", "--tail", "200", "--", param], timeout=timeout)
        return run(["docker", "restart", "--", param], timeout=timeout)
    return run(["/bin/sh", "-c", a["sh"]], timeout=timeout)


# ---------------------------------------------------------------- envio

def collect_inventory(mode, with_packages):
    inv = {
        "system": safe(system_info, {}),
        "services": safe(services, {"available": False, "units": []}),
        "ports": safe(ports, []),
        "docker": safe(docker),
        "software": safe(software, []),
        "websites": safe(websites, []),
        "certificates": safe(certificates, []),
        "cron": safe(cron_jobs, {}),
        "users": safe(users, {}),
        "security": safe(security, {}),
        "actions": action_catalog(mode),
        "actions_mode": mode,
        "collected_at": int(time.time()),
    }
    if with_packages:
        inv["packages"] = safe(packages, None)
    return inv


def post(conf, payload):
    url = conf["HUB_URL"].rstrip("/") + "/api/agent/report"
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urlrequest.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer " + conf["TOKEN"],
        "User-Agent": "linux-control-agent/" + VERSION,
    })
    ctx = None
    if url.startswith("https") and conf.get("INSECURE_TLS") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urlrequest.urlopen(req, timeout=30, context=ctx) as r:
        return json.loads(r.read().decode("utf-8") or "{}")


def worker(q, results, lock, mode, state):
    while True:
        cmd = q.get()
        started = time.time()
        log("executando ação %s (%s)" % (cmd.get("action"), cmd.get("id")))
        try:
            rc, out = execute_action(cmd, mode, state)
        except Exception as e:
            rc, out = 1, "erro interno do agente: %s" % e
        if len(out) > MAX_OUTPUT:
            out = "[saída truncada, mostrando o final]\n" + out[-MAX_OUTPUT:]
        with lock:
            results.append({"id": cmd.get("id"), "exit_code": rc, "output": out,
                            "duration": round(time.time() - started, 1)})


def main():
    args = sys.argv[1:]
    conf = load_conf()
    mode = conf.get("ACTIONS", "all")
    if mode not in ("all", "readonly", "none"):
        mode = "readonly"
    col = Collector()

    if "--once" in args:
        col.metrics()
        time.sleep(1)
        print(json.dumps({"metrics": col.metrics(), "inventory": collect_inventory(mode, True)}, indent=2, ensure_ascii=False))
        return

    if not conf["HUB_URL"] or not conf["TOKEN"]:
        log("HUB_URL e TOKEN são obrigatórios (em %s ou LCTL_HUB_URL/LCTL_TOKEN)" % CONF_PATH)
        sys.exit(2)

    interval = max(10, int(conf["INTERVAL"]))
    inv_every = max(60, int(conf["INVENTORY_EVERY"]))
    pkg_every = max(600, int(conf["PACKAGES_EVERY"]))
    q, results, lock = queue.Queue(), [], threading.Lock()
    state = {"force_inventory": False}
    threading.Thread(target=worker, args=(q, results, lock, mode, state), daemon=True).start()

    last_inv = last_pkg = 0
    seen_cmds = set()
    log("iniciado v%s, hub=%s, intervalo=%ss, ações=%s" % (VERSION, conf["HUB_URL"], interval, mode))
    while True:
        cycle = time.time()
        with lock:
            sending, results[:] = list(results), []
        payload = {"agent_version": VERSION, "interval": interval, "metrics": safe(col.metrics, {}), "results": sending}
        force = state["force_inventory"]
        want_pkg = force or cycle - last_pkg >= pkg_every
        if force or cycle - last_inv >= inv_every:
            payload["inventory"] = collect_inventory(mode, want_pkg)
        try:
            resp = post(conf, payload)
            if "inventory" in payload:
                last_inv = cycle
                state["force_inventory"] = False
                if want_pkg:
                    last_pkg = cycle
            if resp.get("need_inventory"):
                last_inv = 0
            for cmd in resp.get("commands", []):
                if cmd.get("id") not in seen_cmds:
                    if len(seen_cmds) > 1000:
                        seen_cmds.clear()
                    seen_cmds.add(cmd.get("id"))
                    q.put(cmd)
        except urlerror.HTTPError as e:
            log("hub respondeu HTTP %s" % e.code)
            if e.code == 401:
                log("token recusado pelo hub; confira /etc/linux-control/agent.conf")
            with lock:
                results[:0] = sending
        except Exception as e:
            log("falha ao enviar: %s" % e)
            with lock:
                results[:0] = sending
        if "--test" in args:
            log("teste concluído")
            return
        time.sleep(max(1, interval - (time.time() - cycle)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
