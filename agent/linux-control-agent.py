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
import hashlib
import json
import os
import platform
import pwd
import queue
import re
import shutil
import stat
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib import error as urlerror
from urllib import request as urlrequest

VERSION = "0.2.0"
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
        "ACTIONS": "all",  # none | readonly | all | admin
        "AUTO_UPDATE": "1",
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
        "os": osr.get("PRETTY_NAME") or platform.platform(),
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
        en = enabled.get(f[0], "")
        units.append({"name": f[0], "load": f[1], "active": f[2], "sub": f[3],
                      "desc": f[4] if len(f) > 4 else "", "enabled": en, "key": f[0],
                      "state": ["running" if f[3] == "running" else "stopped"] + ([en] if en in ("enabled", "disabled") else [])})
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
                           "docker_state": c.get("State"), "status": c.get("Status"), "ports": c.get("Ports")})
    stats = {}
    if any(c["docker_state"] == "running" for c in containers):
        rc, out = run(["docker", "stats", "--no-stream", "--format", "{{json .}}"], timeout=20, merge=False)
        for line in out.splitlines():
            try:
                s = json.loads(line)
                stats[s.get("Name")] = {"cpu": s.get("CPUPerc"), "mem": s.get("MemUsage")}
            except ValueError:
                pass
    for c in containers:
        c["stats"] = stats.get(c["name"])
        c["key"] = c["name"]
        c["state"] = ["running" if c["docker_state"] == "running" else "stopped"]
    return {"available": True, "containers": containers}


# Cada item é detectado por um binário no PATH (e a versão pelo argumento dado) ou por uma pasta.
KNOWN_SOFTWARE = [
    {"name": n, "bin": b, "args": a} for n, b, a in (
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
    )
] + [
    {"name": "Coolify", "dir": "/data/coolify"},
    {"name": "cPanel", "dir": "/usr/local/cpanel", "version_file": "/usr/local/cpanel/version"},
]


def software():
    res = []
    for item in KNOWN_SOFTWARE:
        if "dir" in item:
            if os.path.isdir(item["dir"]):
                res.append({"name": item["name"], "path": item["dir"], "version": read(item.get("version_file", "")).strip()})
            continue
        path = which(item["bin"])
        if not path:
            continue
        version = ""
        if item["args"] is not None:
            _, out = run([path] + item["args"], timeout=6)
            version = (out.strip().splitlines() or [""])[0][:140]
        res.append({"name": item["name"], "path": os.path.realpath(path), "version": version})
    return res


def package_manager():
    for pm, binary in (("apt", "dpkg-query"), ("dnf", "dnf"), ("yum", "yum"), ("apk", "apk")):
        if which(binary):
            return pm
    return None


def installed_packages(pm):
    """[[nome, versão], ...] dos pacotes instalados."""
    items = []
    if pm == "apt":
        _, out = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Package}\t${Version}\n"], timeout=30, merge=False)
        items = [f[1:] for f in (l.split("\t") for l in out.splitlines()) if len(f) == 3 and f[0].startswith("ii")]
    elif pm in ("dnf", "yum"):
        _, out = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=30, merge=False)
        items = [l.split("\t") for l in out.splitlines() if "\t" in l]
    elif pm == "apk":
        _, out = run(["apk", "info", "-v"], timeout=30, merge=False)
        items = [[m.group(1), m.group(2)] for m in (re.match(r"^(.+)-(\d[^-]*-r\d+)$", l.strip()) for l in out.splitlines()) if m]
    return sorted(items, key=lambda x: x[0])


def packages():
    pm, updates = package_manager(), []
    items = installed_packages(pm)
    if pm == "apt":
        rc, out = run(["apt", "list", "--upgradable"], timeout=60, merge=False)
        for line in out.splitlines():
            m = re.match(r"^([^/\s]+)/(\S+)\s+(\S+)\s+\S+(?:\s+\[upgradable from: ([^\]]+)\])?", line)
            if m:
                updates.append({"name": m.group(1), "new": m.group(3), "current": m.group(4) or "", "security": "security" in m.group(2)})
    elif pm in ("dnf", "yum"):
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
                updates.append({"name": name, "new": f[1], "current": "", "security": name in sec})
    elif pm == "apk":
        rc, out = run(["apk", "version", "-l", "<"], timeout=30, merge=False)
        for line in out.splitlines()[1:]:
            f = line.split()
            if f:
                updates.append({"name": f[0], "new": f[-1] if len(f) > 2 else "", "current": "", "security": False})
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
            m = re.search(CRON_TAG + r"([0-9a-f]{8})", s)
            jobs.append({"file": path, "line": mask_secrets(s)[:400], "key": m.group(1) if m else None,
                         "state": ["managed"] if m else []})
    rc, out = run(["systemctl", "list-timers", "--all", "--no-pager"], merge=False)
    return {"cron": jobs, "timers": out.strip() if rc == 0 else ""}


SUDO_GROUPS = ("sudo", "wheel", "admin")


def group_members(group):
    rc, out = run(["getent", "group", group], merge=False)
    return [x for x in out.strip().split(":")[3].split(",") if x] if rc == 0 and out.count(":") >= 3 else []


def is_person(pw):
    """Contas de pessoas (UID 1000+). Só elas podem ser alteradas pelo painel."""
    return 1000 <= pw.pw_uid < 65534


def users():
    res, sudo = [], set()
    for g in SUDO_GROUPS:
        sudo.update(group_members(g))
    for p in pwd.getpwall():
        if (p.pw_uid == 0 or is_person(p)) and not p.pw_shell.endswith(("nologin", "false")):
            status = run(["passwd", "-S", p.pw_name], merge=False)[1].split()
            admin = p.pw_name in sudo or p.pw_uid == 0
            locked = len(status) > 1 and status[1] in ("L", "LK")
            res.append({"name": p.pw_name, "uid": p.pw_uid, "home": p.pw_dir, "shell": p.pw_shell,
                        "sudo": admin, "locked": locked, "key": p.pw_name,
                        "state": ["person" if is_person(p) else "system", "admin" if admin else "regular",
                                  "locked" if locked else "unlocked"],
                        "ssh_keys": len([l for l in read(os.path.join(p.pw_dir, ".ssh/authorized_keys")).splitlines()
                                         if l.strip() and not l.startswith("#")])})
    rc, out = run(["last", "-n", "15", "-w"], merge=False)
    return {"accounts": res, "last_logins": out.strip()}


def firewall_status():
    """Primeiro firewall ativo encontrado: ufw, firewalld, nftables ou iptables."""
    if which("ufw"):
        rc, out = run(["ufw", "status", "verbose"], timeout=10, merge=False)
        if rc == 0 and "Status: active" in out:
            return {"type": "ufw", "active": True, "summary": out.strip()[:4000]}
    if which("firewall-cmd") and run(["firewall-cmd", "--state"], timeout=10, merge=False)[1].strip() == "running":
        return {"type": "firewalld", "active": True, "summary": run(["firewall-cmd", "--list-all"], timeout=10, merge=False)[1].strip()[:4000]}
    if which("nft"):
        rc, out = run(["nft", "list", "ruleset"], timeout=10, merge=False)
        rules = [l for l in out.splitlines() if l.strip() and not l.strip().startswith(("table", "chain", "}", "type"))]
        if rc == 0 and rules:
            return {"type": "nftables", "active": True, "summary": "%d regras nftables" % len(rules)}
    if which("iptables"):
        rc, out = run(["iptables", "-S"], timeout=10, merge=False)
        rules = [l for l in out.splitlines() if l.startswith("-A")]
        if rc == 0 and rules:
            return {"type": "iptables", "active": True, "summary": "%d regras iptables" % len(rules)}
    return {"type": None, "active": False, "summary": ""}


def security():
    sec = {}
    ssh = {}
    rc, out = run(["sshd", "-T"], timeout=5, merge=False) if which("sshd") else (1, "")
    if rc == 0:
        for line in out.splitlines():
            k, _, v = line.partition(" ")
            if k in ("port", "permitrootlogin", "passwordauthentication", "pubkeyauthentication"):
                ssh[k] = v
    else:
        for line in read("/etc/ssh/sshd_config").splitlines():
            f = line.strip().split()
            if len(f) >= 2 and not f[0].startswith("#"):
                k = f[0].lower()
                if k in ("port", "permitrootlogin", "passwordauthentication", "pubkeyauthentication") and k not in ssh:
                    ssh[k] = f[1]
    sec["ssh"] = ssh
    failed, ips = ssh_auth_failures(24)
    sec["failed_logins_24h"] = len(failed)
    sec["top_attackers"] = ips[:10]
    sec["firewall"] = firewall_status()
    if which("fail2ban-client"):
        rc, out = run(["fail2ban-client", "status"], timeout=10)
        sec["fail2ban"] = out.strip() if rc == 0 else "instalado, mas não respondeu"
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
#
# O catálogo é a fonte única do que o painel pode pedir a este servidor. Cada ação declara:
#   level   read | change | danger | admin   (o modo do agente decide quais níveis valem)
#   confirm True  -> o painel exige digitar o nome do servidor
#   target  "service" | "container" | "user" | "cron" | "app"  -> vira botão na linha da tabela (ver TARGET_FIELD)
#   when    estados que a linha precisa ter para o botão aparecer (ex.: "running")
#   placement  aba onde a ação ganha um botão próprio no topo (ex.: "users")
#   fields  formulário que o painel monta; cada campo é validado aqui antes de qualquer execução
#           (tipos: text, textarea, select, bool, cron; "suggest" pede sugestões do inventário)
#   sh | run   comando fixo de shell, ou função Python que recebe os parâmetros já validados

LEVELS_BY_MODE = {
    "none": (),
    "readonly": ("read",),
    "all": ("read", "change", "danger"),
    "admin": ("read", "change", "danger", "admin"),
}

UNIT_RE = r"^[A-Za-z0-9][A-Za-z0-9@_.:\\-]{0,199}$"
CONTAINER_RE = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
USER_RE = r"^[a-z_][a-z0-9_-]{0,31}$"
SSH_KEY_RE = r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]{40,8000}( [^\r\n]{0,200})?$"
CRON_SCHEDULE_RE = r"^(@(reboot|hourly|daily|weekly|monthly|yearly)|([0-9*/,-]+[ \t]+){4}[0-9A-Za-z*/,-]+)$"
CRON_ID_RE = r"^[0-9a-f]{8}$"
TZ_RE = r"^[A-Za-z_]+(/[A-Za-z0-9_+-]+){0,2}$"
CRON_FILE = "/etc/cron.d/linux-control"
CRON_TAG = "# lctl:"


def f_text(name, label, pattern, required=True, placeholder="", help="", suggest=None):
    f = {"name": name, "label": label, "type": "text", "pattern": pattern, "required": required,
         "placeholder": placeholder, "help": help}
    if suggest:
        f["suggest"] = suggest  # o painel sugere valores do inventário: services | containers | users
    return f


def f_bool(name, label, help=""):
    return {"name": name, "label": label, "type": "bool", "help": help}


def f_select(name, label, options, help=""):
    return {"name": name, "label": label, "type": "select", "options": options, "required": True, "help": help}


def F_SERVICE():
    return [f_text("name", "Serviço", UNIT_RE, placeholder="nginx", suggest="services")]


def F_CONTAINER():
    return [f_text("name", "Container", CONTAINER_RE, suggest="containers")]


def F_USER():
    return [f_text("name", "Usuário", USER_RE, suggest="users")]


def ssh_auth_failures(hours):
    """Linhas de falha de login SSH nas últimas `hours` horas e contagem por IP de origem."""
    if which("journalctl"):
        rc, out = run(["journalctl", "-q", "--since=-%dh" % hours, "--no-pager", "-o", "short",
                       "_COMM=sshd", "+", "_COMM=sshd-session"], timeout=20, merge=False)
        lines = out.splitlines()
    else:
        lines = (read("/var/log/auth.log") or read("/var/log/secure")).splitlines()[-20000:]
    failed, ips = [], {}
    for line in lines:
        if "Failed password" in line or "Invalid user" in line or "authentication failure" in line:
            failed.append(line)
            m = re.search(r"from (\S+)", line)
            if m:
                ips[m.group(1)] = ips.get(m.group(1), 0) + 1
    return failed, sorted(ips.items(), key=lambda x: -x[1])


def run_failed_logins(p, state):
    failed, ips = ssh_auth_failures(48)
    out = "\n".join(failed[-60:]) or "Nenhuma tentativa falha nas últimas 48 h."
    if ips:
        out += "\n\n== IPs que mais tentaram ==\n" + "\n".join("%6d %s" % (n, ip) for ip, n in ips[:15])
    return 0, out


def unit_name(p):
    name = p["name"]
    return name if name.endswith(".service") else name + ".service"


def run_service_logs(p, state):
    return run(["journalctl", "--no-pager", "-n", "200", "--unit=" + unit_name(p)], timeout=60)


def run_service_status(p, state):
    return run(["systemctl", "status", "--no-pager", "-l", "--", unit_name(p)], timeout=30)


def run_service(verb):
    def fn(p, state):
        unit = unit_name(p)
        rc, out = run(["systemctl", verb, "--", unit], timeout=120)
        _, st = run(["systemctl", "status", "--no-pager", "-l", "-n", "15", "--", unit], timeout=20)
        return rc, (out + "\n" + st).strip()
    return fn


def run_docker_logs(p, state):
    return run(["docker", "logs", "--tail", "200", "--", p["name"]], timeout=60)


def run_docker(verb):
    return lambda p, state: run(["docker", verb, "--", p["name"]], timeout=120)


def run_refresh(p, state):
    state["force_inventory"] = True
    return 0, "Inventário será recoletado e enviado no próximo ciclo."


def existing_user(name):
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def sudo_group():
    """Grupo que dá sudo nesta distribuição (sudo no Debian/Ubuntu, wheel na família Red Hat)."""
    for g in SUDO_GROUPS[:2]:
        if run(["getent", "group", g], merge=False)[0] == 0:
            return g
    return None


def install_ssh_key(pw, key):
    """Grava a chave sem seguir links: a pasta pessoal pertence ao usuário, que poderia apontar
    ~/.ssh ou authorized_keys para arquivos do sistema e esperar o root escrever neles."""
    ssh_dir = os.path.join(pw.pw_dir, ".ssh")
    if os.path.lexists(ssh_dir):
        if not stat.S_ISDIR(os.lstat(ssh_dir).st_mode):
            return "Recusado: %s não é uma pasta comum (link simbólico?)." % ssh_dir
    else:
        os.mkdir(ssh_dir, 0o700)
    dfd = os.open(ssh_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchown(dfd, pw.pw_uid, pw.pw_gid)
        os.fchmod(dfd, 0o700)
        fd = os.open("authorized_keys", os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                return "Recusado: authorized_keys não é um arquivo comum."
            chunks = []
            while True:
                b = os.read(fd, 65536)
                if not b:
                    break
                chunks.append(b)
            current = b"".join(chunks).decode("utf-8", "replace")
            if key in (l.strip() for l in current.splitlines()):
                return "Chave já estava autorizada."
            prefix = "\n" if current and not current.endswith("\n") else ""
            os.write(fd, (prefix + key + "\n").encode("utf-8"))
            os.fchown(fd, pw.pw_uid, pw.pw_gid)
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
    finally:
        os.close(dfd)
    return "Chave SSH autorizada."


def run_user_create(p, state):
    name = p["name"]
    if existing_user(name):
        return 1, "O usuário %s já existe." % name
    rc, out = run(["useradd", "--create-home", "--shell", p.get("shell") or "/bin/bash", "--", name], timeout=30)
    if rc != 0:
        return rc, out
    msgs = ["Usuário %s criado (login só por chave SSH; sem senha)." % name]
    pw = existing_user(name)
    if p.get("sudo"):
        g = sudo_group()
        if g:
            run(["usermod", "-aG", g, "--", name], timeout=20)
            msgs.append("Adicionado ao grupo %s (administrador)." % g)
    if p.get("ssh_key"):
        msgs.append(install_ssh_key(pw, p["ssh_key"]))
    return 0, "\n".join(msgs)


def regular_user(name):
    pw = existing_user(name)
    if not pw:
        return None, "Usuário %s não existe." % name
    if not is_person(pw):
        return None, "Por segurança, só contas de pessoas (UID 1000 ou maior) podem ser alteradas pelo painel."
    return pw, ""


def run_user_add_key(p, state):
    pw, err = regular_user(p["name"])
    if not pw:
        return 1, err
    return 0, install_ssh_key(pw, p["ssh_key"])


def last_admin(name):
    g = sudo_group()
    return bool(g) and group_members(g) == [name]


def run_user_sudo(enable):
    def fn(p, state):
        pw, err = regular_user(p["name"])
        if not pw:
            return 1, err
        g = sudo_group()
        if not g:
            return 1, "Grupo sudo/wheel não encontrado."
        if not enable and last_admin(pw.pw_name):
            return 1, "%s é o único administrador; dê admin a outra conta antes." % pw.pw_name
        if enable:
            rc, out = run(["usermod", "-aG", g, "--", pw.pw_name], timeout=20)
            return rc, out or "%s agora é administrador (%s)." % (pw.pw_name, g)
        rc, out = run(["gpasswd", "-d", pw.pw_name, g], timeout=20)
        return rc, out or "%s deixou de ser administrador." % pw.pw_name
    return fn


def run_user_lock(lock):
    def fn(p, state):
        pw, err = regular_user(p["name"])
        if not pw:
            return 1, err
        rc, out = run(["usermod", "-L" if lock else "-U", "--", pw.pw_name], timeout=20)
        if lock:
            run(["chage", "-E", "0", "--", pw.pw_name], timeout=20)
        else:
            run(["chage", "-E", "-1", "--", pw.pw_name], timeout=20)
        return rc, out or ("Conta %s %s." % (pw.pw_name, "bloqueada" if lock else "desbloqueada"))
    return fn


def run_user_remove(p, state):
    pw, err = regular_user(p["name"])
    if not pw:
        return 1, err
    if last_admin(pw.pw_name):
        return 1, "%s é o único administrador; dê admin a outra conta antes de remover." % pw.pw_name
    args = ["userdel"] + (["--remove"] if p.get("remove_home") else []) + ["--", pw.pw_name]
    rc, out = run(args, timeout=60)
    return rc, out or "Usuário %s removido." % pw.pw_name


def managed_cron_lines():
    return read(CRON_FILE).splitlines()


def write_managed_cron(lines):
    header = "# Gerenciado pelo Linux Control. Edite pelo painel.\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    body = "\n".join(l for l in lines if CRON_TAG in l)
    tmp = CRON_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(header + body + ("\n" if body else ""))
    os.chmod(tmp, 0o644)
    os.replace(tmp, CRON_FILE)


def run_cron_add(p, state):
    if not existing_user(p["user"]):
        return 1, "Usuário %s não existe." % p["user"]
    if not os.path.isdir(os.path.dirname(CRON_FILE)):
        return 1, "Este sistema não usa /etc/cron.d (instale o cron)."
    cid = os.urandom(4).hex()
    desc = re.sub(r"[^\w .,:()-]", "", p.get("description") or "", flags=re.U)[:80]
    command = p["command"].replace("%", "\\%")
    line = "%s %s %s %s%s %s" % (p["schedule"], p["user"], command, CRON_TAG, cid, desc)
    write_managed_cron(managed_cron_lines() + [line])
    return 0, "Agendamento criado (id %s):\n%s" % (cid, line)


def run_cron_remove(p, state):
    lines = managed_cron_lines()
    keep = [l for l in lines if CRON_TAG + p["id"] not in l]
    if len(keep) == len(lines):
        return 1, "Agendamento %s não encontrado (só é possível remover os criados pelo painel)." % p["id"]
    write_managed_cron(keep)
    return 0, "Agendamento %s removido." % p["id"]


# Instaladores populares: pacotes por gerenciador e passos depois da instalação.
APPS = [
    {"id": "nginx", "label": "Nginx", "desc": "Servidor web e proxy reverso.", "apt": ["nginx"], "dnf": ["nginx"], "service": "nginx"},
    {"id": "apache", "label": "Apache", "desc": "Servidor web Apache HTTP.", "apt": ["apache2"], "dnf": ["httpd"], "service": "apache2|httpd"},
    {"id": "caddy", "label": "Caddy", "desc": "Servidor web com HTTPS automático.", "apt": ["caddy"], "dnf": ["caddy"], "service": "caddy"},
    {"id": "docker", "label": "Docker", "desc": "Containers Docker com Compose.", "apt": ["docker.io", "docker-compose-v2"], "dnf": ["moby-engine", "docker-compose"], "service": "docker"},
    {"id": "mariadb", "label": "MariaDB (MySQL)", "desc": "Banco de dados compatível com MySQL.", "apt": ["mariadb-server"], "dnf": ["mariadb-server"], "service": "mariadb"},
    {"id": "postgresql", "label": "PostgreSQL", "desc": "Banco de dados PostgreSQL.", "apt": ["postgresql"], "dnf": ["postgresql-server"], "service": "postgresql",
     "post_dnf": "postgresql-setup --initdb || true"},
    {"id": "redis", "label": "Redis", "desc": "Cache e fila em memória.", "apt": ["redis-server"], "dnf": ["redis"], "service": "redis-server|redis"},
    {"id": "nodejs", "label": "Node.js + npm", "desc": "Node.js da distribuição, com npm.", "apt": ["nodejs", "npm"], "dnf": ["nodejs", "npm"]},
    {"id": "pm2", "label": "PM2", "desc": "Gerenciador de processos Node.js (instala Node.js se faltar).", "apt": ["nodejs", "npm"], "dnf": ["nodejs", "npm"],
     "post": "npm install -g pm2 && pm2 --version", "bin": "pm2"},
    {"id": "php", "label": "PHP-FPM", "desc": "PHP com FPM e extensões comuns.", "apt": ["php-fpm", "php-mysql", "php-curl", "php-mbstring", "php-xml", "php-zip"],
     "dnf": ["php-fpm", "php-mysqlnd", "php-mbstring", "php-xml"]},
    {"id": "certbot", "label": "Certbot", "desc": "Certificados HTTPS grátis (Let's Encrypt), com plugin do Nginx.", "apt": ["certbot", "python3-certbot-nginx"],
     "dnf": ["certbot", "python3-certbot-nginx"]},
    {"id": "fail2ban", "label": "Fail2ban", "desc": "Bloqueia IPs que tentam invadir por força bruta.", "apt": ["fail2ban"], "dnf": ["fail2ban"], "service": "fail2ban"},
    {"id": "ufw", "label": "Firewall UFW", "desc": "Instala e ativa o firewall liberando o SSH (as demais portas ficam fechadas).",
     "apt": ["ufw"], "dnf": ["ufw"], "post": "P=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}'); ufw allow ${P:-22}/tcp; ufw --force enable && ufw status verbose"},
    {"id": "autoupdates", "label": "Atualizações automáticas de segurança", "desc": "Instala e liga as atualizações de segurança automáticas.",
     "apt": ["unattended-upgrades"], "dnf": ["dnf-automatic"],
     "post": "if [ -d /etc/apt/apt.conf.d ]; then printf 'APT::Periodic::Update-Package-Lists \"1\";\\nAPT::Periodic::Unattended-Upgrade \"1\";\\n' > /etc/apt/apt.conf.d/20auto-upgrades; "
             "else sed -i 's/^upgrade_type.*/upgrade_type = security/; s/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf; systemctl enable --now dnf-automatic.timer; fi; echo ativado"},
    {"id": "git", "label": "Git", "desc": "Controle de versão.", "apt": ["git"], "dnf": ["git"]},
    {"id": "tools", "label": "Ferramentas básicas", "desc": "htop, curl, wget, unzip, zip, rsync, nano, ncdu.", "apt": ["htop", "curl", "wget", "unzip", "zip", "rsync", "nano", "ncdu"],
     "dnf": ["htop", "curl", "wget", "unzip", "zip", "rsync", "nano", "ncdu"]},
    {"id": "chrony", "label": "Chrony (hora certa)", "desc": "Sincroniza o relógio do servidor (NTP).", "apt": ["chrony"], "dnf": ["chrony"], "service": "chrony|chronyd"},
]
APPS_BY_ID = {a["id"]: a for a in APPS}


def app_packages(app, pm):
    return app.get("apt" if pm == "apt" else "dnf", []) if pm in ("apt", "dnf", "yum") else []


def apps_status():
    pm = package_manager()
    have = {name for name, _ in installed_packages(pm)}
    res = []
    for app in APPS:
        pkgs = app_packages(app, pm)
        installed = bool(which(app["bin"])) if app.get("bin") else bool(pkgs) and all(x in have for x in pkgs)
        res.append({"id": app["id"], "label": app["label"], "desc": app["desc"], "available": bool(pkgs), "installed": installed,
                    "key": app["id"], "state": ["installed" if installed else "absent"]})
    return res


def run_app(remove):
    def fn(p, state):
        app, pm = APPS_BY_ID[p["app"]], package_manager()
        pkgs = app_packages(app, pm)
        if not pkgs:
            return 1, "%s não tem instalador para este sistema (%s)." % (app["label"], pm or "gerenciador desconhecido")
        if pm == "apt":
            pre = "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && "
            cmd = pre + ("apt-get -y remove " if remove else "apt-get -y install ") + " ".join(pkgs)
        else:
            cmd = "%s -y %s %s" % (pm, "remove" if remove else "install", " ".join(pkgs))
        if not remove:
            post = app.get("post_dnf") if pm != "apt" and app.get("post_dnf") else ""
            post = "; ".join(x for x in (post, app.get("post", "")) if x)
            if app.get("service"):
                units = app["service"].split("|")
                post += "; " if post else ""
                post += " || ".join("systemctl enable --now %s 2>/dev/null" % u for u in units) + " || true"
            if post:
                cmd += " && { " + post + "; }"
        state["force_inventory"] = True
        return run(["/bin/sh", "-c", cmd], timeout=1800)
    return fn


def firewall_cmd(port, proto, allow):
    spec = "%s/%s" % (port, proto)
    kind = firewall_status()["type"] or ("ufw" if which("ufw") else "firewalld" if which("firewall-cmd") else None)
    if kind == "ufw":
        return ["ufw", "allow", spec] if allow else ["ufw", "delete", "allow", spec]
    if kind == "firewalld":
        flag = "--add-port=" if allow else "--remove-port="
        return ["/bin/sh", "-c", "firewall-cmd --permanent %s%s && firewall-cmd --reload" % (flag, spec)]
    return None


def ssh_ports():
    rc, out = run(["sshd", "-T"], timeout=5, merge=False) if which("sshd") else (1, "")
    ports = {int(p) for p in re.findall(r"^port (\d+)$", out, re.M)} if rc == 0 else set()
    return ports or {22}


def run_firewall(allow):
    def fn(p, state):
        port = int(p["port"])
        if not 1 <= port <= 65535:
            return 2, "Porta inválida."
        if not allow and port in ssh_ports():
            return 1, "Recusado: fechar a porta %d derrubaria o acesso SSH ao servidor." % port
        cmd = firewall_cmd(port, p["proto"], allow)
        if not cmd:
            return 1, "Nenhum firewall gerenciável (ufw ou firewalld) encontrado. Instale o UFW pelos instaladores."
        return run(cmd, timeout=60)
    return fn


def run_timezone(p, state):
    if not os.path.exists("/usr/share/zoneinfo/" + p["timezone"]):
        return 1, "Fuso horário desconhecido: %s" % p["timezone"]
    return run(["timedatectl", "set-timezone", p["timezone"]], timeout=30)


PKG_SH = {
    "updates": "if command -v apt-get >/dev/null; then apt-get update -qq && apt list --upgradable 2>/dev/null; "
               "elif command -v dnf >/dev/null; then dnf -q check-update; dnf -q updateinfo list security; "
               "elif command -v yum >/dev/null; then yum -q check-update; elif command -v apk >/dev/null; then apk update && apk version -l '<'; fi; true",
    "security": "if command -v unattended-upgrade >/dev/null; then apt-get update -qq && unattended-upgrade -v; "
                "elif command -v apt-get >/dev/null; then apt-get update -qq && apt list --upgradable 2>/dev/null | grep -- -security | cut -d/ -f1 | xargs -r env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade; "
                "elif command -v dnf >/dev/null; then dnf -y upgrade --security; elif command -v yum >/dev/null; then yum -y update --security; fi; "
                "[ -f /var/run/reboot-required ] && echo '>> REINÍCIO NECESSÁRIO' || true",
    "all": "if command -v apt-get >/dev/null; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade; "
           "elif command -v dnf >/dev/null; then dnf -y upgrade; elif command -v yum >/dev/null; then yum -y update; elif command -v apk >/dev/null; then apk upgrade; fi; "
           "[ -f /var/run/reboot-required ] && echo '>> REINÍCIO NECESSÁRIO' || true",
    "clean": "df -h / | tail -1; if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get -y autoremove --purge && apt-get clean; "
             "elif command -v dnf >/dev/null; then dnf -y autoremove && dnf clean all; elif command -v yum >/dev/null; then yum clean all; "
             "elif command -v apk >/dev/null; then apk cache clean; fi; echo; df -h / | tail -1",
}

TIMEZONES = ["America/Sao_Paulo", "America/Manaus", "America/Fortaleza", "America/Recife", "America/Belem", "America/Cuiaba",
             "America/Porto_Velho", "America/Rio_Branco", "America/Noronha", "UTC", "America/New_York", "America/Chicago",
             "America/Los_Angeles", "Europe/Lisbon", "Europe/London"]

ACTIONS = [
    {"id": "health.overview", "group": "Saúde", "label": "Diagnóstico rápido", "level": "read",
     "desc": "Uptime, memória, discos e processos que mais consomem.",
     "sh": "uptime; echo; free -h; echo; df -hT -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null; echo; "
           "ps -eo pid,user,%cpu,%mem,etime,comm --sort=-%cpu | head -20"},
    {"id": "health.failed_services", "group": "Saúde", "label": "Serviços com falha", "level": "read",
     "desc": "Lista serviços systemd em estado de falha.", "sh": "systemctl --failed --no-pager"},
    {"id": "health.journal_errors", "group": "Saúde", "label": "Erros do sistema (24h)", "level": "read",
     "desc": "Últimos 200 erros registrados no journal nas últimas 24 horas.",
     "sh": "journalctl -p err --since=-24h --no-pager -n 200"},
    {"id": "health.disk_hogs", "group": "Saúde", "label": "O que ocupa o disco", "level": "read", "timeout": 300,
     "desc": "Maiores pastas na raiz e em /var, e arquivos acima de 500 MB.",
     "sh": "echo '== Maiores pastas em / =='; du -xh --max-depth=1 / 2>/dev/null | sort -rh | head -15; "
           "echo; echo '== Maiores pastas em /var =='; du -xh --max-depth=2 /var 2>/dev/null | sort -rh | head -15; "
           "echo; echo '== Arquivos > 500 MB =='; find / -xdev -type f -size +500M -exec ls -lh {} + 2>/dev/null | awk '{print $5, $9}' | sort -rh | head -20"},
    {"id": "health.memory_detail", "group": "Saúde", "label": "Detalhe de memória", "level": "read",
     "desc": "Uso de memória por processo (RSS) e swap.",
     "sh": "free -m; echo; ps -eo pid,user,rss,%mem,comm --sort=-rss | head -25 | awk 'NR==1{print;next}{printf \"%s %s %.0fMB %s %s\\n\",$1,$2,$3/1024,$4,$5}'"},
    {"id": "health.connections", "group": "Saúde", "label": "Conexões de rede ativas", "level": "read",
     "desc": "Resumo de conexões TCP e principais IPs remotos.",
     "sh": "ss -s; echo; echo '== Top IPs remotos =='; ss -tnH state established | awk '{print $4}' | sed 's/:[0-9]*$//' | sort | uniq -c | sort -rn | head -20"},
    {"id": "cleanup.packages", "group": "Limpeza", "label": "Limpar cache de pacotes", "level": "change", "timeout": 600,
     "desc": "Remove pacotes órfãos e limpa o cache do gerenciador de pacotes.", "sh": PKG_SH["clean"]},
    {"id": "cleanup.journal", "group": "Limpeza", "label": "Reduzir logs do journal", "level": "change",
     "desc": "Mantém só os últimos 7 dias (máx. 500 MB) de logs do systemd.",
     "sh": "journalctl --disk-usage; journalctl --vacuum-time=7d --vacuum-size=500M; journalctl --disk-usage"},
    {"id": "cleanup.tmp", "group": "Limpeza", "label": "Limpar /tmp antigo", "level": "change",
     "desc": "Apaga arquivos em /tmp e /var/tmp sem acesso há mais de 7 dias.",
     "sh": "find /tmp /var/tmp -xdev -type f -atime +7 -print -delete 2>/dev/null | tail -50; echo concluído"},
    {"id": "cleanup.old_logs", "group": "Limpeza", "label": "Apagar logs rotacionados", "level": "change",
     "desc": "Remove logs compactados antigos (*.gz, *.1) em /var/log.",
     "sh": "du -sh /var/log; find /var/log -type f \\( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \\) -mtime +7 -print -delete | tail -50; du -sh /var/log"},
    {"id": "cleanup.docker", "group": "Limpeza", "label": "Limpar Docker", "level": "change", "timeout": 900,
     "desc": "Remove containers parados, imagens sem uso e cache de build (volumes são preservados).",
     "sh": "docker system df; docker system prune -af; docker builder prune -af; echo; docker system df"},
    {"id": "security.updates", "group": "Segurança", "label": "Ver atualizações pendentes", "level": "read", "timeout": 300,
     "desc": "Atualiza o índice de pacotes e lista o que pode ser atualizado.", "sh": PKG_SH["updates"]},
    {"id": "security.apply_security", "group": "Segurança", "label": "Aplicar atualizações de segurança", "level": "change", "timeout": 1800,
     "desc": "Instala somente as atualizações de segurança.", "sh": PKG_SH["security"]},
    {"id": "security.apply_all", "group": "Segurança", "label": "Aplicar todas as atualizações", "level": "danger", "confirm": True, "timeout": 3600,
     "desc": "Atualiza todos os pacotes do sistema. Pode reiniciar serviços.", "sh": PKG_SH["all"]},
    {"id": "security.failed_logins", "group": "Segurança", "label": "Tentativas de invasão SSH", "level": "read",
     "desc": "Últimas tentativas de login SSH que falharam e os IPs de origem.", "run": run_failed_logins},
    {"id": "security.listening", "group": "Segurança", "label": "Portas abertas", "level": "read",
     "desc": "Todos os serviços escutando na rede, com o processo responsável.", "sh": "ss -tulpn"},
    {"id": "security.firewall", "group": "Segurança", "label": "Regras de firewall", "level": "read",
     "desc": "Mostra as regras ativas (ufw, firewalld, nftables ou iptables).",
     "sh": "if command -v ufw >/dev/null && ufw status | grep -q active; then ufw status numbered verbose; "
           "elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then firewall-cmd --list-all-zones; "
           "elif command -v nft >/dev/null; then nft list ruleset; else iptables -S; fi"},
    {"id": "security.suid_scan", "group": "Segurança", "label": "Arquivos SUID", "level": "read", "timeout": 300,
     "desc": "Binários com permissão SUID/SGID (úteis para auditoria de escalonamento de privilégio).",
     "sh": "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -exec ls -l {} + 2>/dev/null | awk '{print $1, $3, $9}'"},
    {"id": "firewall.allow", "group": "Segurança", "label": "Liberar porta no firewall", "level": "admin",
     "desc": "Abre uma porta no UFW ou firewalld.", "run": run_firewall(True),
     "fields": [f_text("port", "Porta", r"^[0-9]{1,5}$", placeholder="443"), f_select("proto", "Protocolo", ["tcp", "udp"])]},
    {"id": "firewall.deny", "group": "Segurança", "label": "Fechar porta no firewall", "level": "admin", "confirm": True,
     "desc": "Remove a liberação de uma porta no UFW ou firewalld.", "run": run_firewall(False),
     "fields": [f_text("port", "Porta", r"^[0-9]{1,5}$"), f_select("proto", "Protocolo", ["tcp", "udp"])]},
    {"id": "service.logs", "group": "Serviços", "label": "Logs", "level": "read", "target": "service", "fields": F_SERVICE(),
     "desc": "Últimas 200 linhas de log de um serviço.", "run": run_service_logs},
    {"id": "service.status", "group": "Serviços", "label": "Status", "level": "read", "target": "service", "fields": F_SERVICE(),
     "desc": "Estado detalhado de um serviço systemd.", "run": run_service_status},
    {"id": "service.restart", "group": "Serviços", "label": "Reiniciar", "level": "change", "target": "service", "fields": F_SERVICE(),
     "desc": "Reinicia um serviço systemd.", "run": run_service("restart"), "when": "running"},
    {"id": "service.start", "group": "Serviços", "label": "Iniciar", "level": "change", "target": "service", "fields": F_SERVICE(),
     "desc": "Inicia um serviço systemd parado.", "run": run_service("start"), "when": "stopped"},
    {"id": "service.stop", "group": "Serviços", "label": "Parar", "level": "danger", "confirm": True, "target": "service", "fields": F_SERVICE(),
     "desc": "Para um serviço systemd.", "run": run_service("stop"), "when": "running"},
    {"id": "service.enable", "group": "Serviços", "label": "Ligar no boot", "level": "change", "target": "service", "fields": F_SERVICE(),
     "desc": "Faz o serviço iniciar junto com o servidor.", "run": run_service("enable"), "when": "disabled"},
    {"id": "service.disable", "group": "Serviços", "label": "Não ligar no boot", "level": "change", "target": "service", "fields": F_SERVICE(),
     "desc": "Impede o serviço de iniciar junto com o servidor.", "run": run_service("disable"), "when": "enabled"},
    {"id": "docker.logs", "group": "Serviços", "label": "Logs", "level": "read", "target": "container", "fields": F_CONTAINER(),
     "desc": "Últimas 200 linhas de log de um container Docker.", "run": run_docker_logs},
    {"id": "docker.restart", "group": "Serviços", "label": "Reiniciar", "level": "change", "target": "container", "fields": F_CONTAINER(),
     "desc": "Reinicia um container Docker.", "run": run_docker("restart")},
    {"id": "docker.stop", "group": "Serviços", "label": "Parar", "level": "danger", "confirm": True, "target": "container", "fields": F_CONTAINER(),
     "desc": "Para um container Docker.", "run": run_docker("stop"), "when": "running"},
    {"id": "docker.start", "group": "Serviços", "label": "Iniciar", "level": "change", "target": "container", "fields": F_CONTAINER(),
     "desc": "Inicia um container Docker parado.", "run": run_docker("start"), "when": "stopped"},
    {"id": "users.create", "group": "Usuários", "label": "Criar usuário", "level": "admin", "run": run_user_create, "placement": "users",
     "desc": "Cria uma conta com login por chave SSH (sem senha).",
     "fields": [f_text("name", "Nome de usuário", USER_RE, placeholder="joao", help="minúsculas, números, - e _"),
                f_select("shell", "Shell", ["/bin/bash", "/bin/sh", "/usr/sbin/nologin"]),
                f_bool("sudo", "Administrador (sudo)"),
                dict(f_text("ssh_key", "Chave SSH pública", SSH_KEY_RE, required=False, placeholder="ssh-ed25519 AAAA… usuario@maquina"), type="textarea")]},
    {"id": "users.add_key", "group": "Usuários", "label": "Adicionar chave SSH", "level": "admin", "target": "user", "run": run_user_add_key,
     "desc": "Autoriza mais uma chave SSH para o usuário.",
     "fields": F_USER() + [dict(f_text("ssh_key", "Chave SSH pública", SSH_KEY_RE), type="textarea")]},
    {"id": "users.make_admin", "group": "Usuários", "label": "Tornar admin", "level": "admin", "target": "user", "run": run_user_sudo(True),
     "desc": "Dá permissão de administrador (sudo).", "fields": F_USER(), "when": "regular"},
    {"id": "users.remove_admin", "group": "Usuários", "label": "Tirar admin", "level": "admin", "target": "user", "run": run_user_sudo(False),
     "desc": "Tira a permissão de administrador (sudo).", "fields": F_USER(), "when": "admin"},
    {"id": "users.lock", "group": "Usuários", "label": "Bloquear", "level": "admin", "target": "user", "run": run_user_lock(True),
     "desc": "Bloqueia o acesso da conta sem apagá-la.", "fields": F_USER(), "when": "unlocked"},
    {"id": "users.unlock", "group": "Usuários", "label": "Desbloquear", "level": "admin", "target": "user", "run": run_user_lock(False),
     "desc": "Libera de novo o acesso da conta.", "fields": F_USER(), "when": "locked"},
    {"id": "users.remove", "group": "Usuários", "label": "Remover", "level": "admin", "confirm": True, "target": "user", "run": run_user_remove,
     "desc": "Apaga a conta do usuário.", "fields": F_USER() + [f_bool("remove_home", "Apagar também a pasta pessoal")]},
    {"id": "cron.add", "group": "Agendamentos", "label": "Novo agendamento", "level": "admin", "run": run_cron_add, "placement": "schedules",
     "desc": "Cria uma tarefa cron (gravada em /etc/cron.d/linux-control).",
     "fields": [dict(f_text("schedule", "Quando", CRON_SCHEDULE_RE, placeholder="0 3 * * *"), type="cron"),
                f_text("user", "Rodar como", USER_RE, placeholder="root", suggest="users"),
                f_text("command", "Comando", r"^[^\r\n]{1,1000}$", placeholder="/usr/local/bin/backup.sh"),
                f_text("description", "Descrição", r"^[^\r\n]{0,80}$", required=False)]},
    {"id": "cron.remove", "group": "Agendamentos", "label": "Remover", "level": "admin", "confirm": True, "target": "cron", "run": run_cron_remove,
     "desc": "Remove um agendamento criado pelo painel.", "fields": [f_text("id", "Id", CRON_ID_RE)]},
    {"id": "apps.install", "group": "Instaladores", "label": "Instalar", "level": "admin", "target": "app", "run": run_app(False), "timeout": 1800,
     "desc": "Instala o programa e liga o serviço dele.", "fields": [f_select("app", "Programa", [a["id"] for a in APPS])], "when": "absent"},
    {"id": "apps.remove", "group": "Instaladores", "label": "Remover", "level": "admin", "confirm": True, "target": "app", "run": run_app(True), "timeout": 1800,
     "desc": "Remove o programa (dados e configurações ficam).", "fields": [f_select("app", "Programa", [a["id"] for a in APPS])], "when": "installed"},
    {"id": "agent.refresh", "group": "Sistema", "label": "Atualizar inventário agora", "level": "read", "run": run_refresh,
     "desc": "Força o agente a recoletar serviços, pacotes, segurança e software."},
    {"id": "system.timezone", "group": "Sistema", "label": "Mudar fuso horário", "level": "admin", "run": run_timezone,
     "desc": "Define o fuso horário do servidor.", "fields": [f_select("timezone", "Fuso horário", TIMEZONES)]},
    {"id": "system.reboot", "group": "Sistema", "label": "Reiniciar servidor", "level": "danger", "confirm": True,
     "desc": "Reinicia o servidor em 1 minuto.",
     "sh": "shutdown -r +1 'Reinício solicitado pelo Linux Control' && echo 'Reinício agendado para daqui a 1 minuto.'"},
]

# Cada linha de tabela (serviço, container, usuário, programa, agendamento) traz "key" e "state" no inventário.
# Uma ação com "target" aparece na linha quando todos os estados de "when" estão presentes, e o campo
# "target_field" do formulário recebe a "key" da linha. Contas de sistema nunca recebem ações.
TARGET_FIELD = {"service": "name", "container": "name", "user": "name", "app": "app", "cron": "id"}
for _a in ACTIONS:
    if "target" in _a:
        _a["target_field"] = TARGET_FIELD[_a["target"]]
        _a["when"] = ([_a["when"]] if isinstance(_a.get("when"), str) else list(_a.get("when", [])))
        if _a["target"] == "user":
            _a["when"].insert(0, "person")
        if _a["target"] == "cron":
            _a["when"].insert(0, "managed")
ACTIONS_BY_ID = {a["id"]: a for a in ACTIONS}
PUBLIC_KEYS = ("id", "group", "label", "desc", "level", "confirm", "target", "target_field", "placement", "fields", "timeout", "when")


def allowed_actions(mode):
    levels = LEVELS_BY_MODE.get(mode, ())
    return [a for a in ACTIONS if a["level"] in levels]


def action_catalog(mode):
    return [{k: a[k] for k in PUBLIC_KEYS if k in a} for a in allowed_actions(mode)]


def validate_params(action, raw):
    """Devolve (params, erro). Só passam os campos declarados, cada um conferido pelo seu tipo."""
    raw = raw if isinstance(raw, dict) else {}
    params = {}
    for f in action.get("fields", []):
        v = raw.get(f["name"])
        if f["type"] == "bool":
            params[f["name"]] = v is True
            continue
        v = "" if v is None else str(v).strip()
        if not v:
            if f.get("required", True):
                return None, "Campo obrigatório: %s" % f["label"]
            continue
        if f["type"] == "select" and v not in f["options"]:
            return None, "Opção inválida em %s" % f["label"]
        if f.get("pattern") and not re.fullmatch(f["pattern"], v):
            return None, "Valor inválido em %s" % f["label"]
        params[f["name"]] = v
    return params, None


def execute_action(cmd, mode, state):
    a = ACTIONS_BY_ID.get(cmd.get("action"))
    if not a or a not in allowed_actions(mode):
        return 126, "Ação não permitida neste servidor: %s (modo de ações: %s)" % (cmd.get("action"), mode)
    params, err = validate_params(a, cmd.get("params"))
    if err:
        return 2, err
    if "run" in a:
        return a["run"](params, state)
    return run(["/bin/sh", "-c", a["sh"]], timeout=int(a.get("timeout", 120)))


# ---------------------------------------------------------------- envio

def collect_inventory(mode, with_packages):
    inv = {
        "system": safe(system_info, {}),
        "services": safe(services, {"available": False, "units": []}),
        "ports": safe(ports, []),
        "docker": safe(docker),
        "software": safe(software, []),
        "apps": safe(apps_status, []),
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


def tls_context(conf, url):
    if url.startswith("https") and conf.get("INSECURE_TLS") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def post(conf, payload):
    url = conf["HUB_URL"].rstrip("/") + "/api/agent/report"
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urlrequest.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer " + conf["TOKEN"],
        "User-Agent": "linux-control-agent/" + VERSION,
    })
    with urlrequest.urlopen(req, timeout=30, context=tls_context(conf, url)) as r:
        return json.loads(r.read().decode("utf-8") or "{}")


def self_update(conf, info):
    """Baixa a versão que o hub oferece, confere o SHA-256 e reinicia o processo com ela."""
    if not conf["HUB_URL"].startswith("https://") or conf.get("INSECURE_TLS") == "1":
        log("atualização ignorada: só é aceita de um hub em HTTPS com certificado verificado")
        return
    path = os.path.realpath(__file__)
    if not os.access(os.path.dirname(path), os.W_OK):
        log("atualização ignorada: sem permissão de escrita em %s" % os.path.dirname(path))
        return
    url = conf["HUB_URL"].rstrip("/") + "/agent/linux-control-agent.py"
    with urlrequest.urlopen(urlrequest.Request(url), timeout=60, context=tls_context(conf, url)) as r:
        code = r.read()
    if hashlib.sha256(code).hexdigest() != info.get("sha256"):
        log("atualização recusada: hash não confere")
        return
    tmp = path + ".new"
    with open(tmp, "wb") as f:
        f.write(code)
    try:
        compile(code, tmp, "exec")
    except SyntaxError as e:
        os.remove(tmp)
        log("atualização recusada: o arquivo novo não compila (%s)" % e)
        return
    os.chmod(tmp, 0o755)
    shutil.copy2(path, path + ".bak")
    os.replace(tmp, path)
    log("agente atualizado para v%s; reiniciando" % info.get("version"))
    os.execv(sys.executable, [sys.executable, path] + sys.argv[1:])


def worker(q, results, lock, mode, state):
    while True:
        cmd = q.get()
        started = time.time()
        log("executando ação %s (%s)" % (cmd.get("action"), cmd.get("id")))
        state["busy"] = True
        try:
            rc, out = execute_action(cmd, mode, state)
        except Exception as e:
            rc, out = 1, "Erro interno do agente: %s" % e
        state["busy"] = False
        if len(out) > MAX_OUTPUT:
            out = "[saída truncada, mostrando o final]\n" + out[-MAX_OUTPUT:]
        with lock:
            results.append({"id": cmd.get("id"), "exit_code": rc, "output": out,
                            "duration": round(time.time() - started, 1)})


def main():
    args = sys.argv[1:]
    conf = load_conf()
    mode = conf.get("ACTIONS", "all")
    if mode not in LEVELS_BY_MODE:
        mode = "readonly"
    col = Collector()

    if "--once" in args:
        col.metrics()
        time.sleep(1)
        print(json.dumps({"metrics": col.metrics(), "inventory": collect_inventory(mode, True)}, indent=2, ensure_ascii=False))
        return
    if "--version" in args:
        print(VERSION)
        return

    if not conf["HUB_URL"] or not conf["TOKEN"]:
        log("HUB_URL e TOKEN são obrigatórios (em %s ou LCTL_HUB_URL/LCTL_TOKEN)" % CONF_PATH)
        sys.exit(2)

    interval = max(10, int(conf["INTERVAL"]))
    inv_every = max(60, int(conf["INVENTORY_EVERY"]))
    pkg_every = max(600, int(conf["PACKAGES_EVERY"]))
    auto_update = conf["AUTO_UPDATE"] != "0"
    q, results, lock = queue.Queue(), [], threading.Lock()
    state = {"force_inventory": False}
    threading.Thread(target=worker, args=(q, results, lock, mode, state), daemon=True).start()

    last_inv = last_pkg = 0
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
                q.put(cmd)
            idle = q.empty() and not state.get("busy") and not results
            if auto_update and resp.get("agent_update") and idle:
                safe(lambda: self_update(conf, resp["agent_update"]))
        except urlerror.HTTPError as e:
            log("hub respondeu HTTP %s" % e.code)
            if e.code == 401:
                log("token recusado pelo hub; confira %s" % CONF_PATH)
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
