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
import base64
import calendar
import fcntl
import glob
import hashlib
import json
import os
import platform
import pty
import pwd
import queue
import select
import struct
import re
import shutil
import signal
import stat
import socket
import ssl
import subprocess
import sys
import termios
import threading
import time
from urllib import error as urlerror
from urllib import request as urlrequest

VERSION = "0.7.2"
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


# ---------------------------------------------------------------- datacenter
#
# O provedor é reconhecido pelo DMI (sem rede); só então o agente pergunta a região ao serviço de metadados
# do próprio provedor (169.254.169.254, que não sai da máquina física). Nada vai para terceiros.

VULTR_REGIONS = {"LAX": "Los Angeles", "SAO": "São Paulo", "EWR": "Nova Jersey", "ORD": "Chicago", "DFW": "Dallas", "SEA": "Seattle",
                 "MIA": "Miami", "ATL": "Atlanta", "SJC": "Vale do Silício", "YTO": "Toronto", "MEX": "Cidade do México",
                 "SCL": "Santiago", "LHR": "Londres", "MAN": "Manchester", "FRA": "Frankfurt", "AMS": "Amsterdã", "CDG": "Paris",
                 "MAD": "Madri", "WAW": "Varsóvia", "STO": "Estocolmo", "NRT": "Tóquio", "ITM": "Osaka", "ICN": "Seul",
                 "SGP": "Singapura", "SYD": "Sydney", "MEL": "Melbourne", "BOM": "Mumbai", "DEL": "Délhi", "BLR": "Bangalore",
                 "JNB": "Joanesburgo", "TLV": "Tel Aviv", "HNL": "Honolulu"}
_cloud_cache = {}


def meta_get(url, headers=None, method="GET", timeout=2):
    """Consulta o serviço de metadados direto, sem proxy."""
    opener = urlrequest.build_opener(urlrequest.ProxyHandler({}))
    req = urlrequest.Request(url, headers=headers or {}, method=method, data=b"" if method == "PUT" else None)
    with opener.open(req, timeout=timeout) as r:
        return r.read(65536).decode("utf-8", "replace").strip()


def _vultr():
    reg = json.loads(meta_get("http://169.254.169.254/v1.json")).get("region") or {}
    code = reg.get("regioncode", "")
    return {"region": code, "city": VULTR_REGIONS.get(code, ""), "country": reg.get("countrycode", "")}


def _aws():
    tok = meta_get("http://169.254.169.254/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "60"}, "PUT")
    az = meta_get("http://169.254.169.254/latest/meta-data/placement/availability-zone", {"X-aws-ec2-metadata-token": tok})
    return {"region": az}


CLOUDS = [  # (texto no DMI, provedor, como descobrir a região)
    ("vultr", "Vultr", _vultr),
    ("amazon", "AWS", _aws),
    ("google", "Google Cloud", lambda: {"region": meta_get("http://169.254.169.254/computeMetadata/v1/instance/zone",
                                                           {"Metadata-Flavor": "Google"}).rsplit("/", 1)[-1]}),
    ("digitalocean", "DigitalOcean", lambda: {"region": meta_get("http://169.254.169.254/metadata/v1/region")}),
    ("7783-7084-3265-9085-8269-3286-77", "Azure", lambda: {"region": meta_get(
        "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text", {"Metadata": "true"})}),
    ("hetzner", "Hetzner", lambda: {"region": meta_get("http://169.254.169.254/hetzner/v1/metadata/availability-zone")}),
    ("oraclecloud", "Oracle Cloud", lambda: {"region": meta_get("http://169.254.169.254/opc/v2/instance/canonicalRegionName",
                                                                {"Authorization": "Bearer Oracle"})}),
    ("linode", "Akamai (Linode)", None),
    ("contabo", "Contabo", None),
    ("ovh", "OVHcloud", None),
    ("hostinger", "Hostinger", None),
    ("magalu", "Magalu Cloud", None),
]


def cloud_info():
    """Provedor e região do datacenter. Guardado em memória: não muda enquanto a máquina existir."""
    if _cloud_cache:
        return _cloud_cache.get("v")
    dmi = " ".join(read("/sys/class/dmi/id/" + f).strip() for f in
                   ("sys_vendor", "product_name", "bios_vendor", "chassis_asset_tag", "board_vendor", "chassis_vendor")).lower()
    res = None
    for mark, name, fn in CLOUDS:
        if mark in dmi:
            res = {"provider": name}
            if fn:
                try:
                    res.update({k: v for k, v in fn().items() if v})
                except Exception:
                    pass  # metadados fora do ar: fica só o provedor
            break
    _cloud_cache["v"] = res
    return res


# ---------------------------------------------------------------- saúde dos discos
#
# Duas fontes: o SMART de cada disco físico (smartctl, do pacote smartmontools) e os erros de leitura e gravação
# que o kernel registra. A segunda funciona também em máquina virtual, onde o SMART não existe.

ATA_ATTRS = {5: "reallocated", 187: "reported_uncorrect", 196: "realloc_events", 197: "pending", 198: "offline_uncorrectable", 199: "crc_errors"}
IO_ERROR_RE = re.compile(r"I/O error|Medium Error|Unrecovered read error|\bUNC\b|critical medium error|Buffer I/O error|"
                         r"EXT4-fs error|XFS \(.*\): (?:Corruption|metadata I/O error)|BTRFS (?:error|critical)|"
                         r"ata\d+(?:\.\d+)?: (?:failed command|exception Emask)|nvme\d+n?\d*: .*(?:I/O .*timeout|controller is down)", re.I)
IO_IGNORE_RE = re.compile(r"\b(loop\d+|sr\d+|fd\d+)\b")


def smart_device(name, dtype):
    cmd = ["smartctl", "-j", "-a", name] + (["-d", dtype] if dtype else [])
    rc, out = run(cmd, timeout=30, merge=False)  # o código de saída do smartctl é um mapa de bits: o JSON vale mesmo assim
    try:
        j = json.loads(out)
    except ValueError:
        return None
    d = {"name": name, "model": j.get("model_name") or j.get("model_family") or "",
         "capacity": (j.get("user_capacity") or {}).get("bytes"), "rotational": (j.get("rotation_rate") or 0) > 0,
         "protocol": (j.get("device") or {}).get("protocol", ""),
         "smart_passed": (j.get("smart_status") or {}).get("passed"),
         "temperature": (j.get("temperature") or {}).get("current"),
         "power_on_hours": (j.get("power_on_time") or {}).get("hours")}
    for a in (j.get("ata_smart_attributes") or {}).get("table", []):
        if a.get("id") in ATA_ATTRS:
            d[ATA_ATTRS[a["id"]]] = (a.get("raw") or {}).get("value")
    nv = j.get("nvme_smart_health_information_log")
    if nv:
        d.update({"media_errors": nv.get("media_errors"), "critical_warning": nv.get("critical_warning"),
                  "wear_pct": nv.get("percentage_used"), "spare_pct": nv.get("available_spare")})
    st = (j.get("ata_smart_self_test_log") or {}).get("standard", {}).get("table") or []
    if st:
        d["last_test"] = {"type": (st[0].get("type") or {}).get("string", ""), "status": (st[0].get("status") or {}).get("string", ""),
                          "passed": (st[0].get("status") or {}).get("passed"), "hours": st[0].get("lifetime_hours")}
    return d


def kernel_io_errors(hours=24):
    if which("journalctl"):
        rc, out = run(["journalctl", "-k", "--since=-%dh" % hours, "--no-pager", "-o", "short-iso", "-q"], timeout=30, merge=False)
    else:
        rc, out = run(["dmesg", "-T"], timeout=15, merge=False)
    lines = [l.strip() for l in out.splitlines() if IO_ERROR_RE.search(l) and not IO_IGNORE_RE.search(l)]
    return len(lines), [mask_secrets(l)[:300] for l in lines[-20:]]


def disk_health():
    res = {"smartctl": bool(which("smartctl")), "virtual": run(["systemd-detect-virt", "-q"], merge=False)[0] == 0, "devices": []}
    if res["smartctl"]:
        rc, out = run(["smartctl", "--scan-open", "-j"], timeout=30, merge=False)
        try:
            devs = json.loads(out).get("devices", [])
        except ValueError:
            devs = []
        for dev in devs[:16]:
            d = smart_device(dev.get("name"), dev.get("type"))
            if d:
                res["devices"].append(d)
    res["io_errors_24h"], res["io_error_lines"] = kernel_io_errors(24)
    return res


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


def fail2ban_sshd():
    """Situação do jail sshd do Fail2ban (a saída do fail2ban-client é sempre em inglês)."""
    rc, out = run(["fail2ban-client", "status", "sshd"], timeout=10, merge=False)
    if rc != 0:
        return None
    num = lambda label: int((re.search(label + r":\s*(\d+)", out) or [0, 0])[1])
    return {"active": True, "banned_now": num("Currently banned"), "banned_total": num("Total banned"), "failed_total": num("Total failed")}


def security():
    sec = {}
    ssh = {}
    rc, out = run(["sshd", "-T"], timeout=5, merge=False) if which("sshd") else (1, "")
    if rc == 0:
        for line in out.splitlines():
            k, _, v = line.partition(" ")
            k = k.lower()  # OpenSSH 10 imprime as chaves com maiúsculas (Port, PermitRootLogin)
            if k in ("port", "permitrootlogin", "passwordauthentication", "pubkeyauthentication") and k not in ssh:
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
        sec["fail2ban_sshd"] = fail2ban_sshd()
    sec["reboot_required"] = os.path.exists("/var/run/reboot-required")
    sec["reboot_pkgs"] = read("/var/run/reboot-required.pkgs").split()
    if which("needs-restarting"):
        rc, _ = run(["needs-restarting", "-r"], timeout=20)
        sec["reboot_required"] = sec["reboot_required"] or rc == 1
    auto = auto_updates_enabled()
    if auto is not None:
        sec["auto_updates"] = auto
    return sec


def auto_updates_enabled():
    """True/False quando dá para saber (apt ou dnf); None em outros sistemas."""
    auto = read("/etc/apt/apt.conf.d/20auto-upgrades")
    if auto:
        return bool(re.search(r'Unattended-Upgrade\s+"1"', auto))
    if os.path.exists("/etc/dnf/automatic.conf"):
        return run(["systemctl", "is-enabled", "dnf-automatic.timer"], merge=False)[1].strip() == "enabled"
    return None


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
#   fixes   códigos de problema do diagnóstico que a ação resolve (botão "Resolver" na Visão geral)
#   available  função opcional: quando devolve False, a ação sai do catálogo publicado
#   done    função opcional das ações de ESTADO: True = já aplicada (o painel mostra "já aplicado" em vez de Executar).
#           Ações sem "done" são repetíveis: limpeza, atualizações e leituras podem rodar quantas vezes for preciso.
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
     "apt": ["ufw"], "dnf": ["ufw"], "post": "P=$(sshd -T 2>/dev/null | awk 'tolower($1)==\"port\"{print $2; exit}'); ufw allow ${P:-22}/tcp; ufw --force enable && ufw status verbose"},
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
    ports = {int(p) for p in re.findall(r"^port (\d+)$", out, re.M | re.I)} if rc == 0 else set()
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


# ---------------------------------------------------------------- correções do diagnóstico
#
# Cada ação abaixo declara em "fixes" os códigos de problema do diagnóstico (hub/features/servers/health.js)
# que ela resolve. O painel mostra o botão "Resolver" ao lado do problema sem conhecer o id da ação.

SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_DROPIN = "/etc/ssh/sshd_config.d/00-linux-control.conf"


def sshd_effective():
    """Configuração em uso (sshd -T). Opções que podem repetir (allowusers…) ficam com os valores juntos."""
    os.makedirs("/run/sshd", exist_ok=True) if os.geteuid() == 0 else None  # sshd -T falha sem ela (Ubuntu com ssh.socket)
    rc, out = run(["sshd", "-T"], timeout=10, merge=False) if which("sshd") else (1, "")
    eff = {}
    for l in out.splitlines() if rc == 0 else []:
        k, _, v = l.partition(" ")
        k = k.lower()  # OpenSSH 10 imprime as chaves com maiúsculas
        eff[k] = (eff[k] + " " + v) if k in eff else v
    return eff


DEFAULT_KEY_FILES = {".ssh/authorized_keys", ".ssh/authorized_keys2", "%h/.ssh/authorized_keys", "%h/.ssh/authorized_keys2"}


def ssh_key_login_blocker(eff):
    """Motivo pelo qual não dá para garantir o login por chave, ou "" se a configuração é a padrão."""
    if eff.get("pubkeyauthentication", "yes") != "yes":
        return "PubkeyAuthentication está desligado: ninguém entra por chave."
    if eff.get("authenticationmethods", "any") != "any":
        return "AuthenticationMethods personalizado (%s)." % eff["authenticationmethods"]
    if not set(eff.get("authorizedkeysfile", ".ssh/authorized_keys").split()) <= DEFAULT_KEY_FILES \
            or eff.get("authorizedkeyscommand", "none") != "none":
        return "As chaves ficam num lugar personalizado (AuthorizedKeysFile/AuthorizedKeysCommand)."
    return ""


def ssh_user_allowed(eff, name):
    import fnmatch
    import grp
    deny = eff.get("denyusers", "").split()
    allow = eff.get("allowusers", "").split()
    if any(fnmatch.fnmatch(name, x.split("@")[0]) for x in deny):
        return False
    if allow and not any(fnmatch.fnmatch(name, x.split("@")[0]) for x in allow):
        return False
    groups = set()
    try:
        pw = pwd.getpwnam(name)
        groups = {g.gr_name for g in grp.getgrall() if name in g.gr_mem} | {grp.getgrgid(pw.pw_gid).gr_name}
    except (KeyError, OSError):
        pass
    if any(fnmatch.fnmatch(g, x) for g in groups for x in eff.get("denygroups", "").split()):
        return False
    ag = eff.get("allowgroups", "").split()
    return not ag or any(fnmatch.fnmatch(g, x) for g in groups for x in ag)


ROOT_KEY_OK = ("yes", "prohibit-password", "without-password")


def admins_with_keys(eff=None):
    """Administradores que continuam entrando por chave: com chave, desbloqueados e liberados pelo sshd."""
    eff = eff if eff is not None else sshd_effective()
    accounts = safe(users, {}).get("accounts", [])
    res = [u["name"] for u in accounts if u["ssh_keys"] and not u["locked"] and u["sudo"] and ssh_user_allowed(eff, u["name"])
           and (u["uid"] != 0 or eff.get("permitrootlogin", "yes") in ROOT_KEY_OK)]
    return res, accounts


def write_atomic(path, content):
    """Grava num temporário da mesma pasta e troca de uma vez, mantendo dono e permissão do original."""
    st = os.stat(path) if os.path.exists(path) else None
    tmp = path + ".lctl-tmp"
    with open(tmp, "w") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, st.st_mode & 0o7777 if st else 0o600)
    if st:
        os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, path)


def sshd_write(path, key, value, prepend):
    """Grava a opção e devolve o conteúdo anterior (None se o arquivo não existia)."""
    before = read(path) if os.path.exists(path) else None
    if prepend:
        content = "# Linux Control\n%s %s\n%s" % (key, value, before or "")
    else:
        lines = [l for l in (before or "").splitlines() if not l.lower().startswith(key.lower() + " ")]
        content = "\n".join(["# Gerenciado pelo Linux Control"] * (not lines) + lines + ["%s %s" % (key, value)]) + "\n"
    write_atomic(path, content)
    return before


def sshd_restore(written):
    for path, before in reversed(written):
        if before is None:
            os.remove(path)
        else:
            write_atomic(path, before)


SSHD_SAME = {"without-password": "prohibit-password"}


def sshd_apply(key, value):
    """Grava a opção no arquivo do painel em sshd_config.d (lido antes dos outros: no sshd vale o primeiro valor)
    ou no topo do sshd_config; confere com sshd -t, desfaz se der erro e recarrega o SSH sem derrubar sessões."""
    if not which("sshd"):
        return 1, "sshd não encontrado neste servidor."
    os.makedirs("/run/sshd", exist_ok=True)
    has_include = os.path.isdir(os.path.dirname(SSHD_DROPIN)) and re.search(
        r"^\s*Include\s+/etc/ssh/sshd_config\.d/", read(SSHD_CONFIG), re.M | re.I)
    targets = ([SSHD_DROPIN] if has_include else []) + [SSHD_CONFIG]
    written, now = [], "?"
    for path in targets:
        written.append((path, sshd_write(path, key, value, prepend=path == SSHD_CONFIG)))
        rc, out = run(["sshd", "-t"], timeout=10)
        if rc != 0:
            sshd_restore(written)
            return 1, "Configuração recusada pelo sshd -t, nada foi alterado:\n" + out
        now = sshd_effective().get(key.lower(), "?")
        if SSHD_SAME.get(now, now) == value:
            break
    else:
        sshd_restore(written)
        return 1, "O sshd continuou usando %s %s mesmo depois da mudança; nada foi alterado. Confira o sshd_config manualmente." % (key, now)
    rc, out = run(["/bin/sh", "-c", "systemctl reload ssh 2>&1 || systemctl reload sshd 2>&1"], timeout=20)
    msg = "%s %s gravado em %s. Sessões abertas continuam conectadas." % (key, value, ", ".join(p for p, _ in written))
    if rc != 0:
        socket = run(["systemctl", "is-active", "ssh.socket"], timeout=10, merge=False)[1].strip() == "active"
        msg += ("\nO SSH é iniciado por socket: cada conexão nova já usa a configuração nova." if socket else
                "\nAtenção: não consegui recarregar o SSH (%s). A mudança vale no próximo reinício do serviço." % out.strip()[:200])
    if re.search(r"^\s*Match\s", read(SSHD_CONFIG) + "".join(read(f) for f in glob.glob("/etc/ssh/sshd_config.d/*.conf")), re.M | re.I):
        msg += "\nHá blocos Match no sshd_config: eles podem manter regras diferentes para alguns usuários ou IPs."
    return 0, msg


def run_ssh_root_password(p, state):
    eff = sshd_effective()
    if eff.get("permitrootlogin") in ("no", "prohibit-password", "without-password", "forced-commands-only"):
        return 0, "Nada a fazer: o root já não entra com senha (PermitRootLogin %s)." % eff["permitrootlogin"]
    keys, accounts = admins_with_keys(eff)
    blocker = ssh_key_login_blocker(eff)
    root_key = "root" in keys and not blocker
    others = [u["name"] for u in accounts if u["sudo"] and u["uid"] != 0 and not u["locked"] and ssh_user_allowed(eff, u["name"])]
    if not root_key and not others:
        return 1, ("Recusado: o root não tem chave SSH utilizável e não há outro administrador. Depois da mudança ninguém entraria como root.\n"
                   + (blocker + "\n" if blocker else "")
                   + "Adicione uma chave em /root/.ssh/authorized_keys ou crie um usuário admin na aba Usuários.")
    rc, out = sshd_apply("PermitRootLogin", "prohibit-password")
    return rc, out + ("\nO root continua entrando com chave SSH." if root_key else "\nEntre com um dos administradores: " + ", ".join(others))


def run_ssh_password_off(p, state):
    eff = sshd_effective()
    if eff.get("passwordauthentication") == "no":
        return 0, "Nada a fazer: o SSH já não aceita senha."
    blocker = ssh_key_login_blocker(eff)
    if blocker:
        return 1, "Recusado: " + blocker + " Desligar a senha poderia trancar todo mundo do lado de fora; faça a mudança manualmente."
    keys, accounts = admins_with_keys(eff)
    if not keys:
        return 1, ("Recusado: nenhum administrador liberado no SSH tem chave cadastrada. Desligar a senha trancaria todo mundo do lado de fora.\n"
                   "Adicione uma chave SSH a um administrador (aba Usuários) e tente de novo.")
    rc, out = sshd_apply("PasswordAuthentication", "no")
    no_key = [u["name"] for u in accounts if not u["ssh_keys"] and not u["locked"]]
    out += "\nContinuam entrando por chave: " + ", ".join(keys)
    if no_key:
        out += "\nSem chave (perdem o acesso por SSH): " + ", ".join(no_key)
    return rc, out


def install_packages_cmd(pkgs):
    pm = package_manager()
    if pm == "apt":
        return "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get -y install " + " ".join(pkgs)
    if pm in ("dnf", "yum"):
        return "%s -y install %s" % (pm, " ".join(pkgs))
    return None


def run_install_app(app_id):
    return lambda p, state: run_app(False)({"app": app_id}, state)


F2B_JAIL = "/etc/fail2ban/jail.d/zz-linux-control.local"


def run_fail2ban(p, state):
    if not which("fail2ban-client"):
        rc, out = run_app(False)({"app": "fail2ban"}, state)
        if rc != 0:
            return rc, out
    else:
        out = "Fail2ban já instalado.\n"
    ports = ",".join(str(x) for x in sorted(ssh_ports()))
    backend = "" if os.path.exists("/var/log/auth.log") or os.path.exists("/var/log/secure") else "backend = systemd\n"
    os.makedirs("/etc/fail2ban/jail.d", exist_ok=True)
    # .local é lido por último: vale mesmo se um jail.local do servidor tiver desligado o [sshd].
    old = "/etc/fail2ban/jail.d/linux-control.conf"
    if os.path.exists(old):
        os.remove(old)
    with open(F2B_JAIL, "w") as f:
        # journalmatch inclui sshd-session: no OpenSSH 9.8+ (Ubuntu 24.10+) é esse processo que registra os logins.
        f.write("# Gerenciado pelo Linux Control\n[sshd]\nenabled = true\nport = %s\n%smaxretry = 5\nfindtime = 600\nbantime = 3600\n"
                "ignoreip = 127.0.0.1/8 ::1\njournalmatch = _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _COMM=sshd + _COMM=sshd-session\n"
                % (ports, backend))
    rc, out2 = run(["/bin/sh", "-c", "systemctl enable fail2ban >/dev/null 2>&1; systemctl restart fail2ban"], timeout=90)
    if rc != 0:
        return rc, out + "\nO Fail2ban não reiniciou:\n" + out2 + "\n" + run(["journalctl", "-u", "fail2ban", "-n", "30", "--no-pager"], timeout=20)[1]
    # Com muito log para ler, o jail pode levar alguns segundos para aparecer.
    status = None
    for _ in range(20):
        time.sleep(1)
        status = fail2ban_sshd()
        if status:
            break
    state["force_inventory"] = True
    if not status:
        jails = run(["fail2ban-client", "status"], timeout=10)[1].strip()
        log = run(["/bin/sh", "-c", "grep -iE 'error|sshd' /var/log/fail2ban.log 2>/dev/null | tail -15"], timeout=10)[1].strip()
        return 1, (out + "\nO jail do SSH não subiu em 20 s. Jails ativos:\n%s\n\nÚltimas linhas relevantes do fail2ban.log:\n%s\n\n"
                   "Confira se algum arquivo em /etc/fail2ban/jail.d/*.local ou jail.local redefine o [sshd]." % (jails, log or "(vazio)"))
    return 0, (out[-2000:] + "\nProteção do SSH ligada (5 tentativas em 10 min = bloqueio de 1 h), configuração em %s.\n"
               "Os contadores começam do zero agora; o painel passa a mostrar os IPs bloqueados nos próximos minutos.\n\n"
               "Jail sshd: %d falha(s), %d IP(s) bloqueado(s)." % (F2B_JAIL, status["failed_total"], status["banned_now"]))

def public_listeners():
    """Portas escutando fora do loopback: o firewall novo precisa mantê-las abertas para nada parar de funcionar.
    UDP sem processo também fica (o WireGuard do kernel escuta assim)."""
    keep = set()
    for r in ports():
        a = r["addr"].strip("[]").split("%")[0]
        if not isinstance(r["port"], int) or a.startswith(("127.", "::ffff:127.")) or a == "::1":
            continue
        udp = r["proto"].startswith("udp")
        keep.add((r["port"], "udp" if udp else "tcp"))
    return keep | {(x, "tcp") for x in ssh_ports()}


def run_enable_firewall(p, state):
    keep = sorted(public_listeners())
    specs = ["%d/%s" % k for k in keep]
    ssh_specs = ["%d/tcp" % x for x in sorted(ssh_ports())]
    pm = package_manager()
    if not which("ufw") and not which("firewall-cmd"):
        cmd = install_packages_cmd(["firewalld"] if pm in ("dnf", "yum") else ["ufw"])
        if not cmd:
            return 1, "Gerenciador de pacotes não suportado para instalar um firewall."
        rc, out = run(["/bin/sh", "-c", cmd], timeout=900)
        if rc != 0 or not (which("ufw") or which("firewall-cmd")):
            return 1, "Não consegui instalar o firewall:\n" + out[-3000:]
    if which("ufw"):
        # Só liga depois de conferir que o SSH está na lista: sem isso o servidor ficaria inacessível.
        check = " && ".join("ufw show added | grep -qw 'allow %s'" % x for x in ssh_specs)
        script = ("set -e; " + "; ".join("ufw allow %s" % x for x in specs) + "; " + check
                  + " && ufw --force enable && ufw status verbose")
    else:
        script = ("set -e; systemctl enable --now firewalld; " + "; ".join("firewall-cmd --permanent --add-port=%s" % x for x in specs)
                  + "; firewall-cmd --reload; firewall-cmd --list-all")
    rc, out = run(["/bin/sh", "-c", script], timeout=120)
    note = ""
    if rc == 0 and which("docker"):
        r2, _ = run(["systemctl", "restart", "docker"], timeout=180)
        note = "\nDocker reiniciado para refazer as regras de rede dos containers." if r2 == 0 else "\nAtenção: reinicie o Docker para refazer as regras de rede dos containers."
    if rc != 0:
        return rc, "Firewall NÃO foi ativado (alguma liberação falhou):\n" + out
    return 0, "Portas mantidas abertas (SSH e tudo que já escutava na rede): %s\n\n%s%s" % (", ".join(specs), out, note)


def run_restart_failed(p, state):
    rc, out = run(["systemctl", "list-units", "--state=failed", "--no-legend", "--plain", "--type=service"], timeout=20, merge=False)
    names = [l.split()[0] for l in out.splitlines() if l.strip() and re.fullmatch(UNIT_RE, l.split()[0])]
    if not names:
        return 0, "Nenhum serviço com falha agora."
    lines, deadline = [], time.time() + 480
    if len(names) > 20:
        lines.append("%d serviços com falha; tentando os 20 primeiros." % len(names))
        names = names[:20]
    for n in names:
        if time.time() > deadline:
            lines.append("Tempo esgotado; os demais ficaram para a próxima execução.")
            break
        run(["systemctl", "reset-failed", "--", n], timeout=20)
        r, o = run(["systemctl", "restart", "--", n], timeout=120)
        st = run(["systemctl", "is-active", "--", n], timeout=10, merge=False)[1].strip()
        lines.append("%s: %s%s" % (n, st, "" if r == 0 else "\n  " + o.strip().replace("\n", "\n  ")[:600]))
    state["force_inventory"] = True
    still = [l for l in lines if ": " in l and not l.split(": ", 1)[1].startswith("active")]
    return (1 if still else 0), "\n".join(lines) + ("\n\nVeja os logs dos que continuam falhando na aba Serviços." if still else "")


def smart_devices():
    rc, out = run(["smartctl", "--scan-open", "-j"], timeout=30, merge=False)
    try:
        return [(d["name"], d.get("type")) for d in json.loads(out).get("devices", [])]
    except (ValueError, KeyError):
        return []


def run_disk_report(p, state):
    parts = []
    if which("smartctl"):
        for name, dtype in smart_devices() or []:
            rc, out = run(["smartctl", "-x", name] + (["-d", dtype] if dtype else []), timeout=60)
            parts.append("==== %s ====\n%s" % (name, out.strip()))
        if not parts:
            parts.append("Nenhum disco com SMART encontrado (comum em máquina virtual: o disco físico é do provedor).")
    else:
        parts.append("smartmontools não instalado: sem leitura SMART. Use \"Instalar monitor de disco\".")
    n, lines = kernel_io_errors(72)
    parts.append("==== Erros de disco no log do kernel (72 h): %d ====\n%s" % (n, "\n".join(lines) or "nenhum"))
    rc, out = run(["/bin/sh", "-c", "lsblk -o NAME,SIZE,TYPE,MODEL,ROTA,MOUNTPOINT 2>/dev/null"], timeout=15)
    parts.append("==== Discos ====\n" + out.strip())
    return 0, "\n\n".join(parts)


def run_disk_test(kind):
    def fn(p, state):
        if not which("smartctl"):
            return 1, "smartmontools não instalado. Use \"Instalar monitor de disco\" primeiro."
        devs = smart_devices()
        if not devs:
            return 1, "Nenhum disco com SMART encontrado (em máquina virtual o teste é feito pelo provedor)."
        out = []
        for name, dtype in devs:
            rc, o = run(["smartctl", "-t", kind, name] + (["-d", dtype] if dtype else []), timeout=30)
            m = re.search(r"Please wait (\d+) minutes", o)
            out.append("%s: %s" % (name, ("teste iniciado, leva cerca de %s min" % m.group(1)) if m else o.strip().splitlines()[-1] if o.strip() else "?"))
        return 0, "\n".join(out) + "\n\nO resultado aparece na aba Discos (coluna Último teste) quando terminar. O servidor segue funcionando durante o teste."
    return fn


def run_smartmontools(p, state):
    cmd = install_packages_cmd(["smartmontools"])
    if not cmd:
        return 1, "Gerenciador de pacotes não suportado."
    rc, out = run(["/bin/sh", "-c", cmd + " && { systemctl enable --now smartmontools 2>/dev/null || systemctl enable --now smartd 2>/dev/null || true; smartctl --scan; }"], timeout=900)
    return rc, out[-4000:]


def run_authorize_key(p, state):
    """Autoriza uma chave SSH para root ou para uma conta de pessoa (nunca contas de sistema)."""
    pw = existing_user(p["user"])
    if not pw:
        return 1, "Usuário %s não existe." % p["user"]
    if pw.pw_uid != 0 and not is_person(pw):
        return 1, "Por segurança, só root e contas de pessoas (UID 1000 ou maior) recebem chaves pelo painel."
    return 0, "%s: %s" % (pw.pw_name, install_ssh_key(pw, p["ssh_key"]))


# ---------------------------------------------------------------- aplicativos de 1 clique
#
# Cada aplicativo web vira uma "stack" Docker Compose em /opt/linux-control/stacks/<nome>/, com um .env (0600)
# de senhas geradas aqui. Um Caddy compartilhado (container lctl-proxy, rede "lctl") recebe as portas 80/443 e
# emite o HTTPS de cada domínio. O compose da receita fica como veio; o que o painel precisa (rede do proxy,
# apelido, porta sem domínio) vai num arquivo de override em JSON, que o Compose aceita como YAML.
# Receitas nativas (LAMP, painéis de hospedagem) rodam o comando de instalação documentado e só ficam registradas.

STACKS_DIR = "/opt/linux-control/stacks"
PROXY_DIR = "/opt/linux-control/proxy"
PROXY_IMAGE = "caddy:2.8.4-alpine"
STACK_NAME_RE = r"^[a-z0-9][a-z0-9-]{1,40}$"
DOMAIN_RE = r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
EMAIL_RE = r"^[^@\s\r\n]{1,64}@[^@\s\r\n]{1,190}\.[A-Za-z]{2,24}$"
APP_RECIPES = []          # preenchido pelo bloco de receitas mais abaixo
APP_BY_ID = {}


def compose_cmd():
    if run(["docker", "compose", "version"], timeout=20, merge=False)[0] == 0:
        return ["docker", "compose"]
    return ["docker-compose"] if which("docker-compose") else None


def stack_meta(name):
    try:
        with open(os.path.join(STACKS_DIR, name, "stack.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def stacks_status():
    res = []
    if not os.path.isdir(STACKS_DIR):
        return res
    cc = compose_cmd() if which("docker") else None
    for name in sorted(os.listdir(STACKS_DIR)):
        meta = stack_meta(name)
        if not meta or not re.fullmatch(STACK_NAME_RE, name):
            continue
        state = "native"
        if meta.get("kind") == "docker" and cc:
            rc, out = run(cc + ["-p", name, "ps", "--format", "json"], timeout=30, merge=False)
            running = 0
            for line in out.strip().splitlines():
                try:
                    items = json.loads(line)
                except ValueError:
                    continue
                for it in items if isinstance(items, list) else [items]:
                    running += 1 if str(it.get("State", "")).lower() == "running" else 0
            state = "running" if running else "stopped"
        res.append({"name": name, "app": meta.get("app"), "label": meta.get("label"), "url": meta.get("url"), "kind": meta.get("kind"),
                    "created": meta.get("created"), "key": name, "state": [state, meta.get("kind", "docker")]})
    return res


def app_catalog():
    """O que o painel mostra na vitrine: sem comandos nem compose, só a descrição e o formulário."""
    keys = ("id", "label", "category", "desc", "kind", "license", "license_note", "min_ram_mb", "min_disk_gb", "os",
            "dedicated_server", "needs_domain", "fields", "post_install", "official_docs", "risk_notes")
    return [{k: r[k] for k in keys if k in r} for r in APP_RECIPES]


def render_tpl(text, values):
    return re.sub(r"\{\{(\w+)\}\}", lambda m: str(values.get(m.group(1), "")), text)


def gen_secret(n=24):
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(alphabet[b % len(alphabet)] for b in os.urandom(n))


def write_private(path, content, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(content)


def port_busy(port):
    return any(r["port"] == port and r["proto"].startswith("tcp") for r in ports())


def proxy_container_running():
    rc, out = run(["docker", "inspect", "-f", "{{.State.Running}}", "lctl-proxy"], timeout=20, merge=False)
    return rc == 0 and out.strip() == "true"


def ensure_proxy(cc, email):
    """Sobe o Caddy compartilhado (uma vez) e recarrega a configuração a partir de sites/*.caddy."""
    os.makedirs(os.path.join(PROXY_DIR, "sites"), exist_ok=True)
    global_opts = "{\n\temail %s\n}\n\n" % email if email else ""
    write_private(os.path.join(PROXY_DIR, "Caddyfile"), global_opts + "import /etc/caddy/sites/*.caddy\n", 0o644)
    compose = {"services": {"proxy": {
        "image": PROXY_IMAGE, "container_name": "lctl-proxy", "restart": "unless-stopped",
        "ports": ["80:80", "443:443", "443:443/udp"],
        "volumes": ["./Caddyfile:/etc/caddy/Caddyfile:ro", "./sites:/etc/caddy/sites:ro", "caddy_data:/data", "caddy_config:/config"],
        "networks": ["lctl"]}},
        "volumes": {"caddy_data": {}, "caddy_config": {}}, "networks": {"lctl": {"external": True}}}
    write_private(os.path.join(PROXY_DIR, "docker-compose.json"), json.dumps(compose, indent=2), 0o644)
    if proxy_container_running():
        return run(["docker", "exec", "lctl-proxy", "caddy", "reload", "--config", "/etc/caddy/Caddyfile"], timeout=60)
    busy = [p for p in (80, 443) if port_busy(p)]
    if busy:
        return 1, ("As portas %s já estão em uso por outro servidor web (Nginx/Apache?). Instale sem domínio "
                   "(o app fica numa porta própria) ou libere as portas 80/443." % ", ".join(map(str, busy)))
    return run(cc + ["-p", "lctl-proxy", "-f", os.path.join(PROXY_DIR, "docker-compose.json"), "up", "-d"], timeout=600)


def run_stack_install(p, state):
    app = APP_BY_ID.get(p["app"])
    if not app:
        return 1, "Aplicativo desconhecido: %s" % p["app"]
    try:
        extra = json.loads(p.get("options") or "{}")
    except ValueError:
        return 2, "Opções inválidas."
    domain = (p.get("domain") or "").lower()
    email = p.get("email") or ""
    if app.get("needs_domain") and not domain and app.get("kind") != "docker":
        return 2, "Este aplicativo precisa de um domínio apontado para o servidor."
    values = {"domain": domain, "email": email}
    for f in app.get("fields", []):
        v = str(extra.get(f["name"], "")).strip()
        if not v and f.get("required", True):
            return 2, "Preencha: %s" % f["label"]
        if v and f.get("pattern") and not re.fullmatch(f["pattern"], v):
            return 2, "Valor inválido em %s" % f["label"]
        # Campos entram em comandos de instalação: sem padrão próprio, só caracteres seguros.
        if "\n" in v or "\r" in v or (v and not f.get("pattern") and not re.fullmatch(r"[A-Za-z0-9@._+:/-]{1,200}", v)):
            return 2, "Valor inválido em %s" % f["label"]
        values[f["name"]] = v
    for s in app.get("secrets", []):
        values[s] = gen_secret()
    ram = int(safe(lambda: os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"), 0) / 1048576)
    warn = ""
    if app.get("min_ram_mb") and ram and ram < app["min_ram_mb"]:
        warn = "Atenção: o servidor tem %d MB de RAM; %s recomenda %d MB.\n" % (ram, app["label"], app["min_ram_mb"])

    if app.get("kind") != "docker":
        name = app["id"]
        os.makedirs(os.path.join(STACKS_DIR, name), exist_ok=True)
        rc, out = run(["/bin/bash", "-c", render_tpl(app["install_cmd"], values)], timeout=int(app.get("timeout", 3600)))
        if rc == 0:
            write_private(os.path.join(STACKS_DIR, name, "stack.json"), json.dumps({
                "app": app["id"], "label": app["label"], "kind": app.get("kind"), "created": int(time.time()), "url": render_tpl(app.get("url", ""), values)}))
        state["force_inventory"] = True
        return rc, warn + out[-30000:] + ("\n\n" + app.get("post_install", "") if rc == 0 else "")

    if not which("docker"):
        rc, out = run_app(False)({"app": "docker"}, state)
        if rc != 0:
            return rc, "Não consegui instalar o Docker:\n" + out[-4000:]
    cc = compose_cmd()
    if not cc:
        return 1, "Docker Compose não encontrado (instale docker-compose-v2 ou o plugin compose)."
    base = re.sub(r"[^a-z0-9-]", "-", (domain.split(".")[0] if domain else app["id"]))[:30].strip("-") or app["id"]
    name = base
    i = 2
    while os.path.exists(os.path.join(STACKS_DIR, name)):
        name = "%s-%d" % (base, i)
        i += 1
    d = os.path.join(STACKS_DIR, name)
    os.makedirs(d, mode=0o700)
    env = "".join("%s=%s\n" % (k, render_tpl(str(v), values).replace("\n", "")) for k, v in app.get("env", {}).items())
    write_private(os.path.join(d, ".env"), env)
    write_private(os.path.join(d, "docker-compose.yml"), app["compose"], 0o644)
    svc, port = app["proxy"]["service"], int(app["proxy"]["port"])
    alias = "%s-web" % name
    override = {"services": {svc: {"networks": {"default": {}, "lctl": {"aliases": [alias]}}}}, "networks": {"lctl": {"external": True}}}
    host_port = None
    if not domain:
        host_port = next(x for x in range(8080, 8999) if not port_busy(x))
        override["services"][svc]["ports"] = ["%d:%d" % (host_port, port)]
    write_private(os.path.join(d, "lctl.override.json"), json.dumps(override, indent=2), 0o644)
    run(["docker", "network", "create", "lctl"], timeout=30)
    files = ["-p", name, "-f", os.path.join(d, "docker-compose.yml"), "-f", os.path.join(d, "lctl.override.json")]
    rc, out = run(cc + files + ["up", "-d"], timeout=1800)
    if rc != 0:
        return rc, warn + "Falha ao subir %s:\n%s\n\nA pasta %s ficou para inspeção; remova pelo painel." % (app["label"], out[-8000:], d)
    if app.get("post_up_cmd"):
        # Configuração inicial documentada pelo fornecedor (ex.: instalação automática do Mautic).
        time.sleep(20)
        prc, pout = run(["/bin/bash", "-c", "cd %s && %s" % (d, render_tpl(app["post_up_cmd"], values))], timeout=1800,
                        env=dict(os.environ, COMPOSE_PROJECT_NAME=name, COMPOSE_FILE="docker-compose.yml:lctl.override.json"))
        out += "\n\nConfiguração inicial:\n" + pout[-4000:]
        if prc != 0:
            out += "\n(a configuração inicial falhou; termine pelo navegador)"
    url = ""
    if domain:
        os.makedirs(os.path.join(PROXY_DIR, "sites"), exist_ok=True)
        write_private(os.path.join(PROXY_DIR, "sites", "%s.caddy" % name), "%s {\n\treverse_proxy %s:%d\n}\n" % (domain, alias, port), 0o644)
        prc, pout = ensure_proxy(cc, email)
        if prc != 0:
            out += "\n\nProxy HTTPS: " + pout
        url = "https://%s" % domain
    else:
        ip = next((i["addr"] for i in system_info().get("ips", []) if not i["addr"].startswith(("10.", "172.", "192.168."))), "IP-DO-SERVIDOR")
        url = "http://%s:%d" % (ip.split("/")[0], host_port)
    write_private(os.path.join(d, "stack.json"), json.dumps({"app": app["id"], "label": app["label"], "kind": "docker", "domain": domain,
                                                              "url": url, "created": int(time.time()), "host_port": host_port}))
    state["force_inventory"] = True
    tips = "\n".join(filter(None, [warn.strip(), "%s instalado: %s" % (app["label"], url),
                                   "Aponte o DNS de %s para este servidor antes (o HTTPS é emitido na primeira visita)." % domain if domain else
                                   "Sem domínio: o acesso é por HTTP na porta %d (libere no firewall se precisar)." % host_port,
                                   "Senhas geradas: %s/.env (só root lê)." % d if app.get("secrets") else "",
                                   render_tpl(app.get("post_install", ""), values)]))
    return 0, tips + "\n\n" + out[-4000:]


def stack_dir(name):
    if not re.fullmatch(STACK_NAME_RE, name or "") or not stack_meta(name):
        return None
    return os.path.join(STACKS_DIR, name)


def run_stack(verb):
    def fn(p, state):
        d = stack_dir(p["name"])
        if not d:
            return 1, "Aplicativo %s não encontrado." % p["name"]
        meta = stack_meta(p["name"])
        if meta.get("kind") != "docker":
            return 1, "%s foi instalado direto no sistema; gerencie pelos serviços dele." % meta.get("label")
        cc = compose_cmd()
        files = ["-p", p["name"], "-f", os.path.join(d, "docker-compose.yml"), "-f", os.path.join(d, "lctl.override.json")]
        if verb == "logs":
            return run(cc + files + ["logs", "--no-color", "--tail", "300"], timeout=60)
        if verb == "remove":
            rc, out = run(cc + files + ["down"] + (["-v"] if p.get("remove_data") else []), timeout=600)
            if rc != 0:
                return rc, out
            site = os.path.join(PROXY_DIR, "sites", "%s.caddy" % p["name"])
            if os.path.exists(site):
                os.remove(site)
                if proxy_container_running():
                    run(["docker", "exec", "lctl-proxy", "caddy", "reload", "--config", "/etc/caddy/Caddyfile"], timeout=60)
            if p.get("remove_data"):
                shutil.rmtree(d)
                out += "\nPasta e volumes apagados."
            else:
                os.rename(os.path.join(d, "stack.json"), os.path.join(d, "stack.removed.json"))
                out += "\nContainers removidos; dados preservados nos volumes e em %s." % d
            state["force_inventory"] = True
            return 0, out
        state["force_inventory"] = True
        return run(cc + files + ([verb] if verb != "start" else ["up", "-d"]), timeout=600)
    return fn


# Receitas pesquisadas na documentação oficial de cada projeto (versões fixas). Revise ao atualizar versões.
APP_RECIPES[:] = json.loads(r'''[
 {
  "id": "wordpress",
  "label": "WordPress",
  "category": "Sites e lojas",
  "desc": "CMS mais usado do mundo para sites, blogs e lojas (com WooCommerce).",
  "kind": "docker",
  "license": "grátis",
  "license_note": "Software livre (GPLv2).",
  "min_ram_mb": 1024,
  "min_disk_gb": 10,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [],
  "secrets": [
   "db_password",
   "db_root_password"
  ],
  "compose": "services:\n  app:\n    image: wordpress:7.1.5-php8.4-apache\n    restart: unless-stopped\n    depends_on:\n      - db\n    environment:\n      WORDPRESS_DB_HOST: db:3306\n      WORDPRESS_DB_NAME: wordpress\n      WORDPRESS_DB_USER: wordpress\n      WORDPRESS_DB_PASSWORD: ${WORDPRESS_DB_PASSWORD}\n    volumes:\n      - wp_data:/var/www/html\n    networks:\n      - lctl\n      - db\n  db:\n    image: mariadb:11.8.9\n    restart: unless-stopped\n    environment:\n      MARIADB_DATABASE: wordpress\n      MARIADB_USER: wordpress\n      MARIADB_PASSWORD: ${WORDPRESS_DB_PASSWORD}\n      MARIADB_ROOT_PASSWORD: ${MARIADB_ROOT_PASSWORD}\n    volumes:\n      - db_data:/var/lib/mysql\n    networks:\n      - db\nvolumes:\n  wp_data:\n  db_data:\nnetworks:\n  lctl:\n    external: true\n  db:\n    internal: true\n",
  "env": {
   "WORDPRESS_DB_PASSWORD": "{{db_password}}",
   "MARIADB_ROOT_PASSWORD": "{{db_root_password}}",
   "DOMAIN": "{{domain}}"
  },
  "proxy": {
   "service": "app",
   "port": 80
  },
  "post_install": "Abrir https://{{domain}} e concluir o assistente (idioma, título do site, usuário e senha do administrador). Depois acessar https://{{domain}}/wp-admin.",
  "official_docs": "https://hub.docker.com/_/wordpress",
  "risk_notes": "A imagem oficial (wp-config-docker.php) já reconhece X-Forwarded-Proto=https do proxy. Até concluir o assistente, quem abrir o domínio primeiro cria o administrador: conclua logo após instalar. Tag 7.1.5 = estável atual em 23/11/2026."
 },
 {
  "id": "lamp",
  "label": "LAMP (Apache + MariaDB + PHP)",
  "category": "Sites e lojas",
  "desc": "Pilha clássica Apache, MariaDB e PHP instalada direto no sistema para hospedar sites PHP.",
  "kind": "native",
  "license": "grátis",
  "license_note": "Pacotes livres das distribuições.",
  "min_ram_mb": 1024,
  "min_disk_gb": 10,
  "os": [
   "ubuntu-22.04",
   "ubuntu-24.04",
   "debian-12",
   "almalinux-9"
  ],
  "dedicated_server": true,
  "needs_domain": false,
  "fields": [],
  "secrets": [],
  "install_cmd": "set -euo pipefail; . /etc/os-release; if command -v apt-get >/dev/null; then\n  export DEBIAN_FRONTEND=noninteractive\n  apt-get update\n  apt-get install -y apache2 mariadb-server mariadb-client php libapache2-mod-php php-mysql php-cli php-curl php-gd php-mbstring php-xml php-zip php-intl php-bcmath php-soap php-opcache unzip\n  a2enmod rewrite headers ssl\n  systemctl enable --now apache2 mariadb\n  systemctl restart apache2\nelif command -v dnf >/dev/null; then\n  dnf install -y httpd mod_ssl mariadb-server php php-cli php-fpm php-mysqlnd php-gd php-mbstring php-xml php-intl php-bcmath php-soap php-opcache php-pdo unzip\n  systemctl enable --now httpd mariadb php-fpm\n  if systemctl is-active --quiet firewalld; then firewall-cmd --permanent --add-service=http --add-service=https; firewall-cmd --reload; fi\nelse\n  echo \"Sistema não suportado\" >&2; exit 1\nfi\nmariadb -e \"DROP USER IF EXISTS ''@'localhost'; DROP USER IF EXISTS ''@'$(hostname)'; DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\\\_%'; FLUSH PRIVILEGES;\"\nphp -v\n",
  "post_install": "Colocar os arquivos do site em /var/www/html. Criar banco e usuário: mariadb -e \"CREATE DATABASE app; CREATE USER 'app'@'localhost' IDENTIFIED BY 'senha'; GRANT ALL ON app.* TO 'app'@'localhost';\". Para HTTPS, instalar certificado (ex.: certbot --apache).",
  "official_docs": "https://ubuntu.com/server/docs/how-to-install-and-configure-php ; https://httpd.apache.org/docs/2.4/ ; https://mariadb.com/docs/server/",
  "risk_notes": "Ocupa as portas 80/443 do host e CONFLITA com o proxy Caddy (lctl-proxy): usar só em servidor sem apps Docker do painel (por isso dedicated_server=true). PHP na versão da distribuição (Ubuntu 22.04=8.1, 24.04=8.3, Debian 12=8.2, Alma 9=8.0 no AppStream padrão). Root do MariaDB fica com autenticação unix_socket (só root local, sem senha). php-zip/php-imagick não estão no AppStream do Alma 9 (precisam EPEL/Remi), por isso não são instalados lá. Sem desinstalação automática; em RHEL altera o firewalld."
 },
 {
  "id": "lemp",
  "label": "LEMP (Nginx + MariaDB + PHP-FPM)",
  "category": "Sites e lojas",
  "desc": "Pilha Nginx, MariaDB e PHP-FPM instalada direto no sistema, leve e rápida para sites PHP.",
  "kind": "native",
  "license": "grátis",
  "license_note": "Pacotes livres das distribuições.",
  "min_ram_mb": 1024,
  "min_disk_gb": 10,
  "os": [
   "ubuntu-22.04",
   "ubuntu-24.04",
   "debian-12",
   "almalinux-9"
  ],
  "dedicated_server": true,
  "needs_domain": false,
  "fields": [],
  "secrets": [],
  "install_cmd": "set -euo pipefail; . /etc/os-release; if command -v apt-get >/dev/null; then\n  export DEBIAN_FRONTEND=noninteractive\n  apt-get update\n  apt-get install -y nginx mariadb-server mariadb-client php-fpm php-mysql php-cli php-curl php-gd php-mbstring php-xml php-zip php-intl php-bcmath php-soap php-opcache unzip\n  PHPV=$(php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;')\n  cat > /etc/nginx/sites-available/default <<EOF\nserver {\n    listen 80 default_server;\n    listen [::]:80 default_server;\n    root /var/www/html;\n    index index.php index.html;\n    server_name _;\n    location / { try_files \\$uri \\$uri/ /index.php?\\$args; }\n    location ~ \\.php\\$ {\n        include snippets/fastcgi-php.conf;\n        fastcgi_pass unix:/run/php/php${PHPV}-fpm.sock;\n    }\n    location ~ /\\.ht { deny all; }\n}\nEOF\n  systemctl enable --now nginx mariadb php${PHPV}-fpm\n  nginx -t && systemctl reload nginx\nelif command -v dnf >/dev/null; then\n  dnf install -y nginx mariadb-server php-fpm php-cli php-mysqlnd php-gd php-mbstring php-xml php-intl php-bcmath php-soap php-opcache php-pdo unzip\n  sed -i 's/^user = apache/user = nginx/; s/^group = apache/group = nginx/' /etc/php-fpm.d/www.conf\n  systemctl enable --now nginx mariadb php-fpm\n  if systemctl is-active --quiet firewalld; then firewall-cmd --permanent --add-service=http --add-service=https; firewall-cmd --reload; fi\nelse\n  echo \"Sistema não suportado\" >&2; exit 1\nfi\nmariadb -e \"DROP USER IF EXISTS ''@'localhost'; DROP USER IF EXISTS ''@'$(hostname)'; DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\\\_%'; FLUSH PRIVILEGES;\"\nphp -v\n",
  "post_install": "Colocar os arquivos em /var/www/html (Debian/Ubuntu) ou /usr/share/nginx/html (Alma). Criar banco e usuário no MariaDB. Para HTTPS, usar certbot --nginx.",
  "official_docs": "https://nginx.org/en/docs/ ; https://www.php.net/manual/en/install.fpm.php ; https://mariadb.com/docs/server/",
  "risk_notes": "Ocupa as portas 80/443 do host e CONFLITA com o proxy Caddy (lctl-proxy). Sobrescreve /etc/nginx/sites-available/default em Debian/Ubuntu. Em Alma, o PHP-FPM passa a rodar como usuário nginx (o pacote nginx do Alma já inclui o handler PHP-FPM em /etc/nginx/default.d/php.conf). PHP na versão da distribuição. Sem desinstalação automática."
 },
 {
  "id": "n8n",
  "label": "n8n",
  "category": "Automação",
  "desc": "Plataforma de automação de fluxos com centenas de integrações e nós de IA.",
  "kind": "docker",
  "license": "freemium",
  "license_note": "Sustainable Use License (fair-code): uso interno grátis; recursos Enterprise exigem licença paga.",
  "min_ram_mb": 2048,
  "min_disk_gb": 20,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [
   {
    "name": "timezone",
    "label": "Fuso horário",
    "type": "text",
    "pattern": "^[A-Za-z_]+(/[A-Za-z_+-]+)*$",
    "required": false,
    "default": "America/Sao_Paulo"
   }
  ],
  "secrets": [
   "db_password",
   "encryption_key"
  ],
  "compose": "services:\n  app:\n    image: docker.n8n.io/n8nio/n8n:2.48.8\n    restart: unless-stopped\n    depends_on:\n      - postgres\n    environment:\n      N8N_HOST: ${DOMAIN}\n      N8N_PORT: \"5678\"\n      N8N_PROTOCOL: https\n      N8N_PROXY_HOPS: \"1\"\n      N8N_EDITOR_BASE_URL: https://${DOMAIN}/\n      N8N_WEBHOOK_URL: https://${DOMAIN}/\n      WEBHOOK_URL: https://${DOMAIN}/\n      N8N_ENCRYPTION_KEY: ${N8N_ENCRYPTION_KEY}\n      N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS: \"true\"\n      NODE_ENV: production\n      GENERIC_TIMEZONE: ${TZ}\n      TZ: ${TZ}\n      DB_TYPE: postgresdb\n      DB_POSTGRESDB_HOST: postgres\n      DB_POSTGRESDB_PORT: \"5432\"\n      DB_POSTGRESDB_DATABASE: n8n\n      DB_POSTGRESDB_USER: n8n\n      DB_POSTGRESDB_PASSWORD: ${DB_PASSWORD}\n    volumes:\n      - n8n_data:/home/node/.n8n\n    networks:\n      - lctl\n      - db\n  postgres:\n    image: postgres:17.12\n    restart: unless-stopped\n    environment:\n      POSTGRES_DB: n8n\n      POSTGRES_USER: n8n\n      POSTGRES_PASSWORD: ${DB_PASSWORD}\n    volumes:\n      - pg_data:/var/lib/postgresql/data\n    networks:\n      - db\nvolumes:\n  n8n_data:\n  pg_data:\nnetworks:\n  lctl:\n    external: true\n  db:\n    internal: true\n",
  "env": {
   "DOMAIN": "{{domain}}",
   "DB_PASSWORD": "{{db_password}}",
   "N8N_ENCRYPTION_KEY": "{{encryption_key}}",
   "TZ": "{{timezone}}"
  },
  "proxy": {
   "service": "app",
   "port": 5678
  },
  "post_install": "Abrir https://{{domain}} e criar a conta de proprietário (owner). Guardar o N8N_ENCRYPTION_KEY do .env junto com o backup: sem ele as credenciais salvas ficam ilegíveis.",
  "official_docs": "https://docs.n8n.io/hosting/installation/server-setups/docker-compose/ ; https://docs.n8n.io/hosting/configuration/environment-variables/database/",
  "risk_notes": "2.48.8 = canal 'stable' em 23/11/2026 (2.49.x está como 'next/beta'). Desde a 2.30 a variável oficial é N8N_WEBHOOK_URL; WEBHOOK_URL mantida por compatibilidade. O exemplo oficial de Docker usa SQLite; o bloco Postgres segue as variáveis DB_POSTGRESDB_* da doc de banco. RAM mínima não consta na doc: 2 GB é estimativa (NÃO CONFIRMADO). Até criar o owner, o primeiro visitante vira administrador."
 },
 {
  "id": "mautic",
  "label": "Mautic",
  "category": "Marketing e CRM",
  "desc": "Automação de marketing open source: e-mail, landing pages, formulários, segmentação e lead scoring.",
  "kind": "docker",
  "license": "grátis",
  "license_note": "Software livre (GPLv3).",
  "min_ram_mb": 2048,
  "min_disk_gb": 20,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [
   {
    "name": "admin_email",
    "label": "E-mail do administrador",
    "type": "text",
    "pattern": "^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$",
    "required": true
   }
  ],
  "secrets": [
   "db_password",
   "db_root_password",
   "admin_password"
  ],
  "compose": "services:\n  app:\n    image: mautic/mautic:7.2.2-apache\n    restart: unless-stopped\n    environment:\n      DOCKER_MAUTIC_ROLE: mautic_web\n      MAUTIC_DB_HOST: db\n      MAUTIC_DB_PORT: \"3306\"\n      MAUTIC_DB_DATABASE: mautic\n      MAUTIC_DB_USER: mautic\n      MAUTIC_DB_PASSWORD: ${DB_PASSWORD}\n      MAUTIC_MESSENGER_DSN_EMAIL: doctrine://default\n      MAUTIC_MESSENGER_DSN_HIT: doctrine://default\n      PHP_INI_VALUE_DATE_TIMEZONE: America/Sao_Paulo\n    volumes:\n      - mautic_config:/var/www/html/config\n      - mautic_logs:/var/www/html/var/logs\n      - mautic_files:/var/www/html/docroot/media/files\n      - mautic_images:/var/www/html/docroot/media/images\n    depends_on:\n      db:\n        condition: service_healthy\n    healthcheck:\n      test: [\"CMD\", \"curl\", \"-fs\", \"-o\", \"/dev/null\", \"http://localhost\"]\n      interval: 10s\n      timeout: 5s\n      retries: 60\n      start_period: 30s\n    networks:\n      - lctl\n      - db\n  mautic_cron:\n    image: mautic/mautic:7.2.2-apache\n    restart: unless-stopped\n    environment:\n      DOCKER_MAUTIC_ROLE: mautic_cron\n      MAUTIC_DB_HOST: db\n      MAUTIC_DB_PORT: \"3306\"\n      MAUTIC_DB_DATABASE: mautic\n      MAUTIC_DB_USER: mautic\n      MAUTIC_DB_PASSWORD: ${DB_PASSWORD}\n      MAUTIC_MESSENGER_DSN_EMAIL: doctrine://default\n      MAUTIC_MESSENGER_DSN_HIT: doctrine://default\n      PHP_INI_VALUE_DATE_TIMEZONE: America/Sao_Paulo\n    volumes:\n      - mautic_config:/var/www/html/config\n      - mautic_logs:/var/www/html/var/logs\n      - mautic_files:/var/www/html/docroot/media/files\n      - mautic_images:/var/www/html/docroot/media/images\n    depends_on:\n      app:\n        condition: service_healthy\n    networks:\n      - default\n      - db\n  mautic_worker:\n    image: mautic/mautic:7.2.2-apache\n    restart: unless-stopped\n    environment:\n      DOCKER_MAUTIC_ROLE: mautic_worker\n      MAUTIC_DB_HOST: db\n      MAUTIC_DB_PORT: \"3306\"\n      MAUTIC_DB_DATABASE: mautic\n      MAUTIC_DB_USER: mautic\n      MAUTIC_DB_PASSWORD: ${DB_PASSWORD}\n      MAUTIC_MESSENGER_DSN_EMAIL: doctrine://default\n      MAUTIC_MESSENGER_DSN_HIT: doctrine://default\n      PHP_INI_VALUE_DATE_TIMEZONE: America/Sao_Paulo\n    volumes:\n      - mautic_config:/var/www/html/config\n      - mautic_logs:/var/www/html/var/logs\n      - mautic_files:/var/www/html/docroot/media/files\n      - mautic_images:/var/www/html/docroot/media/images\n    depends_on:\n      app:\n        condition: service_healthy\n    networks:\n      - default\n      - db\n  db:\n    image: mysql:8.4.13\n    restart: unless-stopped\n    environment:\n      MYSQL_DATABASE: mautic\n      MYSQL_USER: mautic\n      MYSQL_PASSWORD: ${DB_PASSWORD}\n      MYSQL_ROOT_PASSWORD: ${DB_ROOT_PASSWORD}\n    volumes:\n      - mysql_data:/var/lib/mysql\n    healthcheck:\n      test: mysqladmin --user=$$MYSQL_USER --password=$$MYSQL_PASSWORD ping\n      interval: 5s\n      timeout: 5s\n      retries: 30\n      start_period: 10s\n    networks:\n      - db\nvolumes:\n  mysql_data:\n  mautic_config:\n  mautic_logs:\n  mautic_files:\n  mautic_images:\nnetworks:\n  default:\n  lctl:\n    external: true\n  db:\n    internal: true\n",
  "env": {
   "DB_PASSWORD": "{{db_password}}",
   "DB_ROOT_PASSWORD": "{{db_root_password}}",
   "DOMAIN": "{{domain}}",
   "ADMIN_EMAIL": "{{admin_email}}",
   "ADMIN_PASSWORD": "{{admin_password}}"
  },
  "proxy": {
   "service": "app",
   "port": 80
  },
  "post_up_cmd": "docker compose exec -T --user www-data --workdir /var/www/html app php ./bin/console mautic:install \"https://{{domain}}\" --admin_email=\"{{admin_email}}\" --admin_password=\"{{admin_password}}\"",
  "post_install": "Entrar em https://{{domain}} com o e-mail informado e a senha gerada (ADMIN_PASSWORD no .env). Se o painel não rodar o post_up_cmd, o instalador web aparece no primeiro acesso. Depois configurar o envio de e-mail (SMTP/SES) em Configurações > E-mail.",
  "official_docs": "https://github.com/mautic/docker-mautic ; https://docs.mautic.org/en/7.x/",
  "risk_notes": "Versão estável atual é a 7.2.2 (se exigirem a 5, existe 5.2.12-apache, ainda com correções). Banco MySQL 8.4 LTS, como no exemplo oficial (mysql:lts). O post_up_cmd (campo extra: rodar na pasta da stack após o primeiro 'up', quando o app estiver saudável) usa o comando de instalação documentado no README do docker-mautic. Gerar ADMIN_PASSWORD só com letras e números. Atrás de proxy pode ser preciso cadastrar o proxy em Configurações > Sistema > 'Trusted proxies' para URLs https corretas: NÃO CONFIRMADO via variável de ambiente."
 },
 {
  "id": "openclaw",
  "label": "OpenClaw (ex-Moltbot/Clawdbot)",
  "category": "Inteligência artificial",
  "desc": "Assistente pessoal de IA no seu servidor, que conversa por WhatsApp, Telegram, Discord e outros canais.",
  "kind": "docker",
  "license": "grátis",
  "license_note": "Código aberto (MIT). Exige chave de um provedor de IA (OpenAI, Anthropic etc., pagos por uso) ou modelo local.",
  "min_ram_mb": 2048,
  "min_disk_gb": 10,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [
   {
    "name": "openai_api_key",
    "label": "Chave de API da OpenAI",
    "type": "password",
    "pattern": "^sk-[A-Za-z0-9_\\-]{20,}$",
    "required": true
   },
   {
    "name": "telegram_bot_token",
    "label": "Token do bot do Telegram (opcional)",
    "type": "password",
    "pattern": "^([0-9]+:[A-Za-z0-9_\\-]{30,})?$",
    "required": false
   }
  ],
  "secrets": [
   "gateway_token"
  ],
  "compose": "services:\n  openclaw-gateway:\n    image: ghcr.io/openclaw/openclaw:2026.11.7\n    restart: unless-stopped\n    init: true\n    env_file:\n      - .env\n    environment:\n      HOME: /home/node\n      OPENCLAW_HOME: /home/node\n      OPENCLAW_STATE_DIR: /home/node/.openclaw\n      OPENCLAW_CONFIG_PATH: /home/node/.openclaw/openclaw.json\n      OPENCLAW_CONFIG_DIR: /home/node/.openclaw\n      OPENCLAW_WORKSPACE_DIR: /home/node/.openclaw/workspace\n      OPENCLAW_GATEWAY_PORT: \"18789\"\n      OPENCLAW_GATEWAY_TOKEN: ${OPENCLAW_GATEWAY_TOKEN}\n      TZ: America/Sao_Paulo\n    command: [\"node\", \"dist/index.js\", \"gateway\", \"--bind\", \"lan\", \"--port\", \"18789\"]\n    cap_drop:\n      - NET_RAW\n      - NET_ADMIN\n    security_opt:\n      - no-new-privileges:true\n    volumes:\n      - openclaw_state:/home/node/.openclaw\n      - openclaw_secrets:/home/node/.config/openclaw\n    healthcheck:\n      test: [\"CMD\", \"node\", \"dist/docker-healthcheck.js\"]\n      interval: 30s\n      timeout: 5s\n      retries: 5\n      start_period: 20s\n    networks:\n      - lctl\nvolumes:\n  openclaw_state:\n  openclaw_secrets:\nnetworks:\n  lctl:\n    external: true\n",
  "env": {
   "OPENCLAW_GATEWAY_TOKEN": "{{gateway_token}}",
   "OPENAI_API_KEY": "{{openai_api_key}}",
   "TELEGRAM_BOT_TOKEN": "{{telegram_bot_token}}",
   "DOMAIN": "{{domain}}"
  },
  "proxy": {
   "service": "openclaw-gateway",
   "port": 18789
  },
  "post_up_cmd": "docker compose stop openclaw-gateway && docker compose run -T --rm --no-deps --entrypoint node openclaw-gateway dist/index.js onboard --non-interactive --accept-risk --skip-health --mode local --auth-choice openai-api-key --secret-input-mode ref --gateway-auth token --gateway-token-ref-env OPENCLAW_GATEWAY_TOKEN --skip-channels --no-install-daemon && docker compose run -T --rm --no-deps --entrypoint node openclaw-gateway dist/index.js config set --batch-json '[{\"path\":\"gateway.mode\",\"value\":\"local\"},{\"path\":\"gateway.bind\",\"value\":\"lan\"},{\"path\":\"gateway.controlUi.allowedOrigins\",\"value\":[\"https://{{domain}}\"]}]' && if [ -n \"{{telegram_bot_token}}\" ]; then docker compose run -T --rm --no-deps --entrypoint node openclaw-gateway dist/index.js channels add --channel telegram --use-env; fi && docker compose up -d openclaw-gateway",
  "post_install": "Abrir https://{{domain}}/ (Control UI) e colar o token do gateway (OPENCLAW_GATEWAY_TOKEN do .env) em Settings. WhatsApp: 'docker compose run --rm --no-deps --entrypoint node openclaw-gateway dist/index.js channels login' e ler o QR code.",
  "official_docs": "https://docs.openclaw.ai/install/docker",
  "risk_notes": "Exige chave de provedor de IA paga (receita usa OpenAI, que é o exemplo do fluxo não interativo oficial; para Anthropic e outros, rodar 'onboard' interativo: valor de --auth-choice NÃO CONFIRMADO). Compose adaptado do oficial: sem portas publicadas (18789/18790/3978), bind mounts do HOME trocados por volumes nomeados e serviço openclaw-cli omitido. Liberar https://dominio em gateway.controlUi.allowedOrigins atrás de proxy é inferência (a doc só mostra localhost): NÃO CONFIRMADO. O agente executa ferramentas e age nas contas conectadas; a doc recomenda um gateway por fronteira de confiança. Para navegação web, usar a tag 2026.11.7-browser. Volumes nomeados: se o gateway (usuário node, uid 1000) não conseguir gravar em /home/node/.openclaw, ajustar dono para 1000:1000 (NÃO CONFIRMADO se a imagem já cria o diretório com o dono certo). post_up_cmd é um campo extra desta receita: comandos a rodar na pasta da stack após o primeiro 'up'."
 },
 {
  "id": "hermes-agent",
  "label": "Hermes Agent (Nous Research)",
  "category": "Inteligência artificial",
  "desc": "Agente de IA autônomo com memória e habilidades, integrado a Telegram, Discord e Slack, com painel web.",
  "kind": "docker",
  "license": "grátis",
  "license_note": "Código aberto (MIT). Exige chave de um provedor de LLM (OpenRouter, Anthropic, OpenAI, Nous Portal), pago por uso, ou endpoint local.",
  "min_ram_mb": 2048,
  "min_disk_gb": 5,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [
   {
    "name": "openrouter_api_key",
    "label": "Chave de API do OpenRouter (opcional)",
    "type": "password",
    "pattern": "^(sk-or-[A-Za-z0-9_\\-]{20,})?$",
    "required": false
   },
   {
    "name": "anthropic_api_key",
    "label": "Chave de API da Anthropic (opcional)",
    "type": "password",
    "pattern": "^(sk-ant-[A-Za-z0-9_\\-]{20,})?$",
    "required": false
   },
   {
    "name": "dashboard_user",
    "label": "Usuário do painel",
    "type": "text",
    "pattern": "^[a-zA-Z0-9_.-]{3,32}$",
    "required": true,
    "default": "admin"
   }
  ],
  "secrets": [
   "dashboard_password",
   "api_server_key"
  ],
  "compose": "services:\n  hermes:\n    image: nousresearch/hermes-agent:v0.23.3\n    restart: unless-stopped\n    command: [\"gateway\", \"run\"]\n    shm_size: 1g\n    environment:\n      HERMES_DASHBOARD: \"1\"\n      HERMES_DASHBOARD_HOST: 0.0.0.0\n      HERMES_DASHBOARD_BASIC_AUTH_USERNAME: ${DASHBOARD_USER}\n      HERMES_DASHBOARD_BASIC_AUTH_PASSWORD: ${DASHBOARD_PASSWORD}\n      API_SERVER_ENABLED: \"true\"\n      API_SERVER_HOST: 0.0.0.0\n      API_SERVER_KEY: ${API_SERVER_KEY}\n      OPENROUTER_API_KEY: ${OPENROUTER_API_KEY}\n      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}\n    volumes:\n      - hermes_data:/opt/data\n    networks:\n      - lctl\nvolumes:\n  hermes_data:\nnetworks:\n  lctl:\n    external: true\n",
  "env": {
   "DASHBOARD_USER": "{{dashboard_user}}",
   "DASHBOARD_PASSWORD": "{{dashboard_password}}",
   "API_SERVER_KEY": "{{api_server_key}}",
   "OPENROUTER_API_KEY": "{{openrouter_api_key}}",
   "ANTHROPIC_API_KEY": "{{anthropic_api_key}}"
  },
  "proxy": {
   "service": "hermes",
   "port": 9119
  },
  "post_install": "Abrir https://{{domain}} e entrar com o usuário e a senha do painel. Para escolher provedor/modelo e conectar Telegram/Discord/Slack: 'docker compose run -it --rm hermes setup' (interativo) e depois 'docker compose restart hermes'. A API compatível com OpenAI fica na porta interna 8642 (Bearer = API_SERVER_KEY).",
  "official_docs": "https://hermes-agent.nousresearch.com/docs/user-guide/docker",
  "risk_notes": "v0.23.3 = última estável (latest/stable). O assistente 'setup' é interativo; só passar a chave por variável pode não definir provedor/modelo: NÃO CONFIRMADO. A doc avisa que o gateway não deve ficar exposto direto na internet; aqui só o painel (9119) passa pelo proxy, e o próprio Hermes exige basic auth em bind não-loopback. Requisitos oficiais: 1 GB mínimo, 2-4 GB recomendado; ferramentas de navegador pedem 2 GB e shm de 1 GB. Nunca rodar dois containers no mesmo volume. Também há instalador nativo (scripts/install.sh), não usado aqui."
 },
 {
  "id": "ollama-open-webui",
  "label": "Ollama + Open WebUI",
  "category": "Inteligência artificial",
  "desc": "Modelos de linguagem locais (Llama, Qwen, Gemma etc.) com interface de chat estilo ChatGPT.",
  "kind": "docker",
  "license": "grátis",
  "license_note": "Ollama: MIT. Open WebUI: licença própria baseada em BSD-3 com cláusula de marca (grátis; remover a marca exige licença acima de 50 usuários).",
  "min_ram_mb": 8192,
  "min_disk_gb": 50,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [],
  "secrets": [
   "webui_secret_key"
  ],
  "compose": "services:\n  ollama:\n    image: ollama/ollama:0.40.17\n    restart: unless-stopped\n    volumes:\n      - ollama_data:/root/.ollama\n    networks:\n      - default\n  open-webui:\n    image: ghcr.io/open-webui/open-webui:v0.13.4\n    restart: unless-stopped\n    depends_on:\n      - ollama\n    environment:\n      OLLAMA_BASE_URL: http://ollama:11434\n      WEBUI_SECRET_KEY: ${WEBUI_SECRET_KEY}\n      WEBUI_URL: https://${DOMAIN}\n    volumes:\n      - webui_data:/app/backend/data\n    networks:\n      - lctl\n      - default\nvolumes:\n  ollama_data:\n  webui_data:\nnetworks:\n  default:\n  lctl:\n    external: true\n",
  "env": {
   "WEBUI_SECRET_KEY": "{{webui_secret_key}}",
   "DOMAIN": "{{domain}}"
  },
  "proxy": {
   "service": "open-webui",
   "port": 8080
  },
  "post_install": "Abrir https://{{domain}} e criar a conta (a primeira vira administradora). Baixar um modelo em Configurações > Modelos ou com 'docker compose exec ollama ollama pull llama3.2:3b'. Depois, desativar novos cadastros no Painel de Admin.",
  "official_docs": "https://docs.openwebui.com/getting-started/quick-start/ ; https://docs.ollama.com/docker",
  "risk_notes": "Sem GPU os modelos rodam na CPU e ficam lentos; GPU NVIDIA exige NVIDIA Container Toolkit no host e 'deploy.resources.reservations.devices' no serviço ollama (não incluído). RAM: ~8 GB para modelos 7-8B quantizados, 16 GB+ para 13B+; cada modelo ocupa de 2 a 40+ GB de disco. A API do Ollama (11434) não tem autenticação, por isso fica só na rede interna. O primeiro visitante vira admin."
 },
 {
  "id": "chatwoot",
  "label": "Chatwoot",
  "category": "Marketing e CRM",
  "desc": "Central de atendimento omnichannel (chat do site, WhatsApp, e-mail, Instagram) com caixa de entrada compartilhada.",
  "kind": "docker",
  "license": "freemium",
  "license_note": "Imagem Community (-ce) é MIT e grátis; recursos Enterprise exigem plano pago.",
  "min_ram_mb": 4096,
  "min_disk_gb": 20,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [],
  "secrets": [
   "db_password",
   "redis_password",
   "secret_key_base"
  ],
  "compose": "services:\n  migrate:\n    image: chatwoot/chatwoot:v4.20.1-ce\n    restart: \"no\"\n    command: [\"bundle\", \"exec\", \"rails\", \"db:chatwoot_prepare\"]\n    depends_on:\n      - postgres\n      - redis\n    environment:\n      NODE_ENV: production\n      RAILS_ENV: production\n      INSTALLATION_ENV: docker\n      SECRET_KEY_BASE: ${SECRET_KEY_BASE}\n      FRONTEND_URL: https://${DOMAIN}\n      ENABLE_ACCOUNT_SIGNUP: \"false\"\n      DEFAULT_LOCALE: pt_BR\n      RAILS_LOG_TO_STDOUT: \"true\"\n      POSTGRES_HOST: postgres\n      POSTGRES_USERNAME: chatwoot\n      POSTGRES_PASSWORD: ${DB_PASSWORD}\n      POSTGRES_DATABASE: chatwoot\n      REDIS_URL: redis://redis:6379\n      REDIS_PASSWORD: ${REDIS_PASSWORD}\n      ACTIVE_STORAGE_SERVICE: local\n    volumes:\n      - storage_data:/app/storage\n    networks:\n      - db\n  rails:\n    image: chatwoot/chatwoot:v4.20.1-ce\n    restart: unless-stopped\n    entrypoint: docker/entrypoints/rails.sh\n    command: [\"bundle\", \"exec\", \"rails\", \"s\", \"-p\", \"3000\", \"-b\", \"0.0.0.0\"]\n    depends_on:\n      migrate:\n        condition: service_completed_successfully\n    environment:\n      NODE_ENV: production\n      RAILS_ENV: production\n      INSTALLATION_ENV: docker\n      SECRET_KEY_BASE: ${SECRET_KEY_BASE}\n      FRONTEND_URL: https://${DOMAIN}\n      ENABLE_ACCOUNT_SIGNUP: \"false\"\n      DEFAULT_LOCALE: pt_BR\n      RAILS_LOG_TO_STDOUT: \"true\"\n      POSTGRES_HOST: postgres\n      POSTGRES_USERNAME: chatwoot\n      POSTGRES_PASSWORD: ${DB_PASSWORD}\n      POSTGRES_DATABASE: chatwoot\n      REDIS_URL: redis://redis:6379\n      REDIS_PASSWORD: ${REDIS_PASSWORD}\n      ACTIVE_STORAGE_SERVICE: local\n    volumes:\n      - storage_data:/app/storage\n    networks:\n      - lctl\n      - db\n  sidekiq:\n    image: chatwoot/chatwoot:v4.20.1-ce\n    restart: unless-stopped\n    command: [\"bundle\", \"exec\", \"sidekiq\", \"-C\", \"config/sidekiq.yml\"]\n    depends_on:\n      migrate:\n        condition: service_completed_successfully\n    environment:\n      NODE_ENV: production\n      RAILS_ENV: production\n      INSTALLATION_ENV: docker\n      SECRET_KEY_BASE: ${SECRET_KEY_BASE}\n      FRONTEND_URL: https://${DOMAIN}\n      ENABLE_ACCOUNT_SIGNUP: \"false\"\n      DEFAULT_LOCALE: pt_BR\n      RAILS_LOG_TO_STDOUT: \"true\"\n      POSTGRES_HOST: postgres\n      POSTGRES_USERNAME: chatwoot\n      POSTGRES_PASSWORD: ${DB_PASSWORD}\n      POSTGRES_DATABASE: chatwoot\n      REDIS_URL: redis://redis:6379\n      REDIS_PASSWORD: ${REDIS_PASSWORD}\n      ACTIVE_STORAGE_SERVICE: local\n    volumes:\n      - storage_data:/app/storage\n    networks:\n      - default\n      - db\n  postgres:\n    image: pgvector/pgvector:0.8.7-pg16\n    restart: unless-stopped\n    environment:\n      POSTGRES_DB: chatwoot\n      POSTGRES_USER: chatwoot\n      POSTGRES_PASSWORD: ${DB_PASSWORD}\n    volumes:\n      - postgres_data:/var/lib/postgresql/data\n    networks:\n      - db\n  redis:\n    image: redis:7.4.12-alpine\n    restart: unless-stopped\n    command: [\"sh\", \"-c\", \"redis-server --requirepass \\\"$$REDIS_PASSWORD\\\"\"]\n    environment:\n      REDIS_PASSWORD: ${REDIS_PASSWORD}\n    volumes:\n      - redis_data:/data\n    networks:\n      - db\nvolumes:\n  storage_data:\n  postgres_data:\n  redis_data:\nnetworks:\n  default:\n  lctl:\n    external: true\n  db:\n    internal: true\n",
  "env": {
   "DOMAIN": "{{domain}}",
   "DB_PASSWORD": "{{db_password}}",
   "REDIS_PASSWORD": "{{redis_password}}",
   "SECRET_KEY_BASE": "{{secret_key_base}}"
  },
  "proxy": {
   "service": "rails",
   "port": 3000
  },
  "post_install": "Abrir https://{{domain}} e criar a conta de super administrador. Configurar SMTP (SMTP_* e MAILER_SENDER_EMAIL no .env) para convites e notificações, e adicionar as caixas de entrada.",
  "official_docs": "https://developers.chatwoot.com/self-hosted/deployment/docker ; https://developers.chatwoot.com/self-hosted/configuration/environment-variables",
  "risk_notes": "O serviço 'migrate' roda 'rails db:chatwoot_prepare' (passo obrigatório da doc, idempotente) a cada subida e após atualizar a imagem. SECRET_KEY_BASE: gerar 128 caracteres hex. A doc pede ao Nginx 'underscores_in_headers on'; verificar se o lctl-proxy (Caddy) não descarta cabeçalhos com '_'. Imagem oficial usa pgvector:pg16 e redis:alpine, aqui com tags fixas. RAM mínima não consta na página de Docker: 4 GB é estimativa (NÃO CONFIRMADO)."
 },
 {
  "id": "odoo",
  "label": "Odoo Community",
  "category": "Marketing e CRM",
  "desc": "ERP e CRM modular: vendas, estoque, financeiro, site e muito mais.",
  "kind": "docker",
  "license": "freemium",
  "license_note": "Community é LGPLv3 e grátis; Odoo Enterprise exige assinatura paga.",
  "min_ram_mb": 2048,
  "min_disk_gb": 20,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [],
  "secrets": [
   "db_password"
  ],
  "compose": "services:\n  odoo:\n    image: odoo:19.0-20261112\n    restart: unless-stopped\n    depends_on:\n      - db\n    command: [\"--proxy-mode\"]\n    environment:\n      HOST: db\n      USER: odoo\n      PASSWORD: ${DB_PASSWORD}\n    volumes:\n      - odoo_data:/var/lib/odoo\n      - odoo_addons:/mnt/extra-addons\n    networks:\n      - lctl\n      - db\n  db:\n    image: postgres:17.12\n    restart: unless-stopped\n    environment:\n      POSTGRES_DB: postgres\n      POSTGRES_USER: odoo\n      POSTGRES_PASSWORD: ${DB_PASSWORD}\n    volumes:\n      - pg_data:/var/lib/postgresql/data\n    networks:\n      - db\nvolumes:\n  odoo_data:\n  odoo_addons:\n  pg_data:\nnetworks:\n  lctl:\n    external: true\n  db:\n    internal: true\n",
  "env": {
   "DB_PASSWORD": "{{db_password}}",
   "DOMAIN": "{{domain}}"
  },
  "proxy": {
   "service": "odoo",
   "port": 8069
  },
  "post_install": "Abrir https://{{domain}}, definir a senha mestra (master password) e criar o primeiro banco com e-mail e senha do administrador, idioma Português (BR) e país Brasil.",
  "official_docs": "https://hub.docker.com/_/odoo ; https://www.odoo.com/documentation/19.0/administration/on_premise/deploy.html",
  "risk_notes": "Usada a 19.0; a 20.0 (tag 20.0-20261112) já existe, mas é a mais nova e muitos módulos da comunidade ainda não foram migrados. Até definir a senha mestra, qualquer visitante pode criar ou apagar bancos em /web/database/manager: fazer isso logo. Com workers>0 o websocket vai para a porta 8072 e o proxy teria de rotear /websocket (desnecessário no modo padrão). Localização fiscal brasileira (NF-e) exige módulos de terceiros (OCA l10n-brazil)."
 },
 {
  "id": "nextcloud",
  "label": "Nextcloud",
  "category": "Infraestrutura e monitoramento",
  "desc": "Nuvem privada para arquivos, calendário, contatos e colaboração, hospedada no seu servidor.",
  "kind": "docker",
  "license": "grátis",
  "license_note": "AGPLv3. Suporte Enterprise é pago (opcional).",
  "min_ram_mb": 2048,
  "min_disk_gb": 20,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [
   {
    "name": "admin_user",
    "label": "Usuário administrador",
    "type": "text",
    "pattern": "^[a-zA-Z0-9_.@-]{3,64}$",
    "required": true,
    "default": "admin"
   }
  ],
  "secrets": [
   "db_password",
   "db_root_password",
   "redis_password",
   "admin_password"
  ],
  "compose": "services:\n  app:\n    image: nextcloud:35.0.3-apache\n    restart: unless-stopped\n    depends_on:\n      - db\n      - redis\n    environment:\n      MYSQL_HOST: db\n      MYSQL_DATABASE: nextcloud\n      MYSQL_USER: nextcloud\n      MYSQL_PASSWORD: ${DB_PASSWORD}\n      REDIS_HOST: redis\n      REDIS_HOST_PASSWORD: ${REDIS_PASSWORD}\n      NEXTCLOUD_ADMIN_USER: ${ADMIN_USER}\n      NEXTCLOUD_ADMIN_PASSWORD: ${ADMIN_PASSWORD}\n      NEXTCLOUD_TRUSTED_DOMAINS: ${DOMAIN}\n      TRUSTED_PROXIES: 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16\n      OVERWRITEPROTOCOL: https\n      OVERWRITEHOST: ${DOMAIN}\n      OVERWRITECLIURL: https://${DOMAIN}\n      PHP_MEMORY_LIMIT: 512M\n      PHP_UPLOAD_LIMIT: 10G\n    volumes:\n      - nextcloud_data:/var/www/html\n    networks:\n      - lctl\n      - db\n  cron:\n    image: nextcloud:35.0.3-apache\n    restart: unless-stopped\n    entrypoint: /cron.sh\n    depends_on:\n      - app\n    environment:\n      MYSQL_HOST: db\n      MYSQL_DATABASE: nextcloud\n      MYSQL_USER: nextcloud\n      MYSQL_PASSWORD: ${DB_PASSWORD}\n      REDIS_HOST: redis\n      REDIS_HOST_PASSWORD: ${REDIS_PASSWORD}\n    volumes:\n      - nextcloud_data:/var/www/html\n    networks:\n      - default\n      - db\n  db:\n    image: mariadb:11.4.13\n    restart: unless-stopped\n    command: [\"--transaction-isolation=READ-COMMITTED\", \"--log-bin=binlog\", \"--binlog-format=ROW\"]\n    environment:\n      MARIADB_DATABASE: nextcloud\n      MARIADB_USER: nextcloud\n      MARIADB_PASSWORD: ${DB_PASSWORD}\n      MARIADB_ROOT_PASSWORD: ${DB_ROOT_PASSWORD}\n    volumes:\n      - db_data:/var/lib/mysql\n    networks:\n      - db\n  redis:\n    image: redis:7.4.12-alpine\n    restart: unless-stopped\n    command: [\"sh\", \"-c\", \"redis-server --requirepass \\\"$$REDIS_PASSWORD\\\"\"]\n    environment:\n      REDIS_PASSWORD: ${REDIS_PASSWORD}\n    networks:\n      - db\nvolumes:\n  nextcloud_data:\n  db_data:\nnetworks:\n  default:\n  lctl:\n    external: true\n  db:\n    internal: true\n",
  "env": {
   "DOMAIN": "{{domain}}",
   "DB_PASSWORD": "{{db_password}}",
   "DB_ROOT_PASSWORD": "{{db_root_password}}",
   "REDIS_PASSWORD": "{{redis_password}}",
   "ADMIN_USER": "{{admin_user}}",
   "ADMIN_PASSWORD": "{{admin_password}}"
  },
  "proxy": {
   "service": "app",
   "port": 80
  },
  "post_install": "Aguardar a primeira inicialização (instalação automática, alguns minutos) e entrar em https://{{domain}} com o usuário administrador e a senha gerada (ADMIN_PASSWORD no .env). Conferir Configurações de administração > Visão geral.",
  "official_docs": "https://github.com/nextcloud/docker ; https://docs.nextcloud.com/server/latest/admin_manual/installation/system_requirements.html",
  "risk_notes": "Instalação automática via NEXTCLOUD_ADMIN_* (imagem oficial). TRUSTED_PROXIES cobre as faixas privadas do Docker; restringir à sub-rede da rede lctl se possível. MariaDB 11.4 LTS (suportada pelo Nextcloud desde a 30); suporte à 11.8 na 35: NÃO CONFIRMADO. Os arquivos dos usuários ficam no volume nextcloud_data: dimensionar o disco conforme o uso. O upload de arquivos grandes também depende do limite de corpo do lctl-proxy."
 },
 {
  "id": "ghost",
  "label": "Ghost",
  "category": "Sites e lojas",
  "desc": "Plataforma de publicação para blogs, newsletters e assinaturas pagas.",
  "kind": "docker",
  "license": "grátis",
  "license_note": "MIT. Ghost(Pro) hospedado é pago (não usado aqui).",
  "min_ram_mb": 1024,
  "min_disk_gb": 10,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [],
  "secrets": [
   "db_password",
   "db_root_password"
  ],
  "compose": "services:\n  app:\n    image: ghost:6.78.0\n    restart: unless-stopped\n    depends_on:\n      - db\n    environment:\n      url: https://${DOMAIN}\n      NODE_ENV: production\n      database__client: mysql\n      database__connection__host: db\n      database__connection__user: ghost\n      database__connection__password: ${DB_PASSWORD}\n      database__connection__database: ghost\n    volumes:\n      - ghost_content:/var/lib/ghost/content\n    networks:\n      - lctl\n      - db\n  db:\n    image: mysql:8.4.13\n    restart: unless-stopped\n    environment:\n      MYSQL_DATABASE: ghost\n      MYSQL_USER: ghost\n      MYSQL_PASSWORD: ${DB_PASSWORD}\n      MYSQL_ROOT_PASSWORD: ${DB_ROOT_PASSWORD}\n    volumes:\n      - mysql_data:/var/lib/mysql\n    networks:\n      - db\nvolumes:\n  ghost_content:\n  mysql_data:\nnetworks:\n  lctl:\n    external: true\n  db:\n    internal: true\n",
  "env": {
   "DOMAIN": "{{domain}}",
   "DB_PASSWORD": "{{db_password}}",
   "DB_ROOT_PASSWORD": "{{db_root_password}}"
  },
  "proxy": {
   "service": "app",
   "port": 2368
  },
  "post_install": "Abrir https://{{domain}}/ghost e criar a conta de proprietário. Configurar e-mail transacional (mail__* no .env, ex.: SMTP ou Mailgun) para login por link mágico e newsletters.",
  "official_docs": "https://hub.docker.com/_/ghost ; https://docs.ghost.org/install/docker",
  "risk_notes": "Ghost exige MySQL 8 em produção (SQLite só para desenvolvimento). O Ghost 6 oficial em Docker usa um compose próprio com Caddy e serviços opcionais (ActivityPub/Tinybird); aqui só o núcleo, sem esses extras. Sem e-mail configurado, convites de equipe e newsletters não funcionam. O primeiro acesso a /ghost cria o dono do site."
 },
 {
  "kind": "script",
  "id": "cpanel",
  "label": "cPanel & WHM",
  "category": "Painéis de hospedagem",
  "desc": "Painel de hospedagem comercial mais usado do mercado, com WHM para revendas e contas.",
  "license": "pago",
  "license_note": "Licença paga mensal por servidor; teste grátis de 15 dias (exige conta na cPanel Store com e-mail verificado).",
  "min_ram_mb": 2048,
  "min_disk_gb": 20,
  "os": [
   "ubuntu-24.04",
   "almalinux-8",
   "almalinux-9",
   "almalinux-10"
  ],
  "dedicated_server": true,
  "needs_domain": false,
  "fields": [
   {
    "name": "hostname",
    "label": "Hostname do servidor (FQDN, ex.: srv1.seudominio.com.br)",
    "type": "text",
    "pattern": "^(?=.{1,60}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.){2,}[a-z]{2,}$",
    "required": true
   }
  ],
  "secrets": [],
  "install_cmd": "set -e; hostnamectl set-hostname {{hostname}}; cd /home && curl -o latest -L https://securedownloads.cpanel.net/latest && sh latest",
  "post_install": "Acessar https://IP_DO_SERVIDOR:2087 com root e a senha do root, aceitar os termos, ativar o teste de 15 dias ou a licença e configurar nameservers e IPs.",
  "official_docs": "https://docs.cpanel.net/installation-guide/install/ ; https://docs.cpanel.net/installation-guide/system-requirements-ubuntu/ ; https://docs.cpanel.net/installation-guide/system-requirements-almalinux/",
  "risk_notes": "Só em sistema recém-instalado. Não há desinstalador: para remover é preciso reformatar o servidor. Instalação não interativa, mas demorada (pode passar de 1 hora). Hostname: FQDN registrado, até 60 caracteres, diferente de qualquer domínio hospedado e resolvendo para o IP. Exige IP público estático. Ubuntu só 24.04; Alma 10 requer cPanel 132+. Também suporta Rocky e CloudLinux. Assume portas 80/443 e o firewall: incompatível com o lctl-proxy e as apps Docker do painel. RAM: 2 GB mínimo, 4 GB recomendado; disco 20 GB mínimo, 40 GB recomendado."
 },
 {
  "kind": "script",
  "id": "plesk",
  "label": "Plesk",
  "category": "Painéis de hospedagem",
  "desc": "Painel de hospedagem comercial com WordPress Toolkit, e-mail, DNS e gestão de sites.",
  "license": "pago",
  "license_note": "Licença paga (mensal ou anual); a instalação vem com licença de teste. Duração do teste: NÃO CONFIRMADO na doc consultada.",
  "min_ram_mb": 2048,
  "min_disk_gb": 20,
  "os": [
   "ubuntu-22.04",
   "ubuntu-24.04",
   "debian-12",
   "almalinux-8",
   "almalinux-9"
  ],
  "dedicated_server": true,
  "needs_domain": false,
  "fields": [],
  "secrets": [],
  "install_cmd": "bash -c 'sh <(curl -fsSL https://autoinstall.plesk.com/one-click-installer || wget -O - https://autoinstall.plesk.com/one-click-installer)'",
  "post_install": "Acessar https://IP_DO_SERVIDOR:8443 (ou o link de login exibido no fim da instalação), definir senha do admin, e-mail de contato e aplicar a licença.",
  "official_docs": "https://docs.plesk.com/en-US/obsidian/deployment-guide/76444/ ; https://docs.plesk.com/release-notes/obsidian/software-requirements/",
  "risk_notes": "Exige servidor limpo com acesso à internet. Instalação automática (sem perguntas) com configuração padrão, leva de 30 a 60 minutos. Requisitos oficiais: 1 GB RAM + 1 GB de swap, 20 GB de disco (2 GB indicado aqui). Também suporta Ubuntu 26.04, Debian 13, Alma 10 e Rocky 8. Abre as portas 8443 e 8447 e assume 80/443: incompatível com o lctl-proxy. Remoção completa só reinstalando o sistema."
 },
 {
  "kind": "script",
  "id": "cloudpanel",
  "label": "CloudPanel",
  "category": "Painéis de hospedagem",
  "desc": "Painel gratuito e leve para sites PHP, Node.js, Python e estáticos com Nginx.",
  "license": "grátis",
  "license_note": "Gratuito (Community Edition).",
  "min_ram_mb": 2048,
  "min_disk_gb": 10,
  "os": [
   "ubuntu-22.04",
   "ubuntu-24.04",
   "debian-12"
  ],
  "dedicated_server": true,
  "needs_domain": false,
  "fields": [],
  "secrets": [],
  "install_cmd": "set -e; export DEBIAN_FRONTEND=noninteractive; apt update && apt -y upgrade && apt -y install curl wget sudo; cd /root && curl -sS https://installer.cloudpanel.io/ce/v2/install.sh -o install.sh; echo \"8146dbe0a488e7088b04071b0c34d59aa0ab1fe9dcec382d395fd155c9e6c476 install.sh\" | sha256sum -c && sudo DB_ENGINE=MYSQL_8.4 bash install.sh",
  "post_install": "Acessar https://IP_DO_SERVIDOR:8443 o quanto antes (aceitando o certificado autoassinado) e criar o usuário administrador.",
  "official_docs": "https://www.cloudpanel.io/docs/v2/getting-started/other/ ; https://www.cloudpanel.io/docs/v2/requirements/",
  "risk_notes": "Exige servidor vazio (Ubuntu 22.04/24.04/26.04 ou Debian 12/13). O hash SHA-256 do instalador muda a cada versão: se o sha256sum falhar, atualizar o hash pela doc oficial antes de instalar. Até criar o admin, quem acessar a porta 8443 primeiro assume o painel: a doc recomenda liberar a 8443 só para o seu IP. Ocupa 80/443 com Nginx: incompatível com o lctl-proxy. DB_ENGINE alternativos: MYSQL_8.0, MARIADB_11.8, MARIADB_11.4, MARIADB_10.11 etc."
 },
 {
  "kind": "script",
  "id": "aapanel",
  "label": "aaPanel",
  "category": "Painéis de hospedagem",
  "desc": "Painel gratuito de hospedagem com instalação de LNMP/LAMP, sites, bancos e Docker em poucos cliques.",
  "license": "freemium",
  "license_note": "Versão gratuita; plano Pro pago com recursos extras.",
  "min_ram_mb": 1024,
  "min_disk_gb": 10,
  "os": [
   "ubuntu-22.04",
   "ubuntu-24.04",
   "debian-12",
   "almalinux-8",
   "almalinux-9"
  ],
  "dedicated_server": true,
  "needs_domain": false,
  "fields": [
   {
    "name": "panel_user",
    "label": "Usuário do painel",
    "type": "text",
    "pattern": "^[a-zA-Z0-9_]{5,32}$",
    "required": true,
    "default": "webadmin"
   }
  ],
  "secrets": [
   "admin_password"
  ],
  "install_cmd": "cd /root && URL=https://www.aapanel.com/script/install_panel_en.sh && if [ -f /usr/bin/curl ];then curl -ksSO $URL ;else wget --no-check-certificate -O install_panel_en.sh $URL;fi;bash install_panel_en.sh -y -u {{panel_user}} -p {{admin_password}}",
  "post_install": "O instalador imprime no final a URL de acesso (porta aleatória e caminho de segurança). Consultar a qualquer momento com 'bt default'. Entrar com o usuário e a senha definidos e escolher a pilha (LNMP/LAMP).",
  "official_docs": "https://www.aapanel.com/new/download.html",
  "risk_notes": "Comando oficial da página de download; as flags -y (sem confirmação), -u e -p vêm do próprio script (opção --help), não da página: confirmadas no código em 23/11/2026. O script pode perguntar se deve trocar a fonte do apt ou forçar instalação em ambientes incomuns (ainda interativo nesses casos). Requisitos: mínimo 512 MB/1 núcleo, recomendado 1 GB; disco não informado (10 GB é estimativa). Também suporta Debian 13, Ubuntu 26.04, Alma/Rocky 10. Instala Nginx/Apache nas portas 80/443: incompatível com o lctl-proxy."
 },
 {
  "kind": "script",
  "id": "cyberpanel",
  "label": "CyberPanel",
  "category": "Painéis de hospedagem",
  "desc": "Painel gratuito com OpenLiteSpeed, e-mail, DNS e cache LiteSpeed para WordPress.",
  "license": "freemium",
  "license_note": "Grátis com OpenLiteSpeed; LiteSpeed Enterprise e add-ons são pagos.",
  "min_ram_mb": 1024,
  "min_disk_gb": 10,
  "os": [
   "ubuntu-22.04",
   "ubuntu-24.04",
   "almalinux-8",
   "almalinux-9"
  ],
  "dedicated_server": true,
  "needs_domain": false,
  "fields": [],
  "secrets": [
   "admin_password"
  ],
  "install_cmd": "bash -c 'sh <(curl -fsSL https://cyberpanel.net/install.sh || wget -O - https://cyberpanel.net/install.sh) -v ols -p {{admin_password}} -a'",
  "post_install": "Acessar https://IP_DO_SERVIDOR:8090 com usuário admin e a senha gerada.",
  "official_docs": "https://cyberpanel.net/KnowledgeBase/home/install-cyberpanel/",
  "risk_notes": "A doc mostra só o modo interativo; as flags -v ols (OpenLiteSpeed, silencioso), -p (senha) e -a (Redis/Memcached) vêm do código do instalador oficial (cyberpanel.sh, função Check_Argument): confirmadas no código, não na doc. A senha precisa passar na validação do script (usar só letras e números, 12+ caracteres). Servidor recém-instalado obrigatório. Sem a flag -p a senha padrão seria 1234567. Instala OpenLiteSpeed, Postfix, PowerDNS e Pure-FTPd, ocupando 80/443/53/25: incompatível com o lctl-proxy e não removível de forma limpa."
 },
 {
  "id": "webmin",
  "label": "Webmin",
  "category": "Painéis de hospedagem",
  "desc": "Painel web para administrar o sistema Linux (usuários, serviços, pacotes, firewall).",
  "kind": "native",
  "license": "grátis",
  "license_note": "Software livre (BSD).",
  "min_ram_mb": 512,
  "min_disk_gb": 1,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": false,
  "fields": [],
  "secrets": [],
  "install_cmd": "set -e; cd /root && curl -o webmin-setup-repo.sh https://raw.githubusercontent.com/webmin/webmin/master/webmin-setup-repo.sh && sh webmin-setup-repo.sh --force && if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y webmin --install-recommends; else dnf install -y webmin; fi",
  "post_install": "Acessar https://IP_DO_SERVIDOR:10000 com o usuário root (ou outro usuário com sudo) e a senha do sistema.",
  "official_docs": "https://webmin.com/download/",
  "risk_notes": "Convive com o painel (não usa 80/443), mas expõe a porta 10000 com login por senha do root: liberar no firewall só para IPs confiáveis. Usa certificado autoassinado. O Webmin pode alterar configurações que o agente do painel também gerencia (firewall, serviços). A flag --force do script de repositório pula a confirmação (documentada no --help do script). Requisitos mínimos não informados na doc: valores estimados."
 },
 {
  "kind": "script",
  "id": "coolify",
  "label": "Coolify",
  "category": "Painéis de hospedagem",
  "desc": "PaaS self-hosted (alternativa ao Heroku/Vercel) para publicar apps, bancos e serviços com Docker.",
  "license": "grátis",
  "license_note": "Apache 2.0 self-hosted grátis; Coolify Cloud é pago.",
  "min_ram_mb": 2048,
  "min_disk_gb": 30,
  "os": "any",
  "dedicated_server": true,
  "needs_domain": false,
  "fields": [],
  "secrets": [],
  "install_cmd": "curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash",
  "post_install": "Acessar http://IP_DO_SERVIDOR:8000 IMEDIATAMENTE e criar a conta de administrador (a janela de cadastro fecha em 10 minutos; se fechar, 'docker restart coolify'). Fazer backup de /data/coolify/source/.env.",
  "official_docs": "https://coolify.io/docs/get-started/installation",
  "risk_notes": "A doc recomenda servidor novo. O Coolify sobe o próprio proxy (Traefik) nas portas 80/443, conflitando com o lctl-proxy, e gerencia o Docker do host. Quem acessar a porta 8000 primeiro vira admin com acesso root ao servidor. Requisitos: 2 núcleos, 2 GB RAM, 10 GB livres + espaço para imagens/volumes/backups (30 GB indicado). Docker instalado via snap deve ser removido antes; em algumas distros RHEL o Docker precisa ser instalado manualmente."
 },
 {
  "id": "portainer",
  "label": "Portainer CE",
  "category": "Infraestrutura e monitoramento",
  "desc": "Interface web para gerenciar containers, imagens, volumes e stacks Docker.",
  "kind": "docker",
  "license": "freemium",
  "license_note": "Community Edition grátis (zlib); Business Edition paga (grátis até 3 nós).",
  "min_ram_mb": 512,
  "min_disk_gb": 2,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [],
  "secrets": [],
  "compose": "services:\n  portainer:\n    image: portainer/portainer-ce:2.39.9\n    restart: unless-stopped\n    command: [\"-H\", \"unix:///var/run/docker.sock\"]\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n      - portainer_data:/data\n    networks:\n      - lctl\nvolumes:\n  portainer_data:\nnetworks:\n  lctl:\n    external: true\n",
  "env": {
   "DOMAIN": "{{domain}}"
  },
  "proxy": {
   "service": "portainer",
   "port": 9000
  },
  "post_install": "Abrir https://{{domain}} em até 5 minutos e criar o usuário admin (senha de 12+ caracteres). Se passar do prazo, reiniciar o container.",
  "official_docs": "https://docs.portainer.io/start/install-ce/server/docker/linux",
  "risk_notes": "Montar /var/run/docker.sock dá controle total do Docker e, na prática, root no host: proteger com senha forte e, se possível, restringir o acesso por IP. 2.39.9 = versão LTS; 2.45.x é STS (curto prazo). Por segurança, o Portainer desativa o cadastro inicial após 5 minutos sem configuração. Pode parar/apagar containers do próprio painel Linux Control."
 },
 {
  "id": "uptime-kuma",
  "label": "Uptime Kuma",
  "category": "Infraestrutura e monitoramento",
  "desc": "Monitor de disponibilidade de sites, APIs e portas com alertas e página de status.",
  "kind": "docker",
  "license": "grátis",
  "license_note": "MIT.",
  "min_ram_mb": 512,
  "min_disk_gb": 2,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [],
  "secrets": [],
  "compose": "services:\n  uptime-kuma:\n    image: louislam/uptime-kuma:2.5.12\n    restart: unless-stopped\n    volumes:\n      - kuma_data:/app/data\n    networks:\n      - lctl\nvolumes:\n  kuma_data:\nnetworks:\n  lctl:\n    external: true\n",
  "env": {
   "DOMAIN": "{{domain}}"
  },
  "proxy": {
   "service": "uptime-kuma",
   "port": 3001
  },
  "post_install": "Abrir https://{{domain}}, escolher o banco (SQLite embutido) e criar o usuário administrador. Cadastrar monitores e notificações (e-mail, Telegram etc.).",
  "official_docs": "https://github.com/louislam/uptime-kuma/wiki/%F0%9F%94%A7-How-to-Install",
  "risk_notes": "O primeiro visitante cria o admin. Usa WebSocket (o Caddy repassa por padrão). Não usar volume em NFS (SQLite). 2.5.12 = estável da série 2; a 3.0 está em beta."
 },
 {
  "id": "grafana",
  "label": "Grafana",
  "category": "Infraestrutura e monitoramento",
  "desc": "Painéis e alertas para métricas, logs e dados de bancos (Prometheus, MySQL, Postgres e outros).",
  "kind": "docker",
  "license": "freemium",
  "license_note": "Grafana OSS é AGPLv3 e grátis; Grafana Enterprise/Cloud são pagos.",
  "min_ram_mb": 512,
  "min_disk_gb": 2,
  "os": "any",
  "dedicated_server": false,
  "needs_domain": true,
  "fields": [],
  "secrets": [
   "admin_password"
  ],
  "compose": "services:\n  grafana:\n    image: grafana/grafana:13.3.1\n    restart: unless-stopped\n    environment:\n      GF_SERVER_ROOT_URL: https://${DOMAIN}/\n      GF_SERVER_DOMAIN: ${DOMAIN}\n      GF_SECURITY_ADMIN_USER: admin\n      GF_SECURITY_ADMIN_PASSWORD: ${ADMIN_PASSWORD}\n      GF_USERS_ALLOW_SIGN_UP: \"false\"\n    volumes:\n      - grafana_data:/var/lib/grafana\n    networks:\n      - lctl\nvolumes:\n  grafana_data:\nnetworks:\n  lctl:\n    external: true\n",
  "env": {
   "DOMAIN": "{{domain}}",
   "ADMIN_PASSWORD": "{{admin_password}}"
  },
  "proxy": {
   "service": "grafana",
   "port": 3000
  },
  "post_install": "Entrar em https://{{domain}} com usuário admin e a senha gerada (ADMIN_PASSWORD no .env). Adicionar as fontes de dados (Prometheus, MySQL etc.).",
  "official_docs": "https://grafana.com/docs/grafana/latest/setup-grafana/installation/docker/",
  "risk_notes": "GF_SECURITY_ADMIN_PASSWORD só vale na primeira inicialização (depois a senha fica no banco interno). Requisitos oficiais mínimos: 512 MB e 1 núcleo. 13.3.1 = versão estável mais recente na data."
 }
]''')
APP_BY_ID.update({r["id"]: r for r in APP_RECIPES})


NTP_SH = ("if ! systemctl list-unit-files 2>/dev/null | grep -qE '^(systemd-timesyncd|chronyd?|ntpd?)\\.service'; then "
          "echo 'Nenhum serviço de hora encontrado; instalando o chrony.'; "
          "if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq chrony; else dnf -y -q install chrony || yum -y -q install chrony; fi; "
          "systemctl enable --now chrony 2>/dev/null || systemctl enable --now chronyd; fi; "
          "timedatectl set-ntp true 2>&1 || true; sleep 3; "
          "if ! timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes; then "
          "systemctl restart systemd-timesyncd 2>/dev/null || systemctl restart chronyd 2>/dev/null || systemctl restart chrony 2>/dev/null; sleep 10; fi; "
          "timedatectl; timedatectl show -p NTPSynchronized --value | grep -q yes "
          "|| { echo; echo 'Ainda não sincronizou: confira se a porta 123/udp de saída está liberada.'; exit 1; }")


PKG_SH = {
    "updates": "if command -v apt-get >/dev/null; then apt-get update -qq && apt list --upgradable 2>/dev/null; "
               "elif command -v dnf >/dev/null; then dnf -q check-update; dnf -q updateinfo list security; "
               "elif command -v yum >/dev/null; then yum -q check-update; elif command -v apk >/dev/null; then apk update && apk version -l '<'; fi; true",
    "security": "if command -v unattended-upgrade >/dev/null; then apt-get update -qq && unattended-upgrade -v; "
                "elif command -v apt-get >/dev/null; then apt-get update -qq && apt list --upgradable 2>/dev/null | grep -- -security | cut -d/ -f1 | xargs -r env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade; "
                "elif command -v dnf >/dev/null; then dnf -y upgrade --security; elif command -v yum >/dev/null; then yum -y update --security; fi; "
                "[ -f /var/run/reboot-required ] && echo '>> REINÍCIO NECESSÁRIO' || true",
    "all": "if command -v apt-get >/dev/null; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get -y --with-new-pkgs -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade; apt list --upgradable 2>/dev/null | grep -q upgradable && { echo; echo 'Ainda pendente (exige remover pacotes; faça manualmente):'; apt list --upgradable 2>/dev/null | tail -n +2; }; "
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
    {"id": "health.overview", "fixes": ["cpu_high", "load_high"], "group": "Saúde", "label": "Diagnóstico rápido", "level": "read",
     "desc": "Uptime, memória, discos e processos que mais consomem.",
     "sh": "uptime; echo; free -h; echo; df -hT -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null; echo; "
           "ps -eo pid,user,%cpu,%mem,etime,comm --sort=-%cpu | head -20"},
    {"id": "health.failed_services", "fixes": ["services_failed"], "group": "Saúde", "label": "Serviços com falha", "level": "read",
     "desc": "Lista serviços systemd em estado de falha.", "sh": "systemctl --failed --no-pager"},
    {"id": "health.journal_errors", "group": "Saúde", "label": "Erros do sistema (24h)", "level": "read",
     "desc": "Últimos 200 erros registrados no journal nas últimas 24 horas.",
     "sh": "journalctl -p err --since=-24h --no-pager -n 200"},
    {"id": "health.disk_hogs", "fixes": ["disk_full", "inode_full"], "group": "Saúde", "label": "O que ocupa o disco", "level": "read", "timeout": 300,
     "desc": "Maiores pastas na raiz e em /var, e arquivos acima de 500 MB.",
     "sh": "echo '== Maiores pastas em / =='; du -xh --max-depth=1 / 2>/dev/null | sort -rh | head -15; "
           "echo; echo '== Maiores pastas em /var =='; du -xh --max-depth=2 /var 2>/dev/null | sort -rh | head -15; "
           "echo; echo '== Arquivos > 500 MB =='; find / -xdev -type f -size +500M -exec ls -lh {} + 2>/dev/null | awk '{print $5, $9}' | sort -rh | head -20"},
    {"id": "health.memory_detail", "fixes": ["mem_high", "swap_high"], "group": "Saúde", "label": "Detalhe de memória", "level": "read",
     "desc": "Uso de memória por processo (RSS) e swap.",
     "sh": "free -m; echo; ps -eo pid,user,rss,%mem,comm --sort=-rss | head -25 | awk 'NR==1{print;next}{printf \"%s %s %.0fMB %s %s\\n\",$1,$2,$3/1024,$4,$5}'"},
    {"id": "health.connections", "group": "Saúde", "label": "Conexões de rede ativas", "level": "read",
     "desc": "Resumo de conexões TCP e principais IPs remotos.",
     "sh": "ss -s; echo; echo '== Top IPs remotos =='; ss -tnH state established | awk '{print $4}' | sed 's/:[0-9]*$//' | sort | uniq -c | sort -rn | head -20"},
    {"id": "cleanup.packages", "fixes": ["disk_full"], "group": "Limpeza", "label": "Limpar cache de pacotes", "level": "change", "timeout": 600,
     "desc": "Remove pacotes órfãos e limpa o cache do gerenciador de pacotes.", "sh": PKG_SH["clean"]},
    {"id": "cleanup.journal", "fixes": ["disk_full"], "group": "Limpeza", "label": "Reduzir logs do journal", "level": "change",
     "desc": "Mantém só os últimos 7 dias (máx. 500 MB) de logs do systemd.",
     "sh": "journalctl --disk-usage; journalctl --vacuum-time=7d --vacuum-size=500M; journalctl --disk-usage"},
    {"id": "cleanup.tmp", "fixes": ["disk_full", "inode_full"], "group": "Limpeza", "label": "Limpar /tmp antigo", "level": "change",
     "desc": "Apaga arquivos em /tmp e /var/tmp sem acesso há mais de 7 dias.",
     "sh": "find /tmp /var/tmp -xdev -type f -atime +7 -print -delete 2>/dev/null | tail -50; echo concluído"},
    {"id": "cleanup.old_logs", "fixes": ["disk_full"], "group": "Limpeza", "label": "Apagar logs rotacionados", "level": "change",
     "desc": "Remove logs compactados antigos (*.gz, *.1) em /var/log.",
     "sh": "du -sh /var/log; find /var/log -type f \\( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \\) -mtime +7 -print -delete | tail -50; du -sh /var/log"},
    {"id": "cleanup.docker", "fixes": ["disk_full"], "group": "Limpeza", "label": "Limpar Docker", "level": "change", "timeout": 900,
     "desc": "Remove containers parados, imagens sem uso e cache de build (volumes são preservados).",
     "sh": "docker system df; docker system prune -af; docker builder prune -af; echo; docker system df"},
    {"id": "security.updates", "group": "Segurança", "label": "Ver atualizações pendentes", "level": "read", "timeout": 300,
     "desc": "Atualiza o índice de pacotes e lista o que pode ser atualizado.", "sh": PKG_SH["updates"]},
    {"id": "security.apply_security", "fixes": ["updates_security"], "group": "Segurança", "label": "Aplicar atualizações de segurança", "level": "change", "timeout": 1800,
     "desc": "Instala somente as atualizações de segurança.", "sh": PKG_SH["security"]},
    {"id": "security.apply_all", "fixes": ["updates_available", "updates_security"], "group": "Segurança", "label": "Aplicar todas as atualizações", "level": "danger", "confirm": True, "timeout": 3600,
     "desc": "Atualiza todos os pacotes do sistema. Pode reiniciar serviços.", "sh": PKG_SH["all"]},
    {"id": "security.failed_logins", "fixes": ["ssh_bruteforce"], "group": "Segurança", "label": "Tentativas de invasão SSH", "level": "read",
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
    {"id": "fix.ssh_root_password", "group": "Segurança", "label": "Bloquear senha do root no SSH", "level": "danger", "confirm": True,
     "fixes": ["ssh_root_password"], "run": run_ssh_root_password, "done_label": "o root já não entra com senha",
     "done": lambda: sshd_effective().get("permitrootlogin") in ("no", "prohibit-password", "without-password", "forced-commands-only"),
     "desc": "Root passa a entrar só por chave SSH (PermitRootLogin prohibit-password). Antes de confirmar, garanta que você tem a chave privada do root ou a senha de outro administrador."},
    {"id": "fix.ssh_password_off", "group": "Segurança", "label": "Desligar login por senha no SSH", "level": "danger", "confirm": True,
     "fixes": ["ssh_password_auth"], "run": run_ssh_password_off, "done_label": "o SSH já não aceita senha",
     "done": lambda: sshd_effective().get("passwordauthentication") == "no",
     "desc": "Todos passam a entrar só por chave SSH. Antes de confirmar, garanta que você tem a chave privada de um administrador: quem só usa senha perde o acesso."},
    {"id": "fix.fail2ban", "group": "Segurança", "label": "Bloquear ataques ao SSH (Fail2ban)", "level": "change", "timeout": 900,
     "fixes": ["ssh_bruteforce"], "run": run_fail2ban, "done_label": "Fail2ban protegendo o SSH",
     "done": lambda: which("fail2ban-client") is not None and fail2ban_sshd() is not None,
     "desc": "Instala e liga o Fail2ban: IP que errar a senha 5 vezes em 10 minutos fica bloqueado por 1 hora."},
    {"id": "fix.firewall", "group": "Segurança", "label": "Ativar firewall", "level": "danger", "confirm": True, "timeout": 900,
     "fixes": ["firewall_off"], "run": run_enable_firewall, "done_label": "firewall já ativo",
     "done": lambda: firewall_status()["active"],
     "desc": "Liga o UFW (ou firewalld) mantendo abertas o SSH e todas as portas que já recebem conexões hoje. Com Docker, o serviço é reiniciado."},
    {"id": "fix.auto_updates", "group": "Segurança", "label": "Ligar atualizações automáticas", "level": "change", "timeout": 900,
     "fixes": ["auto_updates_off"], "run": run_install_app("autoupdates"), "done_label": "atualizações automáticas já ligadas",
     "done": lambda: auto_updates_enabled() is True,
     "desc": "Instala e liga a instalação automática das atualizações de segurança."},
    {"id": "fix.restart_failed", "group": "Serviços", "label": "Reiniciar serviços com falha", "level": "change", "timeout": 600,
     "fixes": ["services_failed"], "run": run_restart_failed,
     "desc": "Tenta reiniciar cada serviço em falha e mostra quais voltaram."},
    {"id": "fix.ntp", "group": "Sistema", "label": "Sincronizar relógio", "level": "change", "timeout": 120,
     "fixes": ["ntp_off"], "sh": NTP_SH, "done_label": "relógio já sincronizado",
     "done": lambda: run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], timeout=10, merge=False)[1].strip() == "yes",
     "desc": "Liga a sincronização automática de hora (NTP)."},
    {"id": "fix.renew_certs", "group": "Segurança", "label": "Renovar certificados (Certbot)", "level": "change", "timeout": 900,
     "fixes": ["cert_expiring"],
     "desc": "Renova os certificados Let's Encrypt que estão perto de vencer e recarrega o servidor web.",
     "sh": "PATH=$PATH:/snap/bin; if ! command -v certbot >/dev/null; then echo 'Certbot não instalado: este certificado é renovado por outra ferramenta.'; exit 1; fi; "
           "certbot renew --no-random-sleep-on-renew 2>&1; rc=$?; "
           "systemctl reload nginx 2>/dev/null || systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null || true; exit $rc"},
    {"id": "disk.report", "group": "Discos", "label": "Relatório de saúde dos discos", "level": "read", "timeout": 300, "placement": "disks",
     "fixes": ["disk_smart", "disk_sectors", "disk_wear", "disk_io_errors"], "run": run_disk_report,
     "desc": "SMART completo de cada disco e os erros de leitura e gravação registrados pelo kernel."},
    {"id": "disk.short_test", "group": "Discos", "label": "Teste rápido do disco (2 min)", "level": "change", "placement": "disks",
     "fixes": ["disk_sectors"], "run": run_disk_test("short"),
     "desc": "Pede ao próprio disco um autoteste rápido. O servidor continua funcionando."},
    {"id": "disk.long_test", "group": "Discos", "label": "Teste completo de setores", "level": "change", "placement": "disks",
     "fixes": ["disk_sectors", "disk_smart"], "run": run_disk_test("long"),
     "desc": "Lê toda a superfície do disco procurando setores defeituosos. Pode levar horas; o servidor continua funcionando."},
    {"id": "fix.smartmontools", "group": "Discos", "label": "Instalar monitor de disco (smartmontools)", "level": "change", "timeout": 900,
     "placement": "disks", "fixes": ["smart_missing"], "run": run_smartmontools, "available": lambda: not which("smartctl"),
     "desc": "Instala o smartmontools para o painel ler a saúde física dos discos (setores, desgaste, temperatura)."},
    {"id": "ssh.authorize_key", "group": "Usuários", "label": "Autorizar chave SSH", "level": "admin", "placement": "users", "run": run_authorize_key,
     "desc": "Libera o acesso por chave SSH para o root ou para um usuário.",
     "fields": [f_text("user", "Usuário", USER_RE, placeholder="root", suggest="users"),
                dict(f_text("ssh_key", "Chave SSH pública", SSH_KEY_RE, placeholder="ssh-ed25519 AAAA… usuario@maquina", suggest="ssh_keys"), type="textarea")]},
    {"id": "stacks.install", "group": "Aplicativos", "label": "Instalar aplicativo", "level": "admin", "placement": "apps", "timeout": 3600,
     "run": run_stack_install, "desc": "Instala um aplicativo do catálogo (Docker com HTTPS automático, ou instalação nativa).",
     "fields": [f_select("app", "Aplicativo", [r["id"] for r in APP_RECIPES] or ["-"]),
                f_text("domain", "Domínio", DOMAIN_RE, required=False, placeholder="app.suaempresa.com.br",
                       help="Aponte o DNS para este servidor. Vazio: o app fica numa porta própria, sem HTTPS."),
                f_text("email", "E-mail para o certificado HTTPS", EMAIL_RE, required=False),
                dict(f_text("options", "Opções", r"^\{[^\r\n]{0,4000}\}$", required=False), type="textarea")]},
    {"id": "stack.logs", "group": "Aplicativos", "label": "Logs", "level": "read", "target": "stack", "fields": [f_text("name", "App", STACK_NAME_RE)],
     "run": run_stack("logs"), "desc": "Últimas 300 linhas de log do aplicativo.", "when": "docker"},
    {"id": "stack.restart", "group": "Aplicativos", "label": "Reiniciar", "level": "change", "target": "stack", "fields": [f_text("name", "App", STACK_NAME_RE)],
     "run": run_stack("restart"), "desc": "Reinicia os containers do aplicativo.", "when": "running"},
    {"id": "stack.stop", "group": "Aplicativos", "label": "Parar", "level": "danger", "confirm": True, "target": "stack",
     "fields": [f_text("name", "App", STACK_NAME_RE)], "run": run_stack("stop"), "desc": "Para o aplicativo (os dados ficam).", "when": "running"},
    {"id": "stack.start", "group": "Aplicativos", "label": "Iniciar", "level": "change", "target": "stack", "fields": [f_text("name", "App", STACK_NAME_RE)],
     "run": run_stack("start"), "desc": "Liga o aplicativo de novo.", "when": "stopped"},
    {"id": "stack.remove", "group": "Aplicativos", "label": "Remover", "level": "admin", "confirm": True, "target": "stack",
     "fields": [f_text("name", "App", STACK_NAME_RE), f_bool("remove_data", "Apagar também os dados (banco, uploads). Sem volta.")],
     "run": run_stack("remove"), "desc": "Remove o aplicativo. Sem marcar a opção, os dados ficam guardados.", "when": "docker"},
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
                dict(f_text("ssh_key", "Chave SSH pública", SSH_KEY_RE, required=False, placeholder="ssh-ed25519 AAAA… usuario@maquina", suggest="ssh_keys"), type="textarea")]},
    {"id": "users.add_key", "group": "Usuários", "label": "Adicionar chave SSH", "level": "admin", "target": "user", "run": run_user_add_key,
     "desc": "Autoriza mais uma chave SSH para o usuário.",
     "fields": F_USER() + [dict(f_text("ssh_key", "Chave SSH pública", SSH_KEY_RE, suggest="ssh_keys"), type="textarea")]},
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
    {"id": "system.reboot", "fixes": ["reboot_required"], "group": "Sistema", "label": "Reiniciar servidor", "level": "danger", "confirm": True,
     "desc": "Reinicia o servidor em 1 minuto.",
     "sh": "shutdown -r +1 'Reinício solicitado pelo Linux Control' && echo 'Reinício agendado para daqui a 1 minuto.'"},
]

# Cada linha de tabela (serviço, container, usuário, programa, agendamento) traz "key" e "state" no inventário.
# Uma ação com "target" aparece na linha quando todos os estados de "when" estão presentes, e o campo
# "target_field" do formulário recebe a "key" da linha. Contas de sistema nunca recebem ações.
TARGET_FIELD = {"service": "name", "container": "name", "user": "name", "app": "app", "cron": "id", "stack": "name"}
for _a in ACTIONS:
    if "target" in _a:
        _a["target_field"] = TARGET_FIELD[_a["target"]]
        _a["when"] = ([_a["when"]] if isinstance(_a.get("when"), str) else list(_a.get("when", [])))
        if _a["target"] == "user":
            _a["when"].insert(0, "person")
        if _a["target"] == "cron":
            _a["when"].insert(0, "managed")
ACTIONS_BY_ID = {a["id"]: a for a in ACTIONS}
PUBLIC_KEYS = ("id", "group", "label", "desc", "level", "confirm", "target", "target_field", "placement", "fields", "timeout", "when", "fixes")


def allowed_actions(mode):
    levels = LEVELS_BY_MODE.get(mode, ())
    return [a for a in ACTIONS if a["level"] in levels]


def action_state(a):
    """Ações de estado (ligar Fail2ban, firewall…) informam se já estão aplicadas; as repetíveis (limpeza,
    atualizações, leituras) não têm "done" e sempre podem rodar de novo."""
    if "done" not in a:
        return {}
    try:
        done = bool(a["done"]())
    except Exception:
        done = False
    return {"done": done, "done_label": a.get("done_label", "já aplicado")}


def action_catalog(mode):
    """Catálogo publicado: ações com "available" só aparecem quando fazem sentido (ex.: instalar o que falta)."""
    return [dict({k: a[k] for k in PUBLIC_KEYS if k in a}, **action_state(a))
            for a in allowed_actions(mode) if a.get("available", lambda: True)()]


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
        "cloud": safe(cloud_info),
        "disk_health": safe(disk_health),
        "services": safe(services, {"available": False, "units": []}),
        "ports": safe(ports, []),
        "docker": safe(docker),
        "software": safe(software, []),
        "apps": safe(apps_status, []),
        "stacks": safe(stacks_status, []),
        "app_catalog": app_catalog(),
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


def api(conf, method, path, payload=None, timeout=40):
    """Chamada ao hub com o token do agente (canal rápido e terminal)."""
    url = conf["HUB_URL"].rstrip("/") + path
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
    req = urlrequest.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + conf["TOKEN"],
        "User-Agent": "linux-control-agent/" + VERSION})
    with urlrequest.urlopen(req, timeout=timeout, context=tls_context(conf, url)) as r:
        return json.loads(r.read().decode("utf-8") or "{}")


def wake_listener(conf, wake):
    """Canal rápido: mantém um GET aberto no hub; quando chega ação ou terminal, acorda o ciclo principal."""
    while True:
        try:
            if api(conf, "GET", "/api/agent/wait", timeout=40).get("wake"):
                wake.set()
        except Exception:
            time.sleep(10)  # hub antigo (sem a rota) ou fora do ar: o ciclo normal continua funcionando


# ---------------------------------------------------------------- terminal
#
# Só no modo admin. Um bash de login como root num pseudo-terminal; a entrada chega por long-poll e a
# saída vai em lotes pequenos (a cada ~30 ms). O hub grava a sessão e fecha por inatividade.

TERMINALS = set()
TERMINAL_MAX = 3


HUB_LOST_SECONDS = 90  # sem falar com o hub por esse tempo, o shell é encerrado (nada de root órfão)


def run_terminal(conf, sid):
    master = slave = proc = None
    alive = {"on": True, "last_ok": time.time()}
    reader = None
    try:
        master, slave = pty.openpty()
        me = pwd.getpwuid(os.getuid())  # root quando instalado; o usuário atual nos testes
        env = {"TERM": "xterm-256color", "HOME": me.pw_dir, "USER": me.pw_name, "LOGNAME": me.pw_name, "SHELL": "/bin/bash",
               "LANG": os.environ.get("LANG", "C.UTF-8"), "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
               "LCTL_TERMINAL": sid[:8]}
        shell = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"

        def child_setup():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)  # o pseudo-terminal vira o terminal de controle (Ctrl+C funciona)

        proc = subprocess.Popen([shell, "-l"], stdin=slave, stdout=slave, stderr=slave,
                                cwd=me.pw_dir if os.access(me.pw_dir, os.X_OK) else "/", env=env, preexec_fn=child_setup, close_fds=True)
        os.close(slave)
        slave = None

        def resize(r):
            try:
                fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", int(r["rows"]), int(r["cols"]), 0, 0))
            except (OSError, KeyError, ValueError, TypeError):
                pass

        def pump_input():
            while alive["on"]:
                try:
                    msg = api(conf, "GET", "/api/agent/terminal/%s/in" % sid, timeout=40)
                    alive["last_ok"] = time.time()
                except urlerror.HTTPError as e:
                    if e.code in (401, 404, 410):
                        break  # sessão encerrada no hub ou token revogado
                    time.sleep(2)
                    continue
                except Exception:
                    time.sleep(2)
                    continue
                if not alive["on"]:
                    break
                if msg.get("resize"):
                    resize(msg["resize"])
                for chunk in msg.get("data") or []:
                    try:
                        os.write(master, base64.b64decode(chunk))
                    except OSError:
                        break
                if msg.get("close"):
                    break
            alive["on"] = False

        reader = threading.Thread(target=pump_input, daemon=True)
        reader.start()
        pending = b""
        while alive["on"]:
            if time.time() - alive["last_ok"] > HUB_LOST_SECONDS:
                log("terminal %s: sem contato com o hub; encerrando o shell" % sid[:8])
                break
            r, _, _ = select.select([master], [], [], 1.0)
            if r:
                try:
                    buf = os.read(master, 65536)
                except OSError:
                    buf = b""
                if not buf:
                    break  # o shell terminou
                time.sleep(0.03)  # junta a saída em lotes para não fazer um POST por caractere
                while select.select([master], [], [], 0)[0] and len(buf) < 262144:
                    try:
                        more = os.read(master, 65536)
                    except OSError:
                        break
                    if not more:
                        break
                    buf += more
                pending = (pending + buf)[-1048576:]  # se o envio falhar, guarda até 1 MB para a próxima tentativa
            elif proc.poll() is not None:
                break
            if pending:
                try:
                    resp = api(conf, "POST", "/api/agent/terminal/%s/out" % sid, {"data": [base64.b64encode(pending).decode("ascii")]})
                    alive["last_ok"] = time.time()
                    pending = b""
                    if resp.get("close"):
                        break
                except urlerror.HTTPError as e:
                    if e.code in (401, 404, 410):
                        break
                    time.sleep(1)
                except Exception as e:
                    log("terminal %s: falha ao enviar saída (%s)" % (sid[:8], e))
                    time.sleep(1)
    finally:
        alive["on"] = False
        code = -1
        if proc is not None:
            # O shell é líder do próprio grupo (setsid): o grupo inteiro sai junto, inclusive o que ficou em segundo plano.
            for sig, wait in ((signal.SIGHUP, 3), (signal.SIGKILL, 5)):
                try:
                    os.killpg(proc.pid, sig)
                except OSError:
                    pass
                try:
                    code = proc.wait(timeout=wait)
                    break
                except subprocess.TimeoutExpired:
                    continue
            code = proc.returncode if proc.returncode is not None else code
        if reader is not None:
            reader.join(45)  # só fecha o pseudo-terminal depois que a leitura parou de escrever nele
        for fd in (slave, master):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        try:
            api(conf, "POST", "/api/agent/terminal/%s/out" % sid, {"data": [], "exit": code}, timeout=10)
        except Exception:
            pass
        TERMINALS.discard(sid)
        log("terminal %s encerrado" % sid[:8])


def open_terminals(conf, mode, sessions):
    for t in sessions or []:
        sid = str(t.get("id", ""))
        if not re.fullmatch(r"[a-f0-9]{32}", sid) or sid in TERMINALS:
            continue
        if mode != "admin":
            log("terminal recusado: o agente não está no modo admin")
            continue
        if len(TERMINALS) >= TERMINAL_MAX:
            continue
        TERMINALS.add(sid)
        log("abrindo terminal %s" % sid[:8])
        threading.Thread(target=run_terminal, args=(conf, sid), daemon=True).start()


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
    # Mesmo User-Agent do relatório: proxies como a Cloudflare bloqueiam o padrão do Python.
    req = urlrequest.Request(url, headers={"User-Agent": "linux-control-agent/" + VERSION})
    with urlrequest.urlopen(req, timeout=60, context=tls_context(conf, url)) as r:
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


def run_command(cmd, mode, state):
    """Executa uma ação da fila e devolve o resultado para o hub."""
    started = time.time()
    log("executando ação %s (%s)" % (cmd.get("action"), cmd.get("id")))
    state["busy"] = True
    try:
        rc, out = execute_action(cmd, mode, state)
    except Exception as e:
        rc, out = 1, "Erro interno do agente: %s" % e
    state["busy"] = False
    if (ACTIONS_BY_ID.get(cmd.get("action")) or {}).get("level", "read") != "read":
        state["force_inventory"] = True  # só depois de terminar: o diagnóstico reflete a mudança no ciclo seguinte
    if len(out) > MAX_OUTPUT:
        out = "[saída truncada, mostrando o final]\n" + out[-MAX_OUTPUT:]
    return {"id": cmd.get("id"), "exit_code": rc, "output": out, "duration": round(time.time() - started, 1)}


WAKE = threading.Event()  # acorda o ciclo principal: resultado pronto ou aviso do hub


def worker(q, results, lock, mode, state):
    while True:
        res = run_command(q.get(), mode, state)
        with lock:
            results.append(res)
        WAKE.set()  # entrega o resultado já, sem esperar o próximo ciclo


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
    wake = WAKE
    threading.Thread(target=wake_listener, args=(conf, wake), daemon=True).start()

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
            open_terminals(conf, mode, resp.get("terminals"))
            idle = q.empty() and not state.get("busy") and not results and not TERMINALS  # não reinicia com terminal aberto
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
        # Espera o próximo ciclo, ou acorda antes se o hub avisar (ação na fila, terminal para abrir).
        wake.wait(max(1, interval - (time.time() - cycle)))
        wake.clear()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
