#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sabbat-netinspect — Inspector de Red y Conexiones (presente dinámico)

MVP portable sobre psutil con:
- Conexiones activas (TCP/UDP, IPv4/IPv6), correlación PID↔Proceso y unidad systemd (Linux)
- Filtros por proto/estado/puertos/IP/CIDR/proceso/usuario/PID/públicas/sospechosas
- GeoIP opcional (MaxMind, si geoip2 está instalado) con caché por IP
- Threat Intel local desde CSV (IPs exactas y rangos CIDR, sin llamadas online)
- Whitelist de puertos (puertos individuales, rangos y comodines)
- Reverse DNS opt-in concurrente y cacheado
- Heurísticas de seguridad (puertos sensibles expuestos, C2/miners, procesos en /tmp o /dev/shm)
- Snapshot/diff detallado
- Salidas: human, --raw (TSV), --json, --jsonl

Filosofía:
- Solo lectura. Timeouts sensatos. No envía datos a Internet por defecto.
- Privacidad por defecto: --sanitize activa (no imprime cmdline completo) salvo --unsafe-proc-cmdline.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime as _dt
import getpass
import ipaddress
import json
import os
import platform
import re
import socket
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Dependencias suaves
try:
    import psutil  # type: ignore
except Exception:
    print("ERROR: sabbat-netinspect requiere 'psutil'. Instala con: pip install psutil", file=sys.stderr)
    raise

try:
    import geoip2.database  # type: ignore
except Exception:
    geoip2 = None  # lazily checked


SCHEMA_VERSION = "1.1"

# Puertos sensibles si están expuestos en 0.0.0.0 / ::
SENSITIVE_EXPOSED_PORTS = {
    21: "ftp",
    23: "telnet",
    445: "smb",
    1433: "mssql",
    2375: "docker-api",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

# Puertos asociados frecuentemente a C2, IRC botnets, cryptominers (Stratum) o shells inversas
C2_LIKE_PORTS = {
    1337, 3333, 4444, 5555, 6667, 6668, 6697, 9001, 9050, 14444, 33445, 45700
}

SUSPICIOUS_PROC_DIRS = (
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "\\appdata\\local\\temp\\"
)


def _ensure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                enc = getattr(stream, "encoding", None) or ""
                if enc.lower().replace("-", "") != "utf8":
                    stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


# -----------------------------
# Utilidades
# -----------------------------

def now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat()


def get_hostname() -> str:
    if hasattr(os, "uname"):
        try:
            return os.uname().nodename
        except Exception:
            pass
    try:
        return socket.gethostname() or platform.node() or "?"
    except Exception:
        return "?"


def within_deadline(start_ts: float, deadline_sec: Optional[float]) -> bool:
    if not deadline_sec:
        return True
    return (time.time() - start_ts) <= deadline_sec


def parse_port_selector(expr: Optional[str]) -> Optional[Set[int]]:
    """Parses '80,443,8000-8100' into a set of allowed ports (0-65535)."""
    if not expr:
        return None
    out: Set[int] = set()
    for tok in re.split(r"[,\s]+", expr.strip()):
        if not tok:
            continue
        if "-" in tok:
            a, b = tok.split("-", 1)
            try:
                a_i = int(a)
                b_i = int(b)
            except ValueError:
                continue
            lo, hi = sorted((max(0, a_i), min(65535, b_i)))
            out.update(range(lo, hi + 1))
        else:
            try:
                v = int(tok)
            except ValueError:
                continue
            if 0 <= v <= 65535:
                out.add(v)
    return out


def is_public_ip(ip_str: Optional[str]) -> bool:
    """Devuelve True si la IP es global/pública (no privada, loopback, link-local ni multicast)."""
    if not ip_str:
        return False
    try:
        # Limpiar scope ID en IPv6 (p.ej. fe80::1%eth0)
        clean_ip = ip_str.split("%", 1)[0]
        ip_obj = ipaddress.ip_address(clean_ip)
        return bool(ip_obj.is_global)
    except ValueError:
        return False


def match_ip_filter(ip_str: Optional[str], expr: Optional[str]) -> bool:
    """Comprueba si ip_str coincide con una IP o subred CIDR (o lista separada por comas)."""
    if not expr:
        return True
    if not ip_str:
        return False
    clean_ip = ip_str.split("%", 1)[0]
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return clean_ip == expr.strip()

    for tok in re.split(r"[,\s]+", expr.strip()):
        if not tok:
            continue
        try:
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                if ip_obj in net:
                    return True
            else:
                if ip_obj == ipaddress.ip_address(tok):
                    return True
        except ValueError:
            if clean_ip == tok:
                return True
    return False


# -----------------------------
# Modelos
# -----------------------------

@dataclass
class ProcInfo:
    name: Optional[str] = None
    cmdline: Optional[str] = None
    user: Optional[str] = None
    exe: Optional[str] = None


@dataclass
class ServiceInfo:
    systemd_unit: Optional[str] = None


@dataclass
class GeoInfo:
    country: Optional[str] = None


@dataclass
class TIInfo:
    listed: bool = False
    source: Optional[str] = None
    confidence: Optional[int] = None


@dataclass
class Addr:
    ip: Optional[str] = None
    port: Optional[int] = None
    rdns: Optional[str] = None


@dataclass
class Finding:
    id: str
    proto: str  # tcp|udp|unix
    state: str  # LISTEN|ESTABLISHED|OTHER
    laddr: Addr
    raddr: Optional[Addr]
    pid: Optional[int]
    proc: ProcInfo = field(default_factory=ProcInfo)
    service: Optional[ServiceInfo] = None
    geoip: Optional[GeoInfo] = None
    ti: Optional[TIInfo] = None
    flags: List[str] = field(default_factory=list)
    evidence: Optional[str] = None

    def stable_id(self) -> str:
        return self.id


# -----------------------------
# Enriquecedores
# -----------------------------

def _sanitize_cmdline(cmdline_list: List[str], unsafe: bool) -> str:
    if unsafe:
        return " ".join(cmdline_list)[:512]
    if not cmdline_list:
        return ""
    exe = cmdline_list[0]
    tail = cmdline_list[1] if len(cmdline_list) > 1 and not cmdline_list[1].startswith("-") else ""
    s = " ".join(x for x in (exe, tail) if x)
    return s[:256]


def _detect_systemd_unit(pid: Optional[int]) -> Optional[ServiceInfo]:
    if not pid or pid <= 0:
        return None
    cg_path = Path(f"/proc/{pid}/cgroup")
    try:
        if not cg_path.exists():
            return None
        txt = cg_path.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"/([^/\s]+\.(?:service|scope|slice))\b", txt)
        if m:
            return ServiceInfo(systemd_unit=m.group(1))
    except Exception:
        pass
    return None


def enrich_proc(pid: Optional[int], sanitize: bool, unsafe_cmdline: bool) -> ProcInfo:
    if pid is None or pid <= 0:
        return ProcInfo()
    try:
        p = psutil.Process(pid)
        name = p.name()
        user = None
        try:
            user = p.username()
        except Exception:
            pass
        raw_cmd = []
        try:
            raw_cmd = p.cmdline()
        except Exception:
            pass
        cmd = _sanitize_cmdline(raw_cmd, unsafe_cmdline) if (sanitize or unsafe_cmdline) else ""
        exe_path = None
        if hasattr(p, "exe"):
            try:
                exe_path = p.exe()
            except Exception:
                exe_path = None
        if not exe_path and raw_cmd:
            exe_path = raw_cmd[0]
        return ProcInfo(name=name, cmdline=cmd, user=user, exe=exe_path)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return ProcInfo()


_RDNS_CACHE: Dict[str, Optional[str]] = {}


def reverse_dns(ip: str, timeout: float = 1.5) -> Optional[str]:
    if not ip:
        return None
    if ip in _RDNS_CACHE:
        return _RDNS_CACHE[ip]

    def _lookup() -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(_lookup)
        try:
            res = fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            res = None
    _RDNS_CACHE[ip] = res
    return res


def batch_reverse_dns(ips: Iterable[str], start_ts: float, deadline_sec: Optional[float], per_ip_timeout: float = 1.5) -> Dict[str, Optional[str]]:
    """Resuelve múltiples IPs en paralelo respetando el deadline global y caché."""
    unique_ips = [ip for ip in set(ips) if ip and ip not in _RDNS_CACHE]
    if unique_ips and within_deadline(start_ts, deadline_sec):
        def _task(ip_addr: str) -> Tuple[str, Optional[str]]:
            try:
                return ip_addr, socket.gethostbyaddr(ip_addr)[0]
            except Exception:
                return ip_addr, None

        remaining = max(0.5, (deadline_sec - (time.time() - start_ts))) if deadline_sec else per_ip_timeout * 2
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(unique_ips))) as ex:
            fut_map = {ex.submit(_task, ip): ip for ip in unique_ips}
            try:
                for fut in concurrent.futures.as_completed(fut_map, timeout=remaining):
                    ip_k = fut_map[fut]
                    try:
                        _, host = fut.result(timeout=per_ip_timeout)
                        _RDNS_CACHE[ip_k] = host
                    except Exception:
                        _RDNS_CACHE[ip_k] = None
            except concurrent.futures.TimeoutError:
                for fut, ip_k in fut_map.items():
                    if ip_k not in _RDNS_CACHE:
                        _RDNS_CACHE[ip_k] = None
    return _RDNS_CACHE


_GEOIP_CACHE: Dict[str, Optional[GeoInfo]] = {}


def geoip_lookup(ip: str, reader) -> Optional[GeoInfo]:
    if not reader or not ip:
        return None
    if ip in _GEOIP_CACHE:
        return _GEOIP_CACHE[ip]
    try:
        r = reader.country(ip)
        cc = getattr(r.country, "iso_code", None)
        res = GeoInfo(country=cc)
    except Exception:
        res = None
    _GEOIP_CACHE[ip] = res
    return res


# -----------------------------
# Threat Intel local (CSV: IP exacta + CIDR)
# -----------------------------

IPNetworkType = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass
class TIIndex:
    listed: Set[str]
    meta: Dict[str, Tuple[str, Optional[int]]]  # ip -> (source, confidence)
    networks: List[Tuple[IPNetworkType, str, Optional[int]]] = field(default_factory=list)

    @classmethod
    def from_csv(cls, path: Path) -> "TIIndex":
        listed: Set[str] = set()
        meta: Dict[str, Tuple[str, Optional[int]]] = {}
        networks: List[Tuple[IPNetworkType, str, Optional[int]]] = []
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            # Ignorar líneas de comentario antes de pasar a DictReader
            non_comment_lines = [line for line in f if line.strip() and not line.lstrip().startswith("#")]
            rdr = csv.DictReader(non_comment_lines)
            for row in rdr:
                ip = (row.get("ip") or "").strip()
                if not ip:
                    continue
                src = (row.get("source") or "local").strip()
                conf_raw = (row.get("confidence") or "").strip()
                try:
                    conf = int(conf_raw) if conf_raw else None
                except ValueError:
                    conf = None
                if "/" in ip:
                    try:
                        net = ipaddress.ip_network(ip, strict=False)
                        networks.append((net, src, conf))
                        continue
                    except ValueError:
                        pass
                listed.add(ip)
                meta[ip] = (src, conf)
        return cls(listed=listed, meta=meta, networks=networks)

    def query(self, ip: str) -> Optional[TIInfo]:
        if not ip:
            return None
        if ip in self.listed:
            src, conf = self.meta.get(ip, ("local", None))
            return TIInfo(listed=True, source=src, confidence=conf)
        if self.networks:
            clean_ip = ip.split("%", 1)[0]
            try:
                ip_obj = ipaddress.ip_address(clean_ip)
                for net, src, conf in self.networks:
                    if ip_obj in net:
                        return TIInfo(listed=True, source=src, confidence=conf)
            except ValueError:
                pass
        return None


# -----------------------------
# Whitelist de puertos
# -----------------------------

@dataclass
class PortWhitelist:
    allow_tcp: Set[int]
    allow_udp: Set[int]
    allow_all_tcp: bool = False
    allow_all_udp: bool = False

    @classmethod
    def from_file(cls, path: Path) -> "PortWhitelist":
        allow_tcp: Set[int] = set()
        allow_udp: Set[int] = set()
        all_tcp = all_udp = False
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.split("#", 1)[0].strip()
                if not s:
                    continue
                if s.lower() in {"tcp/*", "tcp/all"}:
                    all_tcp = True
                    continue
                if s.lower() in {"udp/*", "udp/all"}:
                    all_udp = True
                    continue
                m = re.match(r"^(tcp|udp)/(\d{1,5})(?:-(\d{1,5}))?$", s, re.I)
                if not m:
                    continue
                proto_str = m.group(1).lower()
                p_start = int(m.group(2))
                p_end = int(m.group(3)) if m.group(3) else p_start
                lo, hi = sorted((max(0, p_start), min(65535, p_end)))
                target_set = allow_tcp if proto_str == "tcp" else allow_udp
                target_set.update(range(lo, hi + 1))
        return cls(allow_tcp=allow_tcp, allow_udp=allow_udp, allow_all_tcp=all_tcp, allow_all_udp=all_udp)

    def allowed(self, proto: str, port: Optional[int]) -> bool:
        if port is None:
            return True
        if proto == "tcp":
            return self.allow_all_tcp or (port in self.allow_tcp)
        if proto == "udp":
            return self.allow_all_udp or (port in self.allow_udp)
        return False


# -----------------------------
# Recolección
# -----------------------------

def collect_connections(proto: str, state: str, scope: str, include_unix: bool, max_conns: Optional[int]):
    kinds = set()
    if proto in {"tcp", "all"}:
        kinds.add("tcp")
    if proto in {"udp", "all"}:
        kinds.add("udp")

    seen = 0
    try:
        conns = psutil.net_connections(kind="inet")  # tcp+udp
    except Exception:
        conns = []

    for c in conns:
        if max_conns and seen >= max_conns:
            return
        p = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        if p not in kinds:
            continue
        yield (p, c)
        seen += 1

    if include_unix:
        try:
            for c in psutil.net_connections(kind="unix"):
                if max_conns and seen >= max_conns:
                    return
                yield ("unix", c)
                seen += 1
        except Exception:
            pass


def is_state_match(proto: str, state_filter: str, conn_state: str, laddr, raddr) -> bool:
    if proto == "udp":
        if state_filter == "all":
            return True
        if state_filter == "listening":
            return bool(laddr) and not raddr
        if state_filter == "established":
            return bool(raddr)
        return True
    s = conn_state.upper() if conn_state else ""
    if state_filter == "all":
        return True
    if state_filter == "listening":
        return s == "LISTEN"
    if state_filter == "established":
        return s == "ESTABLISHED"
    return True


def filter_by_user_pid(conn_pid: Optional[int], target_pid: Optional[int], target_user: Optional[str]) -> bool:
    if target_pid is not None and (conn_pid != target_pid):
        return False
    if target_user:
        try:
            u = psutil.Process(conn_pid).username() if conn_pid else None
        except Exception:
            u = None
        if not u or not u.lower().endswith(target_user.lower()):
            return False
    return True


# -----------------------------
# Construcción de findings
# -----------------------------

def build_finding(proto: str, conn, sanitize: bool, unsafe_cmdline: bool) -> Finding:
    laddr = Addr()
    raddr = None
    try:
        if conn.laddr:
            if isinstance(conn.laddr, tuple) and len(conn.laddr) >= 2:
                laddr = Addr(ip=str(conn.laddr[0]), port=int(conn.laddr[1]))
            elif isinstance(conn.laddr, str):
                laddr = Addr(ip=conn.laddr, port=None)
        if conn.raddr:
            if isinstance(conn.raddr, tuple) and len(conn.raddr) >= 2:
                raddr = Addr(ip=str(conn.raddr[0]), port=int(conn.raddr[1]))
            elif isinstance(conn.raddr, str):
                raddr = Addr(ip=conn.raddr, port=None)
    except Exception:
        pass

    state = (conn.status or "").upper() if getattr(conn, "status", None) else ("LISTEN" if proto == "udp" and raddr is None else "OTHER")
    pid = getattr(conn, "pid", None)
    proc = enrich_proc(pid, sanitize=sanitize, unsafe_cmdline=unsafe_cmdline)
    svc = _detect_systemd_unit(pid)

    rid = f"{proto}:{state}:{(laddr.ip or '?')}:{(laddr.port or 0)}:{pid or 0}"
    if raddr:
        rid += f":{raddr.ip}:{raddr.port}"

    return Finding(
        id=rid,
        proto=proto,
        state=state,
        laddr=laddr,
        raddr=raddr,
        pid=pid,
        proc=proc,
        service=svc,
    )


# -----------------------------
# Motor principal
# -----------------------------

def run_inspect(args) -> Dict[str, Any]:
    start = time.time()
    _GEOIP_CACHE.clear()

    geo_reader = None
    if getattr(args, "geoip_db", None):
        if geoip2 is None:
            print("WARN: geoip2 no está instalado; ignoro --geoip-db", file=sys.stderr)
        else:
            dbp = Path(args.geoip_db)
            if dbp.exists():
                try:
                    geo_reader = geoip2.database.Reader(str(dbp))
                except Exception as e:
                    print(f"WARN: no se pudo abrir GeoIP DB: {e}", file=sys.stderr)
            else:
                print("WARN: GeoIP DB no encontrada", file=sys.stderr)

    ti_index = None
    if getattr(args, "check_threat_intel", False) and getattr(args, "ti_csv", None):
        p = Path(args.ti_csv)
        if p.exists():
            try:
                ti_index = TIIndex.from_csv(p)
            except Exception as e:
                print(f"WARN: fallo cargando TI CSV: {e}", file=sys.stderr)
        else:
            print("WARN: TI CSV no existe", file=sys.stderr)

    whitelist = None
    if getattr(args, "check_ports", False) and getattr(args, "whitelist", None):
        wp = Path(args.whitelist)
        if wp.exists():
            whitelist = PortWhitelist.from_file(wp)
        else:
            print("WARN: whitelist no existe, ignoro --check-ports", file=sys.stderr)

    lports = parse_port_selector(getattr(args, "lport", None))
    rports = parse_port_selector(getattr(args, "rport", None))
    laddr_filter = getattr(args, "laddr", None)
    raddr_filter = getattr(args, "raddr", None)
    proc_filter = getattr(args, "proc", None)
    only_public = getattr(args, "only_public", False)
    only_suspicious = getattr(args, "only_suspicious", False)

    target_user = getattr(args, "user", None)
    if getattr(args, "scope", "all") == "own" and not target_user:
        try:
            target_user = getpass.getuser()
        except Exception:
            target_user = None

    findings: List[Finding] = []
    # Pasamos max_conns=None al recolector para aplicar primero todos los filtros y cortar exactamente en max_conns hallazgos válidos
    for p, c in collect_connections(args.proto, args.state, args.scope, args.include_unix, None):
        if not is_state_match(p, args.state, getattr(c, "status", ""), c.laddr, c.raddr):
            continue
        try:
            la_ip = str(c.laddr[0]) if (c.laddr and isinstance(c.laddr, tuple)) else None
            la_port = int(c.laddr[1]) if (c.laddr and isinstance(c.laddr, tuple) and len(c.laddr) >= 2) else None
            ra_ip = str(c.raddr[0]) if (c.raddr and isinstance(c.raddr, tuple)) else None
            ra_port = int(c.raddr[1]) if (c.raddr and isinstance(c.raddr, tuple) and len(c.raddr) >= 2) else None
        except Exception:
            la_ip = la_port = ra_ip = ra_port = None

        if lports is not None and la_port not in lports:
            continue
        if rports is not None and ra_port not in rports:
            continue
        if laddr_filter and not match_ip_filter(la_ip, laddr_filter):
            continue
        if raddr_filter and not match_ip_filter(ra_ip, raddr_filter):
            continue
        if only_public and not is_public_ip(ra_ip):
            continue
        if not filter_by_user_pid(getattr(c, "pid", None), args.pid, target_user):
            continue

        f = build_finding(p, c, sanitize=not args.unsafe_proc_cmdline, unsafe_cmdline=args.unsafe_proc_cmdline)
        if proc_filter:
            pname = (f.proc.name or "").lower()
            pcmd = (f.proc.cmdline or "").lower()
            if proc_filter.lower() not in pname and proc_filter.lower() not in pcmd:
                continue

        findings.append(f)
        if args.max_conns and not only_suspicious and len(findings) >= args.max_conns:
            break

    # Resolución RDNS en lote si está activada
    if getattr(args, "rdns", False) and findings and within_deadline(start, args.deadline_sec):
        remote_ips = [f.raddr.ip for f in findings if f.raddr and f.raddr.ip]
        batch_reverse_dns(remote_ips, start, args.deadline_sec)

    for f in findings:
        if not within_deadline(start, args.deadline_sec):
            break

        evidences: List[str] = []

        if args.rdns and f.raddr and f.raddr.ip:
            f.raddr.rdns = _RDNS_CACHE.get(f.raddr.ip) if f.raddr.ip in _RDNS_CACHE else reverse_dns(f.raddr.ip, timeout=1.5)

        if geo_reader and f.raddr and f.raddr.ip:
            f.geoip = geoip_lookup(f.raddr.ip, geo_reader)

        if ti_index and f.raddr and f.raddr.ip:
            ti = ti_index.query(f.raddr.ip)
            if ti:
                f.ti = ti
                f.flags.append("ti_blacklisted")
                evidences.append(f"TI hit for {f.raddr.ip} ({ti.source}, conf={ti.confidence})")

        if args.check_ports and whitelist and f.state == "LISTEN" and f.proto in {"tcp", "udp"}:
            port = f.laddr.port
            if port is not None and not whitelist.allowed(f.proto, port):
                f.flags.append("not_in_whitelist")
                evidences.append(f"listening on {f.laddr.ip}:{port} (not in whitelist)")

        if f.state == "LISTEN":
            l_ip = f.laddr.ip or ""
            l_port = f.laddr.port or 0
            if l_ip in {"0.0.0.0", "::", "*"}:
                if l_port >= 1024:
                    f.flags.append("exposed_high_port")
                if l_port in SENSITIVE_EXPOSED_PORTS:
                    svc_name = SENSITIVE_EXPOSED_PORTS[l_port]
                    f.flags.append("exposed_sensitive_port")
                    evidences.append(f"sensitive service ({svc_name}) exposed on {l_ip}:{l_port}")

        if f.state == "ESTABLISHED" and f.raddr and f.raddr.port in C2_LIKE_PORTS:
            f.flags.append("c2_like_port")
            evidences.append(f"connection to suspicious port {f.raddr.port}")

        # Heurística de ejecutable en directorio temporal (/tmp, /dev/shm, etc.)
        exe_or_cmd = (f.proc.exe or f.proc.cmdline or "").lower()
        if exe_or_cmd and any(d in exe_or_cmd for d in SUSPICIOUS_PROC_DIRS):
            f.flags.append("proc_suspicious_path")
            evidences.append(f"process running from temporary/shared memory path: {f.proc.exe or f.proc.cmdline}")

        # Sanitizar exe en salida final si no se pidió unsafe_proc_cmdline
        if f.proc.exe and not args.unsafe_proc_cmdline:
            f.proc.exe = Path(f.proc.exe).name

        if evidences and not f.evidence:
            f.evidence = "; ".join(evidences)
        elif evidences and f.evidence:
            f.evidence = f.evidence + "; " + "; ".join(evidences)

    if only_suspicious:
        findings = [f for f in findings if f.flags]
        if args.max_conns:
            findings = findings[:args.max_conns]

    by_country: Dict[str, int] = {}
    by_proto: Dict[str, int] = Counter()
    by_state: Dict[str, int] = Counter()
    proc_counter: Counter = Counter()

    for f in findings:
        by_proto[f.proto] += 1
        by_state[f.state] += 1
        if f.proc and f.proc.name:
            proc_counter[f.proc.name] += 1
        cc = f.geoip.country if (f.geoip and f.geoip.country) else "??"
        if f.raddr and f.raddr.ip and (f.geoip is not None):
            by_country[cc] = by_country.get(cc, 0) + 1

    summary = {
        "total": len(findings),
        "listening": sum(1 for f in findings if f.state == "LISTEN"),
        "established": sum(1 for f in findings if f.state == "ESTABLISHED"),
        "public_established": sum(1 for f in findings if f.state == "ESTABLISHED" and f.raddr and is_public_ip(f.raddr.ip)),
        "udp": sum(1 for f in findings if f.proto == "udp"),
        "by_country": by_country,
        "by_proto": dict(by_proto),
        "by_state": dict(by_state),
        "top_processes": dict(proc_counter.most_common(5)),
        "suspicious": sum(1 for f in findings if f.flags),
    }

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now_iso(),
        "host": get_hostname(),
        "tool": "sabbat-netinspect",
        "parameters_used": {
            "proto": args.proto,
            "state": args.state,
            "scope": args.scope,
            "geoip": bool(args.geoip_db),
            "ti": bool(args.check_threat_intel and args.ti_csv),
            "max_conns": args.max_conns,
            "deadline_sec": args.deadline_sec,
            "rdns": bool(args.rdns),
            "check_ports": bool(args.check_ports),
        },
        "summary": summary,
        "findings": [asdict(f) for f in findings],
    }
    if geo_reader:
        try:
            geo_reader.close()
        except Exception:
            pass
    return report


# -----------------------------
# Snapshot & Diff
# -----------------------------

def save_snapshot(report: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def load_snapshot(path: Path) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def index_findings(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    idx = {}
    for f in report.get("findings", []):
        fid = f.get("id")
        if fid:
            idx[fid] = f
    return idx


def diff_reports(prev: Dict[str, Any], cur: Dict[str, Any]) -> Dict[str, Any]:
    A = index_findings(prev)
    B = index_findings(cur)
    added = [B[k] for k in sorted(B.keys() - A.keys())]
    removed = [A[k] for k in sorted(A.keys() - B.keys())]
    changed = []
    for k in sorted(A.keys() & B.keys()):
        if json.dumps(A[k], sort_keys=True) != json.dumps(B[k], sort_keys=True):
            changed.append({"id": k, "before": A[k], "after": B[k]})
    return {
        "schema_version": SCHEMA_VERSION,
        "diff_of": f"{prev.get('generated_at')} vs {cur.get('generated_at')}",
        "summary": {"added": len(added), "removed": len(removed), "changed": len(changed)},
        "added": added, "removed": removed, "changed": changed
    }


# -----------------------------
# Impresión
# -----------------------------

def print_human(report: Dict[str, Any]) -> None:
    summ = report["summary"]
    pub_est = summ.get("public_established", 0)
    print(
        f"Total: {summ['total']} | LISTEN: {summ['listening']} | EST: {summ['established']} (Public: {pub_est}) "
        f"| UDP: {summ['udp']} | Suspicious: {summ['suspicious']}"
    )
    print("PROTO\tSTATE\tLADDR\tRADDR\tPID\tPROC\tFLAGS")
    for f in report["findings"]:
        la = f"{f['laddr']['ip']}:{f['laddr']['port']}" if f['laddr']['ip'] else "-"
        if f["raddr"] and f["raddr"].get("ip"):
            ra = f"{f['raddr']['ip']}:{f['raddr']['port']}"
            if f["raddr"].get("rdns"):
                ra += f" ({f['raddr']['rdns']})"
        else:
            ra = "-"
        proc = f['proc'].get('name') or ""
        flags = ",".join(f.get("flags") or [])
        print("\t".join([f["proto"], f["state"], la, ra, str(f["pid"] or ""), proc, flags]))


def print_diff_human(diff: Dict[str, Any]) -> None:
    s = diff["summary"]
    print(f"Diff {diff['diff_of']} — added={s['added']} removed={s['removed']} changed={s['changed']}")
    for item in diff.get("added", []):
        la = f"{item['laddr']['ip']}:{item['laddr']['port']}" if item.get("laddr") else "-"
        ra = f"{item['raddr']['ip']}:{item['raddr']['port']}" if item.get("raddr") else "-"
        proc = (item.get("proc") or {}).get("name") or "?"
        print(f"  [+] {item['proto']} {item['state']} {la} -> {ra} (pid={item.get('pid')}, proc={proc})")
    for item in diff.get("removed", []):
        la = f"{item['laddr']['ip']}:{item['laddr']['port']}" if item.get("laddr") else "-"
        ra = f"{item['raddr']['ip']}:{item['raddr']['port']}" if item.get("raddr") else "-"
        proc = (item.get("proc") or {}).get("name") or "?"
        print(f"  [-] {item['proto']} {item['state']} {la} -> {ra} (pid={item.get('pid')}, proc={proc})")
    for chg in diff.get("changed", []):
        print(f"  [~] {chg['id']}")


def print_raw(report: Dict[str, Any]) -> None:
    print("proto\tstate\tl_ip\tl_port\tr_ip\tr_port\tpid\tproc\tflags")
    for f in report["findings"]:
        la_ip = f['laddr']['ip'] or ""
        la_po = str(f['laddr']['port'] or "")
        if f["raddr"]:
            ra_ip = f['raddr']['ip'] or ""
            ra_po = str(f['raddr']['port'] or "")
        else:
            ra_ip = ra_po = ""
        proc = f['proc'].get('name') or ""
        flags = ",".join(f.get("flags") or [])
        print("\t".join([f["proto"], f["state"], la_ip, la_po, ra_ip, ra_po, str(f["pid"] or ""), proc, flags]))


def print_json(report: Dict[str, Any], jsonl: bool) -> None:
    if jsonl:
        for f in report["findings"]:
            print(json.dumps(f, ensure_ascii=False))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))


# -----------------------------
# CLI
# -----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sabbat-netinspect",
        description="Network & connections inspector (psutil-based), JSON-friendly."
    )
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="Emit JSON report")
    out.add_argument("--jsonl", action="store_true", help="Emit JSON Lines (one finding per line)")
    out.add_argument("--raw", action="store_true", help="Raw TSV to stdout")
    p.add_argument("--proto", choices=["tcp", "udp", "all"], default="all")
    p.add_argument("--state", choices=["listening", "established", "all"], default="all")
    p.add_argument("--scope", choices=["all", "own"], default="all", help="Note: 'all' may require elevated privileges")
    p.add_argument("--pid", type=int, help="Only connections from this PID")
    p.add_argument("--user", type=str, help="Only connections from this user (suffix match)")
    p.add_argument("--proc", type=str, help="Filter by process name or command substring")
    p.add_argument("--laddr", type=str, help="Filter local IP or CIDR (e.g. '127.0.0.1,10.0.0.0/8')")
    p.add_argument("--raddr", type=str, help="Filter remote IP or CIDR (e.g. '203.0.113.0/24')")
    p.add_argument("--lport", type=str, help="Filter local ports: '80,443,8000-8100'")
    p.add_argument("--rport", type=str, help="Filter remote ports: '53,123'")
    p.add_argument("--only-public", action="store_true", help="Only connections to public/global remote IPs")
    p.add_argument("--only-suspicious", action="store_true", help="Only connections with security flags")
    p.add_argument("--rdns", action="store_true", help="Reverse DNS for remote IPs (concurrent with timeout)")
    p.add_argument("--geoip-db", type=str, help="MaxMind GeoLite2 Country DB path (if geoip2 installed)")
    p.add_argument("--whitelist", type=str, help="Ports whitelist file (lines like 'tcp/22', 'tcp/8000-8100', 'tcp/*')")
    p.add_argument("--check-ports", action="store_true", help="Flag listening ports not in whitelist")
    p.add_argument("--ti-csv", type=str, help="Local Threat Intel CSV (columns: ip,source,confidence; supports CIDR)")
    p.add_argument("--check-threat-intel", action="store_true", help="Enable threat intel local lookup")
    p.add_argument("--snapshot", action="store_true", help="Write current snapshot to --output and exit")
    p.add_argument("--output", "-o", type=str, help="Output file for snapshot or JSON")
    p.add_argument("--diff", type=str, help="Compare current state against previous JSON snapshot file")
    p.add_argument("--max-conns", type=int, help="Stop after processing N connections")
    p.add_argument("--deadline-sec", type=float, default=10.0, help="Global soft deadline for enrichment (seconds)")
    p.add_argument("--include-unix", action="store_true", help="Include UNIX sockets")
    p.add_argument("--sanitize", dest="sanitize", action="store_true", default=True, help="Sanitize cmdline (default)")
    p.add_argument("--unsafe-proc-cmdline", dest="unsafe_proc_cmdline", action="store_true", help="Include full cmdline (privacy risk)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    _ensure_utf8_stdio()
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    args = parser.parse_args(argv)

    report = run_inspect(args)

    if args.snapshot:
        if not args.output:
            print("ERROR: --snapshot requiere --output", file=sys.stderr)
            return 1
        save_snapshot(report, Path(args.output))
        print(f"[+] Snapshot escrito en {args.output}")
        return 0

    if args.diff:
        prev = load_snapshot(Path(args.diff))
        cur = report
        diff = diff_reports(prev, cur)
        if args.json or args.output:
            payload = json.dumps(diff, ensure_ascii=False, indent=2)
            if args.output:
                Path(args.output).parent.mkdir(parents=True, exist_ok=True)
                Path(args.output).write_text(payload, encoding="utf-8")
                print(f"[+] Diff JSON escrito en {args.output}")
            else:
                print(payload)
        else:
            print_diff_human(diff)
        return 0

    if args.json or args.output:
        payload = json.dumps(report, ensure_ascii=False, indent=2)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(payload, encoding="utf-8")
            print(f"[+] JSON escrito en {args.output}")
        else:
            print(payload)
    elif args.jsonl:
        print_json(report, jsonl=True)
    elif args.raw:
        print_raw(report)
    else:
        print_human(report)

    exit_code = 2 if report["summary"]["suspicious"] else 0
    return exit_code


def cli_main():
    # Compat: entry points antiguos apuntan a cli_main
    return main()


if __name__ == "__main__":
    raise SystemExit(main())
