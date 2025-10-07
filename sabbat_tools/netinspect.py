#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sabbat-netinspect — Inspector de Red y Conexiones (presente dinámico)

MVP portable sobre psutil con:
- Conexiones activas (TCP/UDP, IPv4/IPv6), correlación PID↔Proceso
- Filtros por proto/estado/puertos/usuario/PID
- GeoIP opcional (MaxMind, si geoip2 está instalado)
- Threat Intel local desde CSV (sin llamadas online)
- Whitelist de puertos (detección de expuestos no permitidos)
- Reverse DNS opt-in
- Snapshot/diff
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
import ipaddress
import json
import os
import re
import socket
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

# Dependencias suaves
try:
    import psutil  # type: ignore
except Exception as e:
    print("ERROR: sabbat-netinspect requiere 'psutil'. Instala con: pip install psutil", file=sys.stderr)
    raise

try:
    import geoip2.database  # type: ignore
except Exception:
    geoip2 = None  # lazily checked


SCHEMA_VERSION = "1.0"


# -----------------------------
# Utilidades
# -----------------------------

def now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat()


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
                a_i = int(a); b_i = int(b)
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


# -----------------------------
# Modelos
# -----------------------------

@dataclass
class ProcInfo:
    name: Optional[str] = None
    cmdline: Optional[str] = None
    user: Optional[str] = None


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
        cmd = _sanitize_cmdline(p.cmdline(), unsafe_cmdline) if sanitize or unsafe_cmdline else ""
        return ProcInfo(name=name, cmdline=cmd, user=user)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return ProcInfo()


def reverse_dns(ip: str, timeout: float = 1.5) -> Optional[str]:
    if not ip:
        return None
    def _lookup() -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(_lookup)
        try:
            return fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return None


def geoip_lookup(ip: str, reader) -> Optional[GeoInfo]:
    if not reader or not ip:
        return None
    try:
        r = reader.country(ip)
        cc = getattr(r.country, "iso_code", None)
        return GeoInfo(country=cc)
    except Exception:
        return None


# -----------------------------
# Threat Intel local (CSV)
# -----------------------------

from dataclasses import dataclass
@dataclass
class TIIndex:
    listed: Set[str]
    meta: Dict[str, Tuple[str, Optional[int]]]  # ip -> (source, confidence)

    @classmethod
    def from_csv(cls, path: Path) -> "TIIndex":
        listed: Set[str] = set()
        meta: Dict[str, Tuple[str, Optional[int]]] = {}
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            rdr = csv.DictReader(f)
            for row in rdr:
                ip = (row.get("ip") or "").strip()
                if not ip:
                    continue
                listed.add(ip)
                src = (row.get("source") or "local").strip()
                conf_raw = (row.get("confidence") or "").strip()
                try:
                    conf = int(conf_raw) if conf_raw else None
                except ValueError:
                    conf = None
                meta[ip] = (src, conf)
        return cls(listed=listed, meta=meta)

    def query(self, ip: str) -> Optional[TIInfo]:
        if ip in self.listed:
            src, conf = self.meta.get(ip, ("local", None))
            return TIInfo(listed=True, source=src, confidence=conf)
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
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s.lower() in {"tcp/*", "tcp/all"}:
                    all_tcp = True
                    continue
                if s.lower() in {"udp/*", "udp/all"}:
                    all_udp = True
                    continue
                m = re.match(r"^(tcp|udp)/(\d{1,5})$", s, re.I)
                if not m:
                    continue
                port = int(m.group(2))
                if 0 <= port <= 65535:
                    if m.group(1).lower() == "tcp":
                        allow_tcp.add(port)
                    else:
                        allow_udp.add(port)
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
    kinds = []
    if proto in {"tcp", "all"}:
        kinds.append("tcp")
    if proto in {"udp", "all"}:
        kinds.append("udp")

    seen = 0
    try:
        conns = psutil.net_connections(kind="inet")  # tcp+udp
    except Exception:
        conns = []

    for c in conns:
        if max_conns and seen >= max_conns:
            return
        p = "tcp" if c.type == socket.SOCK_STREAM else "udp"
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
        if not u or not u.endswith(target_user):
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
            if isinstance(conn.laddr, tuple):
                laddr = Addr(ip=str(conn.laddr[0]), port=int(conn.laddr[1]))
        if conn.raddr:
            if isinstance(conn.raddr, tuple) and len(conn.raddr) >= 2:
                raddr = Addr(ip=str(conn.raddr[0]), port=int(conn.raddr[1]))
    except Exception:
        pass

    state = (conn.status or "").upper() if getattr(conn, "status", None) else ("LISTEN" if proto == "udp" and raddr is None else "OTHER")
    pid = getattr(conn, "pid", None)
    proc = enrich_proc(pid, sanitize=sanitize, unsafe_cmdline=unsafe_cmdline)

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
    )


# -----------------------------
# Motor principal
# -----------------------------

def run_inspect(args) -> Dict[str, object]:
    start = time.time()

    geo_reader = None
    if args.geoip_db:
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
    if args.check_threat_intel and args.ti_csv:
        p = Path(args.ti_csv)
        if p.exists():
            try:
                ti_index = TIIndex.from_csv(p)
            except Exception as e:
                print(f"WARN: fallo cargando TI CSV: {e}", file=sys.stderr)
        else:
            print("WARN: TI CSV no existe", file=sys.stderr)

    whitelist = None
    if args.check_ports and args.whitelist:
        wp = Path(args.whitelist)
        if wp.exists():
            whitelist = PortWhitelist.from_file(wp)
        else:
            print("WARN: whitelist no existe, ignoro --check-ports", file=sys.stderr)

    lports = parse_port_selector(args.lport)
    rports = parse_port_selector(args.rport)

    findings: List[Finding] = []
    for p, c in collect_connections(args.proto, args.state, args.scope, args.include_unix, args.max_conns):
        if not is_state_match(p, args.state, getattr(c, "status", ""), c.laddr, c.raddr):
            continue
        try:
            la = c.laddr[1] if c.laddr else None
            ra = c.raddr[1] if c.raddr else None
        except Exception:
            la = ra = None
        if lports is not None and la not in lports:
            continue
        if rports is not None and ra not in rports:
            continue
        if not filter_by_user_pid(getattr(c, "pid", None), args.pid, args.user):
            continue

        f = build_finding(p, c, sanitize=not args.unsafe_proc_cmdline, unsafe_cmdline=args.unsafe_proc_cmdline)
        findings.append(f)
        if args.max_conns and len(findings) >= args.max_conns:
            break

    for f in findings:
        if not within_deadline(start, args.deadline_sec):
            break

        if args.rdns and f.raddr and f.raddr.ip:
            f.raddr.rdns = reverse_dns(f.raddr.ip, timeout=1.5)

        if geo_reader and f.raddr and f.raddr.ip:
            f.geoip = geoip_lookup(f.raddr.ip, geo_reader)

        if ti_index and f.raddr and f.raddr.ip:
            ti = ti_index.query(f.raddr.ip)
            if ti:
                f.ti = ti
                f.flags.append("ti_blacklisted")
                f.evidence = f"TI hit for {f.raddr.ip} ({ti.source}, conf={ti.confidence})"

        if args.check_ports and whitelist and f.state == "LISTEN" and f.proto in {"tcp", "udp"}:
            port = f.laddr.port
            if port is not None and not whitelist.allowed(f.proto, port):
                f.flags.append("not_in_whitelist")
                f.evidence = f"listening on {f.laddr.ip}:{port} (not in whitelist)"

        if f.state == "LISTEN":
            if f.laddr.ip in {"0.0.0.0", "::"} and (f.laddr.port or 0) >= 1024:
                f.flags.append("exposed_high_port")
        if f.state == "ESTABLISHED" and f.raddr and f.raddr.port in {6667, 6668, 1337, 14444, 33445}:
            f.flags.append("c2_like_port")

    summary = {
        "total": len(findings),
        "listening": sum(1 for f in findings if f.state == "LISTEN"),
        "established": sum(1 for f in findings if f.state == "ESTABLISHED"),
        "udp": sum(1 for f in findings if f.proto == "udp"),
    }
    by_country: Dict[str, int] = {}
    for f in findings:
        cc = f.geoip.country if (f.geoip and f.geoip.country) else "??"
        if f.raddr and f.raddr.ip and (f.geoip is not None):
            by_country[cc] = by_country.get(cc, 0) + 1
    summary["by_country"] = by_country
    summary["suspicious"] = sum(1 for f in findings if f.flags)

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now_iso(),
        "host": os.uname().nodename if hasattr(os, "uname") else "?",
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

def save_snapshot(report: Dict[str, object], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2))


def load_snapshot(path: Path) -> Dict[str, object]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def index_findings(report: Dict[str, object]) -> Dict[str, Dict[str, object]]:
    idx = {}
    for f in report.get("findings", []):
        fid = f.get("id")
        if fid:
            idx[fid] = f
    return idx


def diff_reports(prev: Dict[str, object], cur: Dict[str, object]) -> Dict[str, object]:
    A = index_findings(prev)
    B = index_findings(cur)
    added = [B[k] for k in B.keys() - A.keys()]
    removed = [A[k] for k in A.keys() - B.keys()]
    changed = []
    for k in (A.keys() & B.keys()):
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

def print_human(report: Dict[str, object]) -> None:
    summ = report["summary"]
    print(f"Total: {summ['total']} | LISTEN: {summ['listening']} | EST: {summ['established']} | UDP: {summ['udp']} | Suspicious: {summ['suspicious']}")
    print("PROTO\tSTATE\tLADDR\tRADDR\tPID\tPROC\tFLAGS")
    for f in report["findings"]:
# Makefile for sabbat-tools
        la = f"{f['laddr']['ip']}:{f['laddr']['port']}" if f['laddr']['ip'] else "-"
        if f["raddr"]:
            ra = f"{f['raddr']['ip']}:{f['raddr']['port']}"
        else:
            ra = "-"
        proc = f['proc'].get('name') or ""
        flags = ",".join(f.get("flags") or [])
        print("\t".join([f["proto"], f["state"], la, ra, str(f["pid"] or ""), proc, flags]))


def print_raw(report: Dict[str, object]) -> None:
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


def print_json(report: Dict[str, object], jsonl: bool) -> None:
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
    p.add_argument("--lport", type=str, help="Filter local ports: '80,443,8000-8100'")
    p.add_argument("--rport", type=str, help="Filter remote ports: '53,123'")
    p.add_argument("--rdns", action="store_true", help="Reverse DNS for remote IPs (timeout per lookup)")
    p.add_argument("--geoip-db", type=str, help="MaxMind GeoLite2 Country DB path (if geoip2 installed)")
    p.add_argument("--whitelist", type=str, help="Ports whitelist file (lines like 'tcp/22', 'udp/53', 'tcp/*')")
    p.add_argument("--check-ports", action="store_true", help="Flag listening ports not in whitelist")
    p.add_argument("--ti-csv", type=str, help="Local Threat Intel CSV (columns: ip,source,confidence)")
    p.add_argument("--check-threat-intel", action="store_true", help="Enable threat intel local lookup")
    p.add_argument("--snapshot", action="store_true", help="Write current snapshot to --output and exit")
    p.add_argument("--output", type=str, help="Output file for snapshot or JSON")
    p.add_argument("--diff", type=str, help="Compare current state against previous JSON snapshot file")
    p.add_argument("--max-conns", type=int, help="Stop after processing N connections")
    p.add_argument("--deadline-sec", type=float, default=10.0, help="Global soft deadline for enrichment (seconds)")
    p.add_argument("--include-unix", action="store_true", help="Include UNIX sockets")
    p.add_argument("--sanitize", dest="sanitize", action="store_true", default=True, help="Sanitize cmdline (default)")
    p.add_argument("--unsafe-proc-cmdline", dest="unsafe_proc_cmdline", action="store_true", help="Include full cmdline (privacy risk)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
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
                Path(args.output).write_text(payload)
                print(f"[+] Diff JSON escrito en {args.output}")
            else:
                print(payload)
        else:
            print(f"Diff {diff['diff_of']} — added={diff['summary']['added']} removed={diff['summary']['removed']} changed={diff['summary']['changed']}")
        return 0

    if args.json or args.output:
        payload = json.dumps(report, ensure_ascii=False, indent=2)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(payload)
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

