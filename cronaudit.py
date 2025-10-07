#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sabbat-syscheck — subcomando `cronaudit`
Audita tareas programadas de cron y systemd timers.

Características:
- Recolecta cron system-wide (/etc/crontab, /etc/cron.d/*) y crontabs de usuarios
  (en /var/spool/cron, /var/spool/cron/crontabs y via `crontab -l` cuando sea posible).
- Enumera timers de systemd y resuelve la unidad .service asociada.
- Analiza comandos: patrones peligrosos, rutas relativas/no resolubles, uso de variables sin defaults.
- Análisis de permisos/propietario: usuario efectivo, tareas root, existencia de usuario.
- Detección de tareas huérfanas: usuarios inexistentes, binarios inexistentes, servicios faltantes.
- Salida en JSON opcional para SIEM/monitorización.
- Modo simulación (dry-run): muestra qué se ejecutaría sin ejecutarlo.

Integración sugerida: añadir este archivo al paquete `sabbat_tools` y registrar en setup.cfg/pyproject
un entry point de consola existente `sabbat-syscheck` con subcomando `cronaudit`.

Ejemplos:
  sabbat-syscheck cronaudit --json --output audits/cron_$(date +%Y%m%d).json
  sabbat-syscheck cronaudit --check-dangerous --pattern "rm -rf|wget|curl.*pipe"
  sabbat-syscheck cronaudit --check-privileges --user root
"""

from __future__ import annotations

import argparse
import dataclasses
import fnmatch
import getpass
import grp
import json
import os
import pwd
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# --------------------------- Utilidades comunes ---------------------------

SEVERITY = ("info", "low", "medium", "high", "critical")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/(\s|$)",  # rm -rf /
    r"rm\s+-rf\s+[^;|]*\*",  # rm -rf *
    r"curl\s+[^|\n]*\|\s*(sh|bash)\b",
    r"wget\s+[^|\n]*\|\s*(sh|bash)\b",
    r"(curl|wget)\s+http://",  # http sin TLS
    r"chmod\s+777\b",
    r"chown\s+[^|;]*\broot\b\s+/",
    r"base64\s+-d\s*\|\s*(sh|bash)\b",
    r"python\s+-c\s*\"?exec\(.*base64",
    r"nc\s+.*\s+-e\s+",  # reverse shells
    r"bash\s+-i\s+>&\s+/dev/tcp/",
    r"xmrig|minerd|ethminer|cpuminer",  # cryptominers comunes
]
DANGEROUS_RX = re.compile("|".join(f"({p})" for p in DANGEROUS_PATTERNS), re.I)

ENV_VAR_RX = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([^}:]+)(?::-[^}]+)?\}")
ENV_VAR_WITH_DEFAULT_RX = re.compile(r"\$\{[^}:]+:-[^}]+\}")

CRON_LINE_RX = re.compile(
    r"^\s*(?P<m1>\S+)\s+(?P<m2>\S+)\s+(?P<m3>\S+)\s+(?P<m4>\S+)\s+(?P<m5>\S+)(?:\s+(?P<user>\S+))?\s+(?P<cmd>.+)$"
)

SYSTEMD_COL_SPLIT_RX = re.compile(r"\s{2,}")


@dataclass
class Issue:
    code: str
    message: str
    severity: str


@dataclass
class Finding:
    kind: str  # "cron" | "timer"
    id: str
    source: str
    schedule: str
    user: str
    command: str
    raw: str
    exists_user: bool
    command_resolves: bool
    absolute_cmd: bool
    env_vars: List[str] = field(default_factory=list)
    env_vars_without_default: List[str] = field(default_factory=list)
    needs_root_heuristic: bool = False
    orphaned: bool = False
    timer_unit: Optional[str] = None
    service_unit: Optional[str] = None
    service_missing: bool = False
    issues: List[Issue] = field(default_factory=list)

    def add(self, code: str, message: str, severity: str) -> None:
        self.issues.append(Issue(code, message, severity))


# --------------------------- Recolección: CRON ---------------------------

CRON_PATHS = [
    Path("/etc/crontab"),
    Path("/etc/cron.d"),
]
SPoolPaths = [Path("/var/spool/cron"), Path("/var/spool/cron/crontabs")]


def iter_system_cron_files() -> Iterable[Tuple[Path, str]]:
    for path in CRON_PATHS:
        if path.is_file():
            yield (path, path.read_text(errors="ignore"))
        elif path.is_dir():
            for f in sorted(path.glob("*")):
                if f.is_file():
                    try:
                        yield (f, f.read_text(errors="ignore"))
                    except Exception:
                        continue


def iter_user_crontabs() -> Iterable[Tuple[str, str]]:
    # 1) Intentar leer spool
    for base in SPoolPaths:
        if base.is_dir():
            for f in sorted(base.glob("*")):
                try:
                    user = f.name
                    txt = f.read_text(errors="ignore")
                    yield (user, txt)
                except Exception:
                    continue
    # 2) Fallback: listar usuarios y ejecutar `crontab -l`
    try:
        for p in pwd.getpwall():
            user = p.pw_name
            # Saltar usuarios del sistema sin shell
            if p.pw_shell in ("/usr/sbin/nologin", "/bin/false", ""):  # común
                continue
            try:
                out = subprocess.run(
                    ["crontab", "-l", "-u", user],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if out.returncode == 0 and out.stdout.strip():
                    yield (user, out.stdout)
            except FileNotFoundError:
                break
    except Exception:
        pass


def parse_crontab(text: str, source: str, default_user: Optional[str]) -> Iterable[Finding]:
    env: Dict[str, str] = {}
    for line in text.splitlines():
        raw = line.rstrip("\n")
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        # Líneas tipo KEY=VAL (entorno)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", raw):
            k, v = raw.split("=", 1)
            env[k.strip()] = v.strip()
            continue
        m = CRON_LINE_RX.match(raw)
        if not m:
            # No cron line válido
            f = Finding(
                kind="cron",
                id=f"{source}:{hash(raw)}",
                source=source,
                schedule="?",
                user=default_user or "?",
                command=raw,
                raw=raw,
                exists_user=_user_exists(default_user) if default_user else False,
                command_resolves=False,
                absolute_cmd=False,
            )
            f.add("cron.syntax", "Línea de cron no válida", "medium")
            yield f
            continue
        user = m.group("user") or (default_user or "?")
        sched = " ".join(m.group(g) for g in ["m1", "m2", "m3", "m4", "m5"])  # noqa
        cmd = m.group("cmd").strip()
        yield _analyze_cron_entry(user=user, schedule=sched, cmd=cmd, raw=raw, source=source, env=env)


def _user_exists(user: Optional[str]) -> bool:
    if not user or user == "?":
        return False
    try:
        pwd.getpwnam(user)
        return True
    except KeyError:
        return False


def _first_token(cmd: str) -> str:
    try:
        parts = shlex.split(cmd, posix=True)
        return parts[0] if parts else ""
    except Exception:
        return cmd.split()[0] if cmd.split() else ""


def _analyze_cron_entry(*, user: str, schedule: str, cmd: str, raw: str, source: str, env: Dict[str, str]) -> Finding:
    token = _first_token(cmd)
    token_is_abs = token.startswith("/")
    token_resolves = bool(which(token)) if not token_is_abs else Path(token).exists()
    f = Finding(
        kind="cron",
        id=f"cron:{source}:{user}:{hash(raw)}",
        source=source,
        schedule=schedule,
        user=user,
        command=cmd,
        raw=raw,
        exists_user=_user_exists(user),
        command_resolves=token_resolves,
        absolute_cmd=token_is_abs,
    )
    if not f.exists_user:
        f.orphaned = True
        f.add("cron.user_missing", f"Usuario inexistente: {user}", "high")
    if not token_resolves:
        f.add("cmd.not_found", f"Comando no resoluble: {token}", "high")
    if not token_is_abs:
        f.add("cmd.relative_or_path", f"Primer token no es ruta absoluta: {token}", "low")

    # Variables de entorno
    vars_found = [m.group(1) or m.group(2) for m in ENV_VAR_RX.finditer(cmd)]
    f.env_vars = vars_found
    without_default = []
    for var in vars_found:
        # si aparece como ${VAR:-def} consideramos con default
        if not re.search(rf"\$\{{{re.escape(var)}:-[^}}]+\}}", cmd):
            without_default.append(var)
    f.env_vars_without_default = without_default
    if without_default:
        f.add("env.unsanitized", f"Variables sin default: {', '.join(without_default)}", "low")

    # Patrones peligrosos
    if DANGEROUS_RX.search(cmd):
        f.add("cmd.dangerous_pattern", "Se detectaron patrones peligrosos", "critical")

    # Heurística: ¿parece necesitar root?
    if _needs_root(cmd):
        f.needs_root_heuristic = True
        if user != "root":
            f.add("priv.mismatch", "La tarea parece requerir root pero no se ejecuta como root", "medium")
    else:
        if user == "root":
            f.add("priv.possible_excess", "Tarea ejecutándose como root sin indicios claros de necesidad", "low")

    return f


PRIVILEGED_DIRS = ("/etc/", "/root/", "/var/lib/", "/var/spool/", "/usr/local/sbin/", "/sbin/")


def _needs_root(cmd: str) -> bool:
    # heurística simple: escribir en rutas privilegiadas, bind puertos <1024
    cmd_l = cmd.lower()
    # escritura
    if re.search(r">\s*/(etc|root|var/lib|var/spool|usr/local/sbin|sbin)/", cmd_l):
        return True
    if re.search(r"\b(chown|chmod)\b.*\s/(etc|root|var/lib|var/spool)/", cmd_l):
        return True
    # puertos privilegiados
    if re.search(r"\b(\d{1,3})\b", cmd_l):
        # detectar patrones de puerto obvios
        if re.search(r"\b(80|53|25|110|143|443|22)\b", cmd_l) and re.search(r"\b(nc|ncat|socat|python\s+-m\s+http\.server|busybox\s+httpd|sshd)\b", cmd_l):
            return True
    return False


# ---------------------- Recolección: systemd timers ----------------------

def list_systemd_timers() -> List[Dict[str, str]]:
    timers: List[Dict[str, str]] = []
    try:
        out = subprocess.run(
            ["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if out.returncode != 0:
            return timers
        for line in out.stdout.splitlines():
            if not line.strip():
                continue
            cols = SYSTEMD_COL_SPLIT_RX.split(line.strip())
            if not cols:
                continue
            # Formato típico: NEXT LEFT LAST PASSED UNIT ACTIVATES
            unit = cols[-2] if len(cols) >= 2 else "?"
            activates = cols[-1] if len(cols) >= 1 else "?"
            timers.append({"unit": unit, "activates": activates, "raw": line})
    except FileNotFoundError:
        pass
    return timers


def show_unit_props(unit: str, props: List[str]) -> Dict[str, str]:
    out = subprocess.run(
        ["systemctl", "show", unit, "--no-page", "--property", ",".join(props)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if out.returncode != 0:
        return {}
    d: Dict[str, str] = {}
    for line in out.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def iter_systemd_findings() -> Iterable[Finding]:
    for t in list_systemd_timers():
        unit = t["unit"]
        activates = t.get("activates", "?")
        props = show_unit_props(unit, ["Unit", "Description", "User", "NextElapseUSecRealtime", "LastTriggerUSec", "PartOf", "WantedBy", "UnitFileState"])
        srv_props: Dict[str, str] = {}
        if activates and activates.endswith(".service"):
            srv_props = show_unit_props(activates, ["User", "Group", "FragmentPath", "ExecStart", "UnitFileState"])
        user = srv_props.get("User") or props.get("User") or "root"  # por defecto systemd usa root
        schedule = props.get("NextElapseUSecRealtime") or "?"
        execstart = srv_props.get("ExecStart", "?")
        raw = f"{unit} -> {activates} :: {execstart}"
        f = Finding(
            kind="timer",
            id=f"timer:{unit}",
            source=unit,
            schedule=schedule,
            user=user,
            command=execstart,
            raw=t.get("raw", raw),
            exists_user=_user_exists(user),
            command_resolves=True,
            absolute_cmd=True,
            timer_unit=unit,
            service_unit=activates if activates.endswith(".service") else None,
        )
        if not f.exists_user:
            f.orphaned = True
            f.add("timer.user_missing", f"Usuario inexistente: {user}", "high")
        if f.service_unit and not srv_props:
            f.service_missing = True
            f.add("timer.service_missing", f"Unidad de servicio no encontrada: {f.service_unit}", "high")
        # Intentar extraer comando real del ExecStart=
        cmd = _extract_cmd_from_execstart(execstart)
        if cmd:
            # Reutilizar análisis
            aux = _analyze_cron_entry(user=user, schedule=schedule, cmd=cmd, raw=raw, source=unit, env={})
            f.command = aux.command
            f.command_resolves = aux.command_resolves
            f.absolute_cmd = aux.absolute_cmd
            f.env_vars = aux.env_vars
            f.env_vars_without_default = aux.env_vars_without_default
            f.needs_root_heuristic = aux.needs_root_heuristic
            for i in aux.issues:
                f.add(i.code, i.message, i.severity)
        else:
            f.add("timer.exec_unknown", "No se pudo determinar el comando de ExecStart", "low")
        yield f


def _extract_cmd_from_execstart(execstart: str) -> Optional[str]:
    # ExecStart típicamente: '{ path=/usr/bin/rsync ; argv[]=/usr/bin/rsync -a ... ; ... }'
    if not execstart or execstart == "?":
        return None
    # Intentar encontrar argv[]=
    m = re.search(r"argv\[\]=([^;\}]+)", execstart)
    if m:
        return m.group(1)
    # Fallback: tomar primera cita tras 'path='
    m = re.search(r"path=([^;\}]+)", execstart)
    if m:
        return m.group(1)
    return None


# ------------------------------ Salidas ----------------------------------

def findings_to_json(findings: List[Finding]) -> str:
    def _enc(o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, Path):
            return str(o)
        raise TypeError

    payload = {
        "ts": now_iso(),
        "host": os.uname().nodename if hasattr(os, "uname") else "?",
        "tool": "sabbat-syscheck",
        "module": "cronaudit",
        "version": "1.0.0",
        "findings": findings,
    }
    return json.dumps(payload, default=_enc, ensure_ascii=False, indent=2)


def print_table(findings: List[Finding]) -> None:
    # Tabular una vista rápida en texto
    headers = ["KIND", "USER", "SCHEDULE/NEXT", "SRC", "CMD (trunc)", "ISSUES"]
    print("\t".join(headers))
    for f in findings:
        issues = ",".join(sorted({i.code for i in f.issues})) or "-"
        cmd = (f.command[:70] + "…") if len(f.command) > 70 else f.command
        print("\t".join([
            f.kind,
            f.user,
            f.schedule,
            f.source,
            cmd,
            issues,
        ]))


# ------------------------------ Filtros ----------------------------------

def filter_findings(findings: List[Finding], args: argparse.Namespace) -> List[Finding]:
    out: List[Finding] = []
    pat_rx = re.compile(args.pattern, re.I) if args.pattern else None
    for f in findings:
        if args.user and f.user != args.user:
            continue
        if args.only == "cron" and f.kind != "cron":
            continue
        if args.only == "timers" and f.kind != "timer":
            continue
        if args.check_dangerous and not any(i.code == "cmd.dangerous_pattern" for i in f.issues):
            # si activado, sólo peligrosos
            if not (pat_rx and pat_rx.search(f.command)):
                continue
        if pat_rx and not pat_rx.search(f.command):
            continue
        if args.check_privileges:
            # mostrar root o mismatches
            keep = (f.user == "root") or any(i.code in ("priv.mismatch", "priv.possible_excess") for i in f.issues)
            if not keep:
                continue
        out.append(f)
    return out


# ------------------------------ Main CLI ---------------------------------

def cronaudit_main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="sabbat-syscheck cronaudit",
        description="Auditoría de cron y systemd timers",
    )
    p.add_argument("cronaudit", nargs="?", help=argparse.SUPPRESS)  # permite `sabbat-syscheck cronaudit`
    p.add_argument("--json", action="store_true", help="Salida en JSON estructurado")
    p.add_argument("--output", type=str, help="Archivo de salida (si --json)")
    p.add_argument("--pattern", type=str, help="Regex para filtrar comandos (ej. 'rm -rf|wget|curl.*pipe')")
    p.add_argument("--user", type=str, help="Restringir a un usuario concreto")
    p.add_argument("--check-dangerous", action="store_true", help="Mostrar sólo comandos sospechosos o que hagan match con --pattern")
    p.add_argument("--check-privileges", action="store_true", help="Enfocar en tareas con root o con posibles excesos/mismatch")
    p.add_argument("--only", choices=["all", "cron", "timers"], default="all", help="Restringir el origen de tareas")
    p.add_argument("--dry-run", action="store_true", help="Modo simulación: NO ejecuta nada; muestra lo que ocurriría")

    args = p.parse_args(argv)

    findings: List[Finding] = []

    # Recolectar CRON system-wide
    for path, txt in iter_system_cron_files():
        # /etc/crontab y /etc/cron.d/* incluyen USER en la línea
        for f in parse_crontab(txt, source=str(path), default_user=None):
            findings.append(f)

    # Recolectar crontabs de usuarios
    for user, txt in iter_user_crontabs():
        for f in parse_crontab(txt, source=f"user:{user}", default_user=user):
            findings.append(f)

    # Recolectar timers
    for f in iter_systemd_findings():
        findings.append(f)

    # Filtros y vistas
    findings = filter_findings(findings, args)

    # Marcar huérfanos: comando inexistente o usuario inexistente o servicio faltante
    for f in findings:
        if (not f.exists_user) or (not f.command_resolves) or f.service_missing:
            f.orphaned = True
            if not any(i.code.startswith("orphan.") for i in f.issues):
                f.add("orphan.suspect", "Elemento potencialmente huérfano o roto", "medium")

    if args.json:
        payload = findings_to_json(findings)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(payload)
            print(f"[+] JSON escrito en {args.output}")
        else:
            print(payload)
    else:
        print_table(findings)
        print(f"Total findings: {len(findings)}")

    if args.dry_run:
        # En modo simulación solo informamos — no cambia el código de salida
        return 0

    # Código de salida no-cero si hay hallazgos críticos
    has_critical = any(any(i.severity in ("high", "critical") for i in f.issues) for f in findings)
    return 2 if has_critical else 0


# Permitir invocación directa para desarrollo/pruebas
if __name__ == "__main__":
    sys.exit(cronaudit_main())

