#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sabbat-syscheck — Auditor de Configuración y Salud del Sistema (read-only)

Ahora con subcomando: `cronaudit`
  Audita tareas programadas (cron + systemd timers), con filtros, patrones
  peligrosos y salida JSON específica para SIEM.

Filosofía general:
- Sólo lectura. No cambia nada en el sistema.
- Hallazgos clasificados por riesgo: [ALTO], [MEDIO], [INFO].
- Recomendaciones claras (EN/ES) y salida JSON estable para CI/monitorización.
- Bilingüe: --lang {auto|en|es}. Auto intenta detectar por locale.
- Seguro por defecto: límites de profundidad/archivos, sin seguir enlaces simbólicos salvo que se indique.

Exit codes (modo clásico):
 0 = éxito (sin hallazgos MEDIO/ALTO)
 1 = error de uso/ejecución
 2 = hallazgos MEDIO o ALTO detectados (CI-friendly)

Exit codes (subcomando cronaudit):
 0 = sin hallazgos high/critical (o --dry-run)
 2 = hay hallazgos high/critical

Uso rápido:
  sabbat-syscheck                 # modo clásico (todos los módulos)
  sabbat-syscheck --check-ssh     # modo clásico por flags
  sabbat-syscheck cronaudit --json --output audits/cron_$(date +%Y%m%d).json
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import locale
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SCHEMA_VERSION = "1.1"

# =============================================================================
# i18n mínimo (en/es)
# =============================================================================
I18N = {
    "en": {
        "title": "System Configuration & Health Auditor",
        "running": "Running checks...",
        "done": "Done.",
        "summary": "Summary",
        "risk_high": "[HIGH]",
        "risk_med": "[MEDIUM]",
        "risk_info": "[INFO]",
        "no_findings": "No significant issues found.",
        "err": "ERROR",
        "mod_ssh": "SSH daemon configuration",
        "mod_perms": "Dangerous permissions in critical paths",
        "mod_users": "Users & authentication",
        "mod_cron": "Cron jobs security",
        "rec_fix": "Recommendation",
        "path": "Path",
    },
    "es": {
        "title": "Auditor de Configuración y Salud del Sistema",
        "running": "Ejecutando comprobaciones...",
        "done": "Hecho.",
        "summary": "Resumen",
        "risk_high": "[ALTO]",
        "risk_med": "[MEDIO]",
        "risk_info": "[INFO]",
        "no_findings": "No se han detectado problemas relevantes.",
        "err": "ERROR",
        "mod_ssh": "Configuración del demonio SSH",
        "mod_perms": "Permisos peligrosos en rutas críticas",
        "mod_users": "Usuarios y autenticación",
        "mod_cron": "Seguridad de tareas cron",
        "rec_fix": "Recomendación",
        "path": "Ruta",
    },
}

# Recomendaciones (texto breve en ambos idiomas)
RECS = {
    "ssh_permit_root_yes": {
        "en": "Set PermitRootLogin to 'no' or 'prohibit-password'.",
        "es": "Ajusta PermitRootLogin a 'no' o 'prohibit-password'.",
    },
    "ssh_password_auth_yes": {
        "en": "Disable PasswordAuthentication; prefer public keys.",
        "es": "Deshabilita PasswordAuthentication; usa claves públicas.",
    },
    "ssh_protocol1": {
        "en": "Protocol 1 is obsolete; ensure only modern algorithms are used.",
        "es": "Protocol 1 está obsoleto; usa sólo algoritmos modernos.",
    },
    "ssh_empty_passwords": {
        "en": "Set PermitEmptyPasswords to 'no'.",
        "es": "Establece PermitEmptyPasswords en 'no'.",
    },
    "ssh_x11_forwarding": {
        "en": "Disable X11Forwarding on servers unless strictly required.",
        "es": "Deshabilita X11Forwarding salvo necesidad estricta.",
    },
    "ssh_maxauthtries": {
        "en": "Lower MaxAuthTries (e.g., 3–4).",
        "es": "Reduce MaxAuthTries (p.ej., 3–4).",
    },
    "perm_world_writable": {
        "en": "Remove world-writable bit (chmod o-w) or tighten to 750/640.",
        "es": "Quita escritura global (chmod o-w) o ajusta a 750/640.",
    },
    "perm_777": {
        "en": "Avoid 777; set the minimum required permissions.",
        "es": "Evita 777; establece los mínimos necesarios.",
    },
    "uid0_multiple": {
        "en": "Only 'root' should have UID 0; change others to non-privileged UIDs.",
        "es": "Sólo 'root' debe tener UID 0; cambia el resto a UIDs no privilegiados.",
    },
    "user_no_password": {
        "en": "Lock or set strong passwords; use shadow with hashing.",
        "es": "Bloquea o establece contraseñas fuertes; usa shadow con hash.",
    },
    "login_shell_sysacct": {
        "en": "System accounts should use /usr/sbin/nologin or /bin/false.",
        "es": "Cuentas de sistema con /usr/sbin/nologin o /bin/false.",
    },
    "cron_tmp": {
        "en": "Avoid running from /tmp or writable dirs; move scripts to /usr/local/bin.",
        "es": "Evita ejecutar desde /tmp o directorios escribibles; mueve scripts a /usr/local/bin.",
    },
    "cron_relative": {
        "en": "Use absolute paths in cron entries.",
        "es": "Usa rutas absolutas en las entradas de cron.",
    },
    "cron_world_writable": {
        "en": "Scripts referenced by cron must not be world-writable.",
        "es": "Los scripts usados por cron no deben ser escribibles por todos.",
    },
}

# =============================================================================
# Modelo de hallazgos del modo clásico
# =============================================================================
@dataclasses.dataclass
class Finding:
    module: str
    risk: str  # HIGH|MEDIUM|INFO
    message_en: str
    message_es: str
    path: Optional[str] = None
    recommendation_key: Optional[str] = None
    evidence: Optional[str] = None

    def to_dict(self, lang: str) -> Dict[str, object]:
        msg = self.message_en if lang == "en" else self.message_es
        rec = (
            RECS.get(self.recommendation_key, {}).get(lang)
            if self.recommendation_key
            else None
        )
        return {
            "module": self.module,
            "risk": self.risk,
            "message": msg,
            "path": self.path,
            "recommendation": rec,
            "evidence": self.evidence,
        }

# =============================================================================
# Utilidades comunes
# =============================================================================

def detect_lang(user_choice: str) -> str:
    if user_choice in {"en", "es"}:
        return user_choice
    try:
        loc = locale.getlocale()[0] or ""
    except Exception:
        loc = ""
    return "es" if loc.lower().startswith("es") else "en"


def fmt_risk(lang: str, risk: str) -> str:
    if lang == "en":
        return {"HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "INFO": "[INFO]"}[risk]
    return {"HIGH": "[ALTO]", "MEDIUM": "[MEDIO]", "INFO": "[INFO]"}[risk]

# =============================================================================
# Módulo: SSH
# =============================================================================

SSH_PATH = Path("/etc/ssh/sshd_config")

_SSH_PATTERNS = {
    "PermitRootLogin": re.compile(r"^\s*PermitRootLogin\s+(?P<val>\S+)", re.I),
    "PasswordAuthentication": re.compile(r"^\s*PasswordAuthentication\s+(?P<val>\S+)", re.I),
    "PermitEmptyPasswords": re.compile(r"^\s*PermitEmptyPasswords\s+(?P<val>\S+)", re.I),
    "Protocol": re.compile(r"^\s*Protocol\s+(?P<val>\S+)", re.I),  # legacy
    "X11Forwarding": re.compile(r"^\s*X11Forwarding\s+(?P<val>\S+)", re.I),
    "MaxAuthTries": re.compile(r"^\s*MaxAuthTries\s+(?P<val>\d+)", re.I),
}


def check_ssh(lang: str) -> List[Finding]:
    findings: List[Finding] = []
    if not SSH_PATH.exists():
        return findings

    try:
        lines = SSH_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception as e:
        return [Finding(
            module="ssh",
            risk="INFO",
            message_en=f"Could not read {SSH_PATH}: {e}",
            message_es=f"No se pudo leer {SSH_PATH}: {e}",
        )]

    config: Dict[str, str] = {}
    for ln in lines:
        if ln.strip().startswith("#") or not ln.strip():
            continue
        for key, pat in _SSH_PATTERNS.items():
            m = pat.search(ln)
            if m:
                config[key] = m.group("val").strip()

    if config.get("PermitRootLogin", "").lower() in {"yes", "without-password"}:
        findings.append(Finding(
            module="ssh",
            risk="HIGH",
            message_en="PermitRootLogin is enabled.",
            message_es="PermitRootLogin está habilitado.",
            path=str(SSH_PATH),
            recommendation_key="ssh_permit_root_yes",
            evidence=f"PermitRootLogin {config.get('PermitRootLogin')}"
        ))

    if config.get("PasswordAuthentication", "").lower() == "yes":
        findings.append(Finding(
            module="ssh",
            risk="MEDIUM",
            message_en="PasswordAuthentication is enabled.",
            message_es="PasswordAuthentication está habilitado.",
            path=str(SSH_PATH),
            recommendation_key="ssh_password_auth_yes",
            evidence=f"PasswordAuthentication {config.get('PasswordAuthentication')}"
        ))

    if config.get("PermitEmptyPasswords", "").lower() == "yes":
        findings.append(Finding(
            module="ssh",
            risk="HIGH",
            message_en="PermitEmptyPasswords is enabled.",
            message_es="PermitEmptyPasswords está habilitado.",
            path=str(SSH_PATH),
            recommendation_key="ssh_empty_passwords",
        ))

    proto = config.get("Protocol")
    if proto and proto.strip() == "1":
        findings.append(Finding(
            module="ssh",
            risk="HIGH",
            message_en="SSH Protocol 1 configured (obsolete).",
            message_es="SSH Protocol 1 configurado (obsoleto).",
            path=str(SSH_PATH),
            recommendation_key="ssh_protocol1",
        ))

    if config.get("X11Forwarding", "").lower() == "yes":
        findings.append(Finding(
            module="ssh",
            risk="MEDIUM",
            message_en="X11Forwarding is enabled.",
            message_es="X11Forwarding está habilitado.",
            path=str(SSH_PATH),
            recommendation_key="ssh_x11_forwarding",
        ))

    try:
        tries = int(config.get("MaxAuthTries", "6"))
        if tries > 6:
            findings.append(Finding(
                module="ssh",
                risk="MEDIUM",
                message_en=f"MaxAuthTries is {tries} (consider lowering).",
                message_es=f"MaxAuthTries es {tries} (considera reducir).",
                path=str(SSH_PATH),
                recommendation_key="ssh_maxauthtries",
            ))
    except ValueError:
        pass

    return findings


# =============================================================================
# Módulo: Permisos peligrosos
# =============================================================================

CRITICAL_PATHS_DEFAULT = [
    Path("/etc"),
    Path("/var"),
    Path("/usr/bin"),
]

EXCLUDES_DEFAULT = [
    Path("/var/lib/docker"),
    Path("/var/lib/snapd"),
    Path("/snap"),
]


def is_world_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWOTH)


def is_perm_777(mode: int) -> bool:
    return stat.S_IMODE(mode) == 0o777

def has_sticky(mode: int) -> bool:
    return bool(mode & stat.S_ISVTX)


def safe_scandir(base: Path):
    with os.scandir(base) as it:
        for entry in it:
            try:
                yield entry
            except PermissionError:
                continue


def check_perms(lang: str, roots: List[Path], excludes: List[Path], max_files: int, max_depth: int) -> List[Finding]:
    findings: List[Finding] = []
    scanned = 0
    excl_set = {p.resolve() for p in excludes}

    def _should_skip(p: Path) -> bool:
        try:
            rp = p.resolve()
        except Exception:
            return True
        return any(str(rp).startswith(str(e)) for e in excl_set)

    def _walk(root: Path, depth: int):
        nonlocal scanned
        if depth > max_depth:
            return
        if _should_skip(root):
            return
        try:
            st = root.lstat()
        except (FileNotFoundError, PermissionError, OSError):
            return
        if stat.S_ISREG(st.st_mode):
            scanned += 1
            if is_world_writable(st.st_mode):
                findings.append(Finding(
                    module="perms",
                    risk="HIGH" if is_perm_777(st.st_mode) else "MEDIUM",
                    message_en="World-writable file detected.",
                    message_es="Fichero escribible por todos detectado.",
                    path=str(root),
                    recommendation_key="perm_world_writable" if not is_perm_777(st.st_mode) else "perm_777",
                ))
            return
        if stat.S_ISDIR(st.st_mode):
            scanned += 1
            if is_world_writable(st.st_mode):
                sticky = has_sticky(st.st_mode)
                findings.append(Finding(
                    module="perms",
                    risk="INFO" if sticky else "MEDIUM",
                    message_en="World-writable directory detected.",
                    message_es="Directorio escribible por todos detectado.",
                    path=str(root),
                    recommendation_key="perm_world_writable",
                ))
            try:
                for entry in safe_scandir(root):
                    if scanned >= max_files:
                        return
                    if entry.is_symlink():
                        continue
                    _walk(Path(entry.path), depth + 1)
                    if scanned >= max_files:
                        return
            except PermissionError:
                return

    for r in roots:
        if scanned >= max_files:
            break
        _walk(r, depth=0)
        if scanned >= max_files:
            break

    return findings


# =============================================================================
# Módulo: Usuarios
# =============================================================================

PASSWD = Path("/etc/passwd")
SHADOW = Path("/etc/shadow")


def parse_passwd() -> List[Tuple[str, int, str]]:
    out = []
    try:
        for line in PASSWD.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 7:
                user = parts[0]
                uid = int(parts[2])
                shell = parts[6]
                out.append((user, uid, shell))
    except Exception:
        pass
    return out


def parse_shadow() -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for line in SHADOW.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 2:
                out[parts[0]] = parts[1]
    except Exception:
        pass
    return out


def check_users(lang: str) -> List[Finding]:
    findings: List[Finding] = []
    users = parse_passwd()
    shadow = parse_shadow()

    uid0 = [u for (u, uid, _shell) in users if uid == 0 and u != "root"]
    if uid0:
        findings.append(Finding(
            module="users",
            risk="HIGH",
            message_en=f"Additional UID 0 accounts: {', '.join(uid0)}",
            message_es=f"Cuentas adicionales con UID 0: {', '.join(uid0)}",
            recommendation_key="uid0_multiple",
        ))

    empty_pw = []
    for (u, _uid, _shell) in users:
        pw = shadow.get(u)
        if pw is None:
            continue
        if pw == "":
            empty_pw.append(u)
    if empty_pw:
        findings.append(Finding(
            module="users",
            risk="HIGH",
            message_en=f"Users without password: {', '.join(empty_pw)}",
            message_es=f"Usuarios sin contraseña: {', '.join(empty_pw)}",
            recommendation_key="user_no_password",
        ))

    bad_shell = []
    for (u, uid, shell) in users:
        if 1 <= uid < 1000 and shell.strip() not in {"/usr/sbin/nologin", "/bin/false", "/sbin/nologin"}:
            if shell.strip().endswith("sh") or shell.strip().endswith("bash"):
                bad_shell.append(u)
    if bad_shell:
        findings.append(Finding(
            module="users",
            risk="MEDIUM",
            message_en=f"System accounts with interactive shells: {', '.join(bad_shell)}",
            message_es=f"Cuentas de sistema con shells interactivos: {', '.join(bad_shell)}",
            recommendation_key="login_shell_sysacct",
        ))

    return findings


# =============================================================================
# Módulo: Cron (clásico)
# =============================================================================

CRON_PATHS = [
    Path("/etc/crontab"),
    Path("/etc/cron.d"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.monthly"),
    Path("/etc/cron.weekly"),
    Path("/var/spool/cron"),
    Path("/var/spool/cron/crontabs"),
]

SHELL_KEYWORDS = {"then", "do", "fi", "in", "case", "esac", "if", "while", "for", "time", "exit"}
REDIR_RE = re.compile(r"^\d?>&?\d?$")
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _iter_cron_files() -> List[Path]:
    out: List[Path] = []
    for base in CRON_PATHS:
        if base.is_file():
            out.append(base)
        elif base.is_dir():
            try:
                for root, _dirs, files in os.walk(base, followlinks=False):
                    for f in files:
                        out.append(Path(root) / f)
            except Exception:
                continue
    return out


def _is_system_style(path: Path) -> bool:
    try:
        if path.parent.name == "cron.d":
            return True
        return path.is_absolute() and path.as_posix() == "/etc/crontab"
    except Exception:
        return False

def _extract_cmd(line: str, system_style: bool) -> Optional[str]:
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if ASSIGN_RE.match(s):
        return None
    parts = s.split()
    if not parts:
        return None
    if system_style and len(parts) >= 6:
        return " ".join(parts[6:])
    if not system_style and len(parts) >= 5:
        return " ".join(parts[5:])
    if parts[0].startswith("@"):
        idx = 2 if (system_style and len(parts) >= 2) else 1
        return " ".join(parts[idx:]) if len(parts) > idx else None
    return None


def _first_token_classic(cmd: str) -> Optional[str]:
    try:
        toks = shlex.split(cmd)
    except Exception:
        toks = cmd.split()
    for t0 in toks:
        if not t0:
            continue
        if t0 in SHELL_KEYWORDS:
            continue
        if REDIR_RE.match(t0):
            continue
        if t0.startswith("$") or ASSIGN_RE.match(t0):
            continue
        if t0.startswith("-"):
            continue
        return t0
    return None


def check_cron(lang: str) -> List[Finding]:
    findings: List[Finding] = []
    cron_files = _iter_cron_files()
    for cf in cron_files:
        system_style = _is_system_style(cf)
        try:
            content = cf.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        for ln in content:
            cmd = _extract_cmd(ln, system_style)
            if not cmd:
                continue
            t0 = _first_token_classic(cmd)
            if not t0:
                continue

            if t0.startswith("/"):
                target = Path(t0)

                if str(target).startswith("/tmp/"):
                    findings.append(Finding(
                        module="cron",
                        risk="HIGH",
                        message_en=f"Cron job runs from /tmp: {t0}",
                        message_es=f"Cron ejecuta desde /tmp: {t0}",
                        recommendation_key="cron_tmp",
                        path=str(cf),
                    ))

                try:
                    if target.exists():
                        st = target.lstat()
                        if is_world_writable(st.st_mode):
                            findings.append(Finding(
                                module="cron",
                                risk="HIGH",
                                message_en=f"Cron references world-writable script: {target}",
                                message_es=f"Cron referencia script escribible por todos: {target}",
                                recommendation_key="cron_world_writable",
                                path=str(cf),
                            ))
                except Exception:
                    pass

            else:
                findings.append(Finding(
                    module="cron",
                    risk="MEDIUM",
                    message_en=f"Cron job uses relative path: {t0}",
                    message_es=f"Cron usa ruta relativa: {t0}",
                    recommendation_key="cron_relative",
                    path=str(cf),
                ))
    return findings

# =============================================================================
# Agregador / CLI (modo clásico)
# =============================================================================

def run_checks(args) -> Tuple[List[Finding], Dict[str, object]]:
    lang = detect_lang(args.lang)
    all_findings: List[Finding] = []

    if args.check_ssh or args.all:
        all_findings.extend(check_ssh(lang))
    if args.check_perms or args.all:
        roots = [Path(p) for p in (args.roots or [])] or CRITICAL_PATHS_DEFAULT
        excludes = [Path(p) for p in (args.exclude or [])] or EXCLUDES_DEFAULT
        all_findings.extend(
            check_perms(lang, roots=roots, excludes=excludes, max_files=args.max_files, max_depth=args.max_depth)
        )
    if args.check_users or args.all:
        all_findings.extend(check_users(lang))
    if args.check_cron or args.all:
        all_findings.extend(check_cron(lang))

    high = sum(1 for f in all_findings if f.risk == "HIGH")
    med  = sum(1 for f in all_findings if f.risk == "MEDIUM")
    info = sum(1 for f in all_findings if f.risk == "INFO")

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "lang": lang,
        "parameters_used": {
            "roots": [str(p) for p in ([Path(p) for p in (args.roots or [])] or CRITICAL_PATHS_DEFAULT)],
            "exclude": [str(p) for p in ([Path(p) for p in (args.exclude or [])] or EXCLUDES_DEFAULT)],
            "max_files": args.max_files,
            "max_depth": args.max_depth,
            "modules": [m for m, cond in (
                ("ssh", args.check_ssh or args.all),
                ("perms", args.check_perms or args.all),
                ("users", args.check_users or args.all),
                ("cron", args.check_cron or args.all),
            ) if cond],
        },
        "summary": {"high": high, "medium": med, "info": info, "total": len(all_findings)},
        "findings": [f.to_dict(lang) for f in all_findings],
    }

    return all_findings, report


def _group_key(f: Finding, lang: str) -> Tuple[str, str, Optional[str], str]:
    if f.recommendation_key == "cron_relative":
        title = "Cron usa ruta relativa" if lang == "es" else "Cron job uses relative path"
        return (f.module, f.risk, f.recommendation_key, title)
    if f.recommendation_key == "cron_tmp":
        title = "Cron ejecuta desde /tmp" if lang == "es" else "Cron job runs from /tmp"
        return (f.module, f.risk, f.recommendation_key, title)
    if f.recommendation_key == "cron_world_writable":
        title = ("Cron referencia script escribible por todos"
                 if lang == "es" else "Cron references world-writable script")
        return (f.module, f.risk, f.recommendation_key, title)

    if f.recommendation_key in {"perm_world_writable", "perm_777"}:
        is_dir = "directory" in f.message_en.lower() or "directorio" in f.message_es.lower()
        if lang == "es":
            title = "Directorio escribible por todos" if is_dir else "Fichero escribible por todos"
        else:
            title = "World-writable directory" if is_dir else "World-writable file"
        return (f.module, f.risk, f.recommendation_key, title)

    title = f.message_es if lang == "es" else f.message_en
    return (f.module, f.risk, f.recommendation_key, title)

def print_raw(findings: List[Finding], lang: str, jsonl: bool) -> None:
    if jsonl:
        for f in findings:
            print(json.dumps(f.to_dict(lang), ensure_ascii=False))
        return
    for f in findings:
        msg = f.message_es if lang == "es" else f.message_en
        print("\t".join([
            f.risk,
            f.module,
            msg,
            f.path or "",
            f.evidence or "",
        ]))

def print_human(findings: List[Finding], lang: str, group: bool, group_show: int) -> None:
    t = I18N[lang]
    if not findings:
        print(t["no_findings"])
        return

    if not group:
        for f in findings:
            risk = fmt_risk(lang, f.risk)
            msg  = f.message_es if lang == "es" else f.message_en
            rec  = RECS.get(f.recommendation_key, {}).get(lang) if f.recommendation_key else None
            line = f"{risk} [{f.module}] {msg}"
            if f.path:
                line += f" — {t['path']}: {f.path}"
            print(line)
            if rec:
                print(f"  {t['rec_fix']}: {rec}")
            if f.evidence:
                print(f"  evidence: {f.evidence}")
        return

    groups: Dict[Tuple[str, str, Optional[str], str], List[Finding]] = {}
    for f in findings:
        k = _group_key(f, lang)
        groups.setdefault(k, []).append(f)

    sorted_keys = sorted(groups.keys(), key=lambda k: (-len(groups[k]), k[0], k[3]))

    for k in sorted_keys:
        items = groups[k]
        module, _risk_code, rec_key, title = k
        risk = fmt_risk(lang, items[0].risk)
        rec  = RECS.get(rec_key, {}).get(lang) if rec_key else None

        print(f"{risk} [{module}] {title}  ({'nº' if lang=='es' else 'count'}: {len(items)})")
        if rec:
            print(f"  {t['rec_fix']}: {rec}")

        shown = 0
        for it in items:
            if it.path:
                print(f"  - {t['path']}: {it.path}")
                shown += 1
                if shown >= group_show:
                    break

# =============================================================================
# Subcomando: CRON AUDIT (cronaudit)
# =============================================================================

CA_SEVERITY = ("info", "low", "medium", "high", "critical")

def _ca_now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat()

def _ca_which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

CA_DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/(\\s|$)",
    r"rm\s+-rf\s+[^;|]*\*",
    r"curl\s+[^|\n]*\|\s*(sh|bash)\b",
    r"wget\s+[^|\n]*\|\s*(sh|bash)\b",
    r"(curl|wget)\s+http://",
    r"chmod\s+777\b",
    r"chown\s+[^|;]*\broot\b\s+/",
    r"base64\s+-d\s*\|\s*(sh|bash)\b",
    r"python\s+-c\s*\"?exec\(.*base64",
    r"nc\s+.*\s+-e\s+",
    r"bash\s+-i\s+>&\s+/dev/tcp/",
    r"xmrig|minerd|ethminer|cpuminer",
]
CA_DANGEROUS_RX = re.compile("|".join(f"({p})" for p in CA_DANGEROUS_PATTERNS), re.I)
CA_ENV_VAR_RX = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([^}:]+)(?::-[^}]+)?\}")
CA_CRON_LINE_RX = re.compile(r"^\s*(?P<m1>\S+)\s+(?P<m2>\S+)\s+(?P<m3>\S+)\s+(?P<m4>\S+)\s+(?P<m5>\S+)(?:\s+(?P<user>\S+))?\s+(?P<cmd>.+)$")
CA_SYSTEMD_COL_SPLIT_RX = re.compile(r"\s{2,}")

@dataclass
class CAIssue:
    code: str
    message: str
    severity: str

@dataclass
class CAFinding:
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
    issues: List[CAIssue] = field(default_factory=list)
    def add(self, code: str, message: str, severity: str) -> None:
        self.issues.append(CAIssue(code, message, severity))

# Recolección CRON
CA_CRON_SOURCES = [Path("/etc/crontab"), Path("/etc/cron.d")]
CA_SPOOL_PATHS = [Path("/var/spool/cron"), Path("/var/spool/cron/crontabs")]

def _ca_iter_system_cron_files() -> Iterable[Tuple[Path, str]]:
    for path in CA_CRON_SOURCES:
        if path.is_file():
            yield (path, path.read_text(errors="ignore"))
        elif path.is_dir():
            for f in sorted(path.glob("*")):
                if f.is_file():
                    try:
                        yield (f, f.read_text(errors="ignore"))
                    except Exception:
                        continue

def _ca_iter_user_crontabs() -> Iterable[Tuple[str, str]]:
    for base in CA_SPOOL_PATHS:
        if base.is_dir():
            for f in sorted(base.glob("*")):
                try:
                    yield (f.name, f.read_text(errors="ignore"))
                except Exception:
                    continue
    try:
        import pwd as _pwd
        for p in _pwd.getpwall():
            user = p.pw_name
            if p.pw_shell in ("/usr/sbin/nologin", "/bin/false", ""):
                continue
            try:
                out = subprocess.run(["crontab", "-l", "-u", user], check=False,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if out.returncode == 0 and out.stdout.strip():
                    yield (user, out.stdout)
            except FileNotFoundError:
                break
    except Exception:
        pass

def _ca_user_exists(user: Optional[str]) -> bool:
    if not user or user == "?":
        return False
    try:
        import pwd as _pwd
        _pwd.getpwnam(user)
        return True
    except KeyError:
        return False

def _ca_first_token(cmd: str) -> str:
    try:
        parts = shlex.split(cmd, posix=True)
        return parts[0] if parts else ""
    except Exception:
        return cmd.split()[0] if cmd.split() else ""

def _ca_analyze_cron_entry(*, user: str, schedule: str, cmd: str, raw: str, source: str, env: Dict[str, str]) -> CAFinding:
    token = _ca_first_token(cmd)
    token_is_abs = token.startswith("/")
    token_resolves = bool(_ca_which(token)) if not token_is_abs else Path(token).exists()
    f = CAFinding(
        kind="cron",
        id=f"cron:{source}:{user}:{hash(raw)}",
        source=source,
        schedule=schedule,
        user=user,
        command=cmd,
        raw=raw,
        exists_user=_ca_user_exists(user),
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
    vars_found = [m.group(1) or m.group(2) for m in CA_ENV_VAR_RX.finditer(cmd)]
    f.env_vars = vars_found
    without_default = []
    for var in vars_found:
        if not re.search(rf"\$\{{{re.escape(var)}:-[^}}]+\}}", cmd):
            without_default.append(var)
    f.env_vars_without_default = without_default
    if without_default:
        f.add("env.unsanitized", f"Variables sin default: {', '.join(without_default)}", "low")
    if CA_DANGEROUS_RX.search(cmd):
        f.add("cmd.dangerous_pattern", "Se detectaron patrones peligrosos", "critical")
    if _ca_needs_root(cmd):
        f.needs_root_heuristic = True
        if user != "root":
            f.add("priv.mismatch", "La tarea parece requerir root pero no se ejecuta como root", "medium")
    else:
        if user == "root":
            f.add("priv.possible_excess", "Tarea ejecutándose como root sin indicios claros de necesidad", "low")
    return f

def _ca_needs_root(cmd: str) -> bool:
    cmd_l = cmd.lower()
    if re.search(r">\s*/(etc|root|var/lib|var/spool|usr/local/sbin|sbin)/", cmd_l):
        return True
    if re.search(r"\b(chown|chmod)\b.*\s/(etc|root|var/lib|var/spool)/", cmd_l):
        return True
    if re.search(r"\b(80|53|25|110|143|443|22)\b", cmd_l) and re.search(r"\b(nc|ncat|socat|python\s+-m\s+http\.server|busybox\s+httpd|sshd)\b", cmd_l):
        return True
    return False

def _ca_parse_crontab(text: str, source: str, default_user: Optional[str]) -> Iterable[CAFinding]:
    env: Dict[str, str] = {}
    for line in text.splitlines():
        raw = line.rstrip("\n")
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", raw):
            k, v = raw.split("=", 1)
            env[k.strip()] = v.strip()
            continue
        m = CA_CRON_LINE_RX.match(raw)
        if not m:
            f = CAFinding(
                kind="cron",
                id=f"{source}:{hash(raw)}",
                source=source,
                schedule="?",
                user=default_user or "?",
                command=raw,
                raw=raw,
                exists_user=_ca_user_exists(default_user) if default_user else False,
                command_resolves=False,
                absolute_cmd=False,
            )
            f.add("cron.syntax", "Línea de cron no válida", "medium")
            yield f
            continue
        user = m.group("user") or (default_user or "?")
        sched = " ".join(m.group(g) for g in ["m1", "m2", "m3", "m4", "m5"])
        cmd = m.group("cmd").strip()
        yield _ca_analyze_cron_entry(user=user, schedule=sched, cmd=cmd, raw=raw, source=source, env=env)

# Timers systemd

def _ca_list_systemd_timers() -> List[Dict[str, str]]:
    timers: List[Dict[str, str]] = []
    try:
        out = subprocess.run(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"],
                             check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if out.returncode != 0:
            return timers
        for line in out.stdout.splitlines():
            if not line.strip():
                continue
            cols = CA_SYSTEMD_COL_SPLIT_RX.split(line.strip())
            if not cols:
                continue
            unit = cols[-2] if len(cols) >= 2 else "?"
            activates = cols[-1] if len(cols) >= 1 else "?"
            timers.append({"unit": unit, "activates": activates, "raw": line})
    except FileNotFoundError:
        pass
    return timers

def _ca_show_unit_props(unit: str, props: List[str]) -> Dict[str, str]:
    out = subprocess.run(["systemctl", "show", unit, "--no-page", "--property", ",".join(props)],
                         check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if out.returncode != 0:
        return {}
    d: Dict[str, str] = {}
    for line in out.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d

def _ca_extract_cmd_from_execstart(execstart: str) -> Optional[str]:
    if not execstart or execstart == "?":
        return None
    m = re.search(r"argv\[]=([^;\}]+)", execstart)
    if m:
        return m.group(1)
    m = re.search(r"path=([^;\}]+)", execstart)
    if m:
        return m.group(1)
    return None

def _ca_iter_systemd_findings() -> Iterable[CAFinding]:
    for t in _ca_list_systemd_timers():
        unit = t["unit"]
        activates = t.get("activates", "?")
        props = _ca_show_unit_props(unit, ["Unit", "Description", "User", "NextElapseUSecRealtime", "LastTriggerUSec", "PartOf", "WantedBy", "UnitFileState"])
        srv_props: Dict[str, str] = {}
        if activates and activates.endswith(".service"):
            srv_props = _ca_show_unit_props(activates, ["User", "Group", "FragmentPath", "ExecStart", "UnitFileState"])
        user = srv_props.get("User") or props.get("User") or "root"
        schedule = props.get("NextElapseUSecRealtime") or "?"
        execstart = srv_props.get("ExecStart", "?")
        raw = f"{unit} -> {activates} :: {execstart}"
        f = CAFinding(
            kind="timer",
            id=f"timer:{unit}",
            source=unit,
            schedule=schedule,
            user=user,
            command=execstart,
            raw=t.get("raw", raw),
            exists_user=_ca_user_exists(user),
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
        cmd = _ca_extract_cmd_from_execstart(execstart)
        if cmd:
            aux = _ca_analyze_cron_entry(user=user, schedule=schedule, cmd=cmd, raw=raw, source=unit, env={})
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

# Salidas cronaudit

def _ca_findings_to_json(findings: List[CAFinding]) -> str:
    def _enc(o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, Path):
            return str(o)
        raise TypeError
    payload = {
        "ts": _ca_now_iso(),
        "host": os.uname().nodename if hasattr(os, "uname") else "?",
        "tool": "sabbat-syscheck",
        "module": "cronaudit",
        "version": "1.0.0",
        "findings": findings,
    }
    return json.dumps(payload, default=_enc, ensure_ascii=False, indent=2)

def _ca_print_table(findings: List[CAFinding]) -> None:
    headers = ["KIND", "USER", "SCHEDULE/NEXT", "SRC", "CMD (trunc)", "ISSUES"]
    print("\t".join(headers))
    for f in findings:
        issues = ",".join(sorted({i.code for i in f.issues})) or "-"
        cmd = (f.command[:70] + "…") if len(f.command) > 70 else f.command
        print("\t".join([f.kind, f.user, f.schedule, f.source, cmd, issues]))

def _ca_filter_findings(findings: List[CAFinding], args: argparse.Namespace) -> List[CAFinding]:
    out: List[CAFinding] = []
    pat_rx = re.compile(args.pattern, re.I) if args.pattern else None
    for f in findings:
        if args.user and f.user != args.user:
            continue
        if args.only == "cron" and f.kind != "cron":
            continue
        if args.only == "timers" and f.kind != "timer":
            continue
        if args.check_dangerous and not any(i.code == "cmd.dangerous_pattern" for i in f.issues):
            if not (pat_rx and pat_rx.search(f.command)):
                continue
        if pat_rx and not pat_rx.search(f.command):
            continue
        if args.check_privileges:
            keep = (f.user == "root") or any(i.code in ("priv.mismatch", "priv.possible_excess") for i in f.issues)
            if not keep:
                continue
        out.append(f)
    return out

def cronaudit_add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="Salida en JSON estructurado")
    p.add_argument("--output", type=str, help="Archivo de salida (si --json)")
    p.add_argument("--pattern", type=str, help="Regex para filtrar comandos (ej. 'rm -rf|wget|curl.*pipe')")
    p.add_argument("--user", type=str, help="Restringir a un usuario concreto")
    p.add_argument("--check-dangerous", action="store_true",
                   help="Mostrar sólo comandos sospechosos o que casen con --pattern")
    p.add_argument("--check-privileges", action="store_true",
                   help="Enfocar en tareas con root o con posibles excesos/mismatch")
    p.add_argument("--only", choices=["all", "cron", "timers"], default="all",
                   help="Restringir el origen de tareas")
    p.add_argument("--dry-run", action="store_true",
                   help="Modo simulación: NO ejecuta nada; muestra lo que ocurriría")

def cronaudit_main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="sabbat-syscheck cronaudit",
        description="Auditoría de cron y systemd timers",
    )
    cronaudit_add_arguments(p)
    args = p.parse_args(argv)
    findings: List[CAFinding] = []
    for path, txt in _ca_iter_system_cron_files():
        for f in _ca_parse_crontab(txt, source=str(path), default_user=None):
            findings.append(f)
    for user, txt in _ca_iter_user_crontabs():
        for f in _ca_parse_crontab(txt, source=f"user:{user}", default_user=user):
            findings.append(f)
    for f in _ca_iter_systemd_findings():
        findings.append(f)
    findings = _ca_filter_findings(findings, args)
    for f in findings:
        if (not f.exists_user) or (not f.command_resolves) or f.service_missing:
            f.orphaned = True
            if not any(i.code.startswith("orphan.") for i in f.issues):
                f.add("orphan.suspect", "Elemento potencialmente huérfano o roto", "medium")
    if args.json:
        payload = _ca_findings_to_json(findings)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(payload)
            print(f"[+] JSON escrito en {args.output}")
        else:
            print(payload)
    else:
        _ca_print_table(findings)
        print(f"Total findings: {len(findings)}")
    if args.dry_run:
        return 0
    has_critical = any(any(i.severity in ("high", "critical") for i in f.issues) for f in findings)
    return 2 if has_critical else 0

# =============================================================================
# Parser con subparsers y main
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sabbat-syscheck",
        description="Read-only auditor for common Linux security misconfigurations.",
    )
    # opciones globales (modo clásico)
    p.add_argument("--lang", choices=["auto", "en", "es"], default="auto", help="Language of output")
    p.add_argument("--json", action="store_true", help="Emit JSON to stdout")
    p.add_argument("--jsonl", action="store_true", help="Emit JSON Lines (one finding per line)")
    p.add_argument("--raw", action="store_true", help="Raw TSV to stdout (RISK\tMODULE\tMESSAGE\tPATH\tEVIDENCE)")
    p.add_argument("--check-ssh", dest="check_ssh", action="store_true", help="Audit sshd_config")
    p.add_argument("--check-perms", dest="check_perms", action="store_true", help="Scan dangerous permissions")
    p.add_argument("--check-users", dest="check_users", action="store_true", help="Review /etc/passwd & /etc/shadow")
    p.add_argument("--check-cron", dest="check_cron", action="store_true", help="Analyze system/user crontabs")
    p.add_argument("--all", action="store_true", help="Run all modules (default if none selected)")
    p.add_argument("--roots", nargs="*", help="Roots to scan for --check-perms (default: /etc /var /usr/bin)")
    p.add_argument("--exclude", nargs="*", help="Paths to exclude from --check-perms")
    p.add_argument("--max-files", type=int, default=100000, help="Max filesystem entries to scan")
    p.add_argument("--max-depth", type=int, default=12, help="Max directory depth to recurse")
    p.add_argument("--no-group", dest="group", action="store_false", default=True, help="Disable grouping in human output")
    p.add_argument("--group", dest="group", action="store_true", help="Enable grouping in human output (default)")
    p.add_argument("--group-show", type=int, default=5, help="Examples to show per group (paths)")

    # subcomandos
    sub = p.add_subparsers(dest="subcmd", metavar="subcommand")
    sp_cron = sub.add_parser("cronaudit", help="Audit cron + systemd timers")
    cronaudit_add_arguments(sp_cron)

    return p

def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    args = parser.parse_args(argv)

    # Subcomando
    if getattr(args, "subcmd", None) == "cronaudit":
        sub_argv = []
        # Recolectamos las opciones del subcomando desde args
        for name in ("json","output","pattern","user","check_dangerous","check_privileges","only","dry_run"):
            attr = name if name not in ("check_dangerous","check_privileges","dry_run") else name
            val = getattr(args, attr, None)
            flag = "--" + name.replace("_", "-")
            if isinstance(val, bool):
                if val:
                    sub_argv.append(flag)
            elif val is not None:
                sub_argv.extend([flag, str(val)])
        return cronaudit_main(sub_argv)

    # Modo clásico
    if not (args.check_ssh or args.check_perms or args.check_users or args.check_cron or args.all):
        args.all = True

    try:
        findings, report = run_checks(args)
        lang = detect_lang(args.lang)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        elif getattr(args, 'jsonl', False) or getattr(args, 'raw', False):
            print_raw(findings, lang, jsonl=getattr(args, 'jsonl', False))
        else:
            print_human(findings, lang, group=getattr(args, 'group', True), group_show=getattr(args, 'group_show', 5))
        exit_code = 0 if not any(f.risk in {"HIGH", "MEDIUM"} for f in findings) else 2
        return exit_code
    except KeyboardInterrupt:
        return 1
    except Exception as e:
        lang = detect_lang(getattr(args, 'lang', 'auto'))
        t = I18N[lang]
        print(f"{t['err']}: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())

