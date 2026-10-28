#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fileinspect_ultimate.py — Inspector de ficheros con foco en seguridad y peritaje,
versión corregida (safe_format) para evitar KeyError en textos con llaves literales.

Incluye:
- i18n (es/en) con autodetección
- Modo fichero único o recursivo (-r) con include/exclude patterns y --max-depth
- Detección MIME robusta (python-magic > file(1) > magic bytes nativos > mimetypes)
- Detección de spoofing de extensión y doble extensión maliciosa
- Entropía de Shannon a nivel de fichero y detección de empaquetado (UPX/alta entropía)
- Análisis nativo de cabeceras PE (Windows) y ELF (Linux) sin dependencias externas
- Symlinks claros (realpath, destino, rotos sin crash)
- Hashes con caché SQLite (sha256 por defecto; seleccionables) + historial SQLite
- Comparación de archivos: --compare <FILE2>
- Secret scanning (patrones + JWT/Slack/DB URI/GCP + entropía + Luhn para tarjetas)
- Heurística de malware en scripts (opcional --malware-heuristics)
- Imágenes/EXIF (Pillow), Office/PDF (pypdf/PyPDF2 + escaneo de tags activos /JS, /Launch), multimedia (pymediainfo o ffprobe)
- Comprimidos: --archives off|list|deep (zip/tar.*) con detección de Zip Slip y Zip Bomb
- Dependencias: safety (Python) / npm audit (Node)
- VirusTotal por hash: --vt-api-key o VT_API_KEY
- Export: --export html|pdf, --output FILE, --jsonl y --template (usa safe_format); compatibilidad --html FILE
- Plugins: --plugins-dir (hook run(path: Path, info: dict) -> dict)
- YARA: --yara-rules rutas (si hay yara-python)
- Verbosidad: -v/-vv/-vvv y --debug
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import html as _html
import json
import logging
import math
import mimetypes
import os
import re
import sqlite3
import stat
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# =================== Dependencias opcionales ===================
try:
    import grp
    import pwd  # Unix
    HAVE_PWD_GRP = True
except Exception:
    HAVE_PWD_GRP = False

try:
    import chardet
    CHARDET_AVAILABLE = True
except Exception:
    CHARDET_AVAILABLE = False

try:
    from PIL import ExifTags, Image
    PILLOW_AVAILABLE = True
except Exception:
    PILLOW_AVAILABLE = False

try:
    import magic  # python-magic
    MAGIC_AVAILABLE = True
except Exception:
    MAGIC_AVAILABLE = False

try:
    from pymediainfo import MediaInfo
    MEDIAINFO_AVAILABLE = True
except Exception:
    MEDIAINFO_AVAILABLE = False

try:
    from weasyprint import HTML as WEASY_HTML
    WEASYPRINT_AVAILABLE = True
except Exception:
    WEASYPRINT_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False


def _ensure_utf8_stdio() -> None:
    """Evita UnicodeEncodeError en consolas/pipes Windows (cp1252) al imprimir emojis."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                enc = getattr(stream, "encoding", None) or ""
                if enc.lower().replace("-", "") != "utf8":
                    stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


# =================== i18n ===================
def detect_console_lang() -> str:
    for var in ("LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"):
        v = os.environ.get(var)
        if not v:
            continue
        first = v.split(":")[0]
        code = first.split(".")[0].lower()
        if code.startswith("es"):
            return "es"
        if code.startswith("en"):
            return "en"
    return "en"


def choose_lang(cli_lang: Optional[str]) -> str:
    if not cli_lang or cli_lang == "auto":
        return detect_console_lang()
    return cli_lang if cli_lang in ("en", "es") else "en"


I18N = {
    "en": {
        "usage": """Usage: {prog} [options] <file_or_dir>

Security-focused file inspector (single file or recursive).

Size:
  -b, --bytes      Show exact size in bytes
  -k, --kb         Show size in KB (decimal)
  -m, --mb         Show size in MB (decimal)
  -g, --gb         Show size in GB (decimal)

Hashes:
  --no-hash        Do not compute hashes
  --hash ALGOS     Comma-separated (sha256,sha1,md5,...) — default: sha256

Modes & filters:
  -r, --recursive             Recurse into directories
  --include-pattern PAT1,...  Only include matching globs (e.g. *.py,*.json)
  --exclude-dir NAME1,...     Skip directories (.git,.venv,node_modules,__pycache__)
  --exclude-pattern PAT1,...  Skip files matching these globs
  --max-depth N               Max recursion depth

Other:
  --nofollow       Do not follow symbolic links
  --utc            Timestamps in UTC (ISO 8601)
  --json           JSON output (array if multiple results)
  --jsonl          JSON Lines output (one JSON object per line)
  -o, --output F   Write output/report to file F
  --fail-on-alert  Exit with code 2 if security alerts or diffs are found
  --lang L         Interface language: auto (default), en, es
  -v, --verbose    Verbose logs (-v/-vv/-vvv)
  --debug          Debug logs (same as -vvv)

Advanced:
  --compare FILE2              Compare hashes with FILE2
  --export {html,pdf}          Export report (HTML always generated; PDF via WeasyPrint)
  --template PATH              Custom HTML template (format string)
  --html FILE                  Back-compat: export HTML to FILE
  --db-path PATH               SQLite DB for history/cache
  --no-cache                   Disable hash cache
  --archives {off,list,deep}   Analyze archives (zip/tar.*): list or deep scan
  --yara-rules PATH[,PATH...]  Compile and run YARA rules (if installed)
  --malware-heuristics         Heuristic scan for suspicious script patterns
  --plugins-dir PATH           Load plugins from directory
  --history-show N             Print last N history entries (from SQLite)
  --vt-api-key KEY             VirusTotal API key (or env VT_API_KEY)
""",
        "file_not_found": "Path '{f}' does not exist.",
        "broken_symlink": "Broken symlink",
        "broken_symlink_alert": "⚠️ Broken symbolic link",
        "error": "Error",
        "warning": "Warning",
        "file": "File:",
        "realpath": "Realpath:",
        "symlink": "Symlink:",
        "mime": "MIME type:",
        "size": "Size:",
        "entropy": "Entropy:",
        "perms": "Permissions:",
        "owner": "Owner:",
        "modified": "Modified:",
        "accessed": "Accessed:",
        "created": "Metadata changed:",
        "integrity": "Integrity:",
        "alerts": "Security Alerts:",
        "advanced": "Advanced Analysis:",
        "details_arrow": "→",
        "lines": "{n} lines",
        "cant_count_lines": "Could not count lines",
        "pillow_missing": "Pillow not installed to analyze images.",
        "img_meta_error": "Could not read image metadata (possible corrupt image)",
        "exec_file": "Executable file ({k})",
        "compiler": "Compiler:",
        "encoding": "Encoding: {enc} ({conf:.1f}% conf.)",
        "hash_invalid_algo": "ERROR (invalid algorithm)",
        "hash_read_error": "ERROR (could not read)",
        "owner_fmt_unknown": "{uid}:{gid}",
        "perm_777": "🚨 777 permissions — extremely dangerous",
        "perm_world_writable": "🔓 World-writable",
        "suid": "⚠️ SUID bit — high risk if not required",
        "sgid": "⚠️ SGID bit — potential risk",
        "sensitive_name": "🔍 Potentially sensitive name",
        "double_ext": "🚨 Suspicious double extension ({name})",
        "ext_spoofing": "🚨 Extension/content mismatch (ext={ext}, actual={actual})",
        "high_entropy_exec": "⚠️ High entropy ({ent:.2f}/8.0) — possible packed or encrypted binary",
        "packer_detected": "⚠️ Packer/obfuscator section detected ({sec})",
        "pdf_active_content": "⚠️ PDF contains active/suspicious elements ({tags})",
        "archive_zip_slip": "🚨 Archive path traversal detected (Zip Slip: {entry})",
        "archive_zip_bomb": "🚨 Extreme compression ratio ({ratio:.0f}:1) — possible Zip Bomb",
        "secret_password": "Password in plaintext",
        "secret_api_key": "API key",
        "secret_secret": "Generic secret",
        "secret_privkey": "Private key",
        "secret_aws_ak": "AWS Access Key",
        "secret_aws_sk": "AWS Secret Key",
        "secret_github": "GitHub token",
        "secret_jwt": "JWT token",
        "secret_slack": "Slack token",
        "secret_gcp_key": "Google Cloud API key",
        "secret_stripe": "Stripe API key",
        "secret_db_uri": "Database connection URI with credentials",
        "secret_card": "Possible credit card number",
        "secret_b64_entropy": "High-entropy base64 string (possible secret)",
        "secret_hex_entropy": "High-entropy hex string (possible secret)",
        "img_dim": "Dimensions: {w}x{h}",
        "img_fmt": "Format: {fmt}",
        "img_mode": "Mode: {mode}",
        "img_bitdepth": "{bd}-bit",
        "img_interlaced": "interlaced",
        "img_non_interlaced": "non-interlaced",
        "non_regular": "Non-regular file (no hashing/scan)",
        "directory": "Directory with {n} entries",
        "compare_header": "Hash comparison",
        "compare_diff": "DIFF: {algo} differs",
        "compare_same": "SAME: {algo} identical",
        "export_html_done": "Exported HTML: {p}",
        "export_pdf_done": "Exported PDF: {p}",
        "export_pdf_unavailable": "PDF export requires weasyprint",
        "history_saved": "Saved to history",
        "yara_missing": "yara-python is not installed",
        "plugins_loaded": "Plugins loaded: {n}",
        "media_meta_present": "Media metadata present",
        "pdf_pages": "PDF: {n} pages",
        "pdf_author": "Author: {author}",
        "office_doc": "Office document (OOXML)",
        "media_duration": "Duration: {dur:.1f}s",
        "media_bitrate": "Bitrate: {br}kbps",
        "dep_vuln": "⚠️ Vulnerabilities detected in dependencies",
        "vt_clean": "✓ VirusTotal: Clean ({total} engines)",
        "vt_suspicious": "⚠️ VirusTotal: {mal} malicious, {sus} suspicious ({total} engines)",
        "vt_error": "VirusTotal: Could not check",
    },
    "es": {
        "usage": """Uso: {prog} [opciones] <fichero_o_directorio>

Inspector de ficheros con foco en seguridad (fichero único o recursivo).

Tamaño:
  -b, --bytes      Mostrar tamaño exacto en bytes
  -k, --kb         Mostrar tamaño en KB (decimal)
  -m, --mb         Mostrar tamaño en MB (decimal)
  -g, --gb         Mostrar tamaño en GB (decimal)

Hashes:
  --no-hash        No calcular hashes
  --hash ALGOS     Lista separada por comas (sha256,sha1,md5,...) — por defecto: sha256

Modos y filtros:
  -r, --recursive             Recorrer directorios recursivamente
  --include-pattern PAT1,...  Incluir sólo globs (p. ej. *.py,*.json)
  --exclude-dir NAME1,...     Excluir directorios (.git,.venv,node_modules,__pycache__)
  --exclude-pattern PAT1,...  Excluir ficheros que coincidan
  --max-depth N               Profundidad máxima

Otras:
  --nofollow       No seguir enlaces simbólicos
  --utc            Fechas en UTC (ISO 8601)
  --json           Salida JSON (array si hay múltiples resultados)
  --jsonl          Salida JSON Lines (un objeto JSON por línea)
  -o, --output F   Guardar salida/informe en el fichero F
  --fail-on-alert  Salir con código 2 si hay alertas de seguridad o diferencias
  --lang L         Idioma: auto (defecto), en, es
  -v, --verbose    Logs verbosos (-v/-vv/-vvv)
  --debug          Logs debug (equivale a -vvv)

Avanzadas:
  --compare FILE2              Comparar hashes con FILE2
  --export {html,pdf}          Exportar informe (siempre HTML; PDF con WeasyPrint)
  --template PATH              Plantilla HTML personalizada (format string)
  --html FICHERO               Compatibilidad: exportar sólo HTML a FICHERO
  --db-path PATH               SQLite para historial/caché
  --no-cache                   Desactivar caché de hashes
  --archives {off,list,deep}   Analizar comprimidos (zip/tar.*): listar o escanear
  --yara-rules PATH[,PATH...]  Compilar y ejecutar reglas YARA (si instalado)
  --malware-heuristics         Heurística de malware en scripts
  --plugins-dir PATH           Cargar plugins desde un directorio
  --history-show N             Mostrar últimos N registros del historial
  --vt-api-key KEY             Clave API de VirusTotal (o env VT_API_KEY)
""",
        "file_not_found": "La ruta '{f}' no existe.",
        "broken_symlink": "Enlace simbólico roto",
        "broken_symlink_alert": "⚠️ Enlace simbólico roto",
        "error": "Error",
        "warning": "Aviso",
        "file": "Fichero:",
        "realpath": "Realpath:",
        "symlink": "Enlace:",
        "mime": "Tipo MIME:",
        "size": "Tamaño:",
        "entropy": "Entropía:",
        "perms": "Permisos:",
        "owner": "Propietario:",
        "modified": "Modificado:",
        "accessed": "Accedido:",
        "created": "Cambio de metadatos:",
        "integrity": "Integridad:",
        "alerts": "Alertas de seguridad:",
        "advanced": "Análisis avanzado:",
        "details_arrow": "→",
        "lines": "{n} líneas",
        "cant_count_lines": "No se pudo contar las líneas",
        "pillow_missing": "Pillow no está instalado para analizar imágenes.",
        "img_meta_error": "No se pudieron leer metadatos de la imagen (posible imagen corrupta)",
        "exec_file": "Fichero ejecutable ({k})",
        "compiler": "Compilador:",
        "encoding": "Encoding: {enc} ({conf:.1f}% conf.)",
        "hash_invalid_algo": "ERROR (algoritmo no válido)",
        "hash_read_error": "ERROR (no se pudo leer)",
        "owner_fmt_unknown": "{uid}:{gid}",
        "perm_777": "🚨 Permisos 777 — extremadamente peligroso",
        "perm_world_writable": "🔓 Escribible por otros (world-writable)",
        "suid": "⚠️ Bit SUID — riesgo elevado si no es necesario",
        "sgid": "⚠️ Bit SGID — riesgo potencial",
        "sensitive_name": "🔍 Nombre potencialmente sensible",
        "double_ext": "🚨 Doble extensión sospechosa ({name})",
        "ext_spoofing": "🚨 Discrepancia extensión/contenido (ext={ext}, real={actual})",
        "high_entropy_exec": "⚠️ Alta entropía ({ent:.2f}/8.0) — posible binario empaquetado o cifrado",
        "packer_detected": "⚠️ Sección de empaquetador/ofuscador detectada ({sec})",
        "pdf_active_content": "⚠️ PDF con elementos activos/sospechosos ({tags})",
        "archive_zip_slip": "🚨 Path traversal en archivo comprimido (Zip Slip: {entry})",
        "archive_zip_bomb": "🚨 Ratio de compresión extremo ({ratio:.0f}:1) — posible Zip Bomb",
        "secret_password": "Contraseña en texto claro",
        "secret_api_key": "Clave de API",
        "secret_secret": "Secreto genérico",
        "secret_privkey": "Clave privada",
        "secret_aws_ak": "AWS Access Key",
        "secret_aws_sk": "AWS Secret Key",
        "secret_github": "Token de GitHub",
        "secret_jwt": "Token JWT",
        "secret_slack": "Token de Slack",
        "secret_gcp_key": "Clave API de Google Cloud",
        "secret_stripe": "Clave API de Stripe",
        "secret_db_uri": "URI de base de datos con credenciales",
        "secret_card": "Posible nº de tarjeta",
        "secret_b64_entropy": "Cadena base64 de alta entropía (posible secreto)",
        "secret_hex_entropy": "Cadena hex de alta entropía (posible secreto)",
        "img_dim": "Dimensiones: {w}x{h}",
        "img_fmt": "Formato: {fmt}",
        "img_mode": "Modo: {mode}",
        "img_bitdepth": "{bd}-bit",
        "img_interlaced": "interlaced",
        "img_non_interlaced": "non-interlaced",
        "non_regular": "Fichero no regular (sin hash/escaneo)",
        "directory": "Directorio con {n} entradas",
        "compare_header": "Comparación de hashes",
        "compare_diff": "DIF: {algo} difiere",
        "compare_same": "IGUAL: {algo} idéntico",
        "export_html_done": "HTML exportado: {p}",
        "export_pdf_done": "PDF exportado: {p}",
        "export_pdf_unavailable": "Exportar a PDF requiere weasyprint",
        "history_saved": "Guardado en historial",
        "yara_missing": "yara-python no está instalado",
        "plugins_loaded": "Plugins cargados: {n}",
        "media_meta_present": "Metadatos multimedia presentes",
        "pdf_pages": "PDF: {n} páginas",
        "pdf_author": "Autor: {author}",
        "office_doc": "Documento Office (OOXML)",
        "media_duration": "Duración: {dur:.1f}s",
        "media_bitrate": "Bitrate: {br}kbps",
        "dep_vuln": "⚠️ Vulnerabilidades detectadas en dependencias",
        "vt_clean": "✓ VirusTotal: Limpio ({total} motores)",
        "vt_suspicious": "⚠️ VirusTotal: {mal} maliciosos, {sus} sospechosos ({total} motores)",
        "vt_error": "VirusTotal: No se pudo verificar",
    },
}

# Se asigna tras parsear --lang
T = I18N["en"]

# =================== Utilidades base ===================
ANSI = sys.stdout.isatty() and not os.getenv("NO_COLOR")


def c(s, code):
    if not ANSI:
        return s
    return f"\033[{code}m{s}\033[0m"


def safe_format(s: str, **kwargs) -> str:
    """
    Permite usar str.format en textos con llaves literales (p.ej. CSS o --export {html,pdf}).
    Escapa todas las llaves y re-expone solo los placeholders que pasamos en kwargs.
    """
    escaped = s.replace("{", "{{").replace("}", "}}")
    for k in kwargs:
        escaped = escaped.replace("{{" + k + "}}", "{" + k + "}")
    return escaped.format(**kwargs)


def safe_owner_group(st) -> str:
    if HAVE_PWD_GRP:
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = str(st.st_gid)
        return f"{owner}:{group}"
    return T["owner_fmt_unknown"].format(uid=getattr(st, "st_uid", "?"), gid=getattr(st, "st_gid", "?"))


def format_size_iec(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    units = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"]
    e = int(math.log(n, 1024))
    e = min(e, len(units))
    val = n / (1024 ** e)
    return f"{val:.2f} {units[e - 1]}"


def format_permissions(mode: int) -> str:
    return stat.filemode(mode)


def shutil_which(cmd: str) -> bool:
    from shutil import which
    return which(cmd) is not None


# =================== Magic Bytes nativo & MIME ===================
def detect_builtin_magic_mime(path: Path) -> Optional[str]:
    """Reconocedor ligero de magic bytes y texto sin dependencias externas."""
    try:
        with open(path, "rb") as f:
            head = f.read(512)
    except Exception:
        return None
    if not head:
        return "inode/x-empty"
    if head.startswith(b"\x7fELF"):
        return "application/x-executable"
    if head[:2] == b"MZ":
        return "application/vnd.microsoft.portable-executable"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "application/x-mach-binary"
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "audio/wav"
    if head.startswith(b"SQLite format 3\x00"):
        return "application/vnd.sqlite3"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
        ext = path.suffix.lower()
        if ext == ".docx":
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if ext == ".xlsx":
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        if ext == ".pptx":
            return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        if ext == ".jar":
            return "application/java-archive"
        return "application/zip"
    if head.startswith(b"\x1f\x8b\x08"):
        return "application/gzip"
    if head.startswith(b"BZh"):
        return "application/x-bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "application/x-xz"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "application/zstd"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed"
    if head.startswith(b"Rar!\x1a\x07"):
        return "application/vnd.rar"
    if head.startswith(b"\x00asm"):
        return "application/wasm"
    if head.startswith(b"{\\rtf"):
        return "application/rtf"
    if head.startswith(b"#!"):
        first_line = head.splitlines()[0].decode("latin-1", errors="ignore").lower()
        if "python" in first_line:
            return "text/x-python"
        if any(sh in first_line for sh in ("sh", "bash", "zsh", "dash", "ksh")):
            return "text/x-shellscript"
        return "text/plain"
    # Heurística de texto plano (como file(1) cuando no hay bytes nulos)
    if b"\x00" not in head:
        try:
            text_sample = head.decode("utf-8")
            printable = sum(1 for ch in text_sample if ch.isprintable() or ch in "\r\n\t\x0b\x0c")
            if len(text_sample) > 0 and (printable / len(text_sample)) >= 0.90:
                guess, _ = mimetypes.guess_type(str(path))
                if guess and (guess.startswith("text/") or guess in ("application/json", "application/xml", "application/javascript")):
                    return guess
                return "text/plain"
        except UnicodeDecodeError:
            pass
    return None


def detect_magic_mime(path: Path) -> Optional[str]:
    if MAGIC_AVAILABLE:
        try:
            m = magic.Magic(mime=True)
            return m.from_file(str(path))
        except Exception:
            return None
    return None


def detect_file_mime(path: Path, timeout=2, follow_symlinks=True) -> Optional[str]:
    if not shutil_which("file"):
        return None
    try:
        args = ["file", "--mime-type", "-b"]
        if not follow_symlinks:
            args.insert(1, "-h")
        out = subprocess.run(args + [str(path)], capture_output=True, text=True, timeout=timeout, check=True)
        mt = out.stdout.strip()
        return mt or None
    except Exception:
        return None


def best_mime(path: Path, follow_symlinks=True) -> str:
    if path.is_symlink() and not follow_symlinks:
        return "inode/symlink"
    mt = detect_magic_mime(path)
    if mt:
        return mt
    mt = detect_file_mime(path, follow_symlinks=follow_symlinks)
    if mt:
        return mt
    mt = detect_builtin_magic_mime(path)
    if mt:
        return mt
    guess, _ = mimetypes.guess_type(str(path))
    return guess or "application/octet-stream"


# =================== Secretos / heurística ===================
SECRET_PATTERNS = [
    (re.compile(r'password\s*[:=]\s*["\']?[^"\'\s]{4,}', re.I | re.M), "secret_password"),
    (re.compile(r'api[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9._\-]{10,}', re.I | re.M), "secret_api_key"),
    (re.compile(r'secret\s*[:=]\s*["\']?[^"\'\s]{6,}', re.I | re.M), "secret_secret"),
    (re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'), "secret_privkey"),
    (re.compile(r'(?:aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']?[A-Z0-9]{20}|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b)', re.I), "secret_aws_ak"),
    (re.compile(r'aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}', re.I), "secret_aws_sk"),
    (re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b'), "secret_github"),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'), "secret_jwt"),
    (re.compile(r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b'), "secret_slack"),
    (re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), "secret_gcp_key"),
    (re.compile(r'\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b'), "secret_stripe"),
    (re.compile(r'(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|amqp)://[^/\s:@]+:[^/\s@]+@[^\s"\']+', re.I), "secret_db_uri"),
]
CARD_RE   = re.compile(r'[\d]{4}[\s-]?[\d]{4}[\s-]?[\d]{4}[\s-]?[\d]{4}')
BASE64_RE = re.compile(r'\b[A-Za-z0-9+/]{24,}={0,2}\b')
HEX_RE    = re.compile(r'\b[0-9a-fA-F]{32,}\b')


def shannon_entropy(s: str) -> float:
    from math import log2
    if not s:
        return 0.0
    counts = {ch: s.count(ch) for ch in set(s)}
    return -sum((c / len(s)) * log2(c / len(s)) for c in counts.values())


def file_shannon_entropy(path: Path, max_sample_bytes: int = 2 * 1024 * 1024) -> Optional[float]:
    """Calcula la entropía de Shannon de un fichero en bits por byte (0.0 a 8.0)."""
    try:
        with open(path, "rb") as f:
            data = f.read(max_sample_bytes)
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        total = len(data)
        ent = 0.0
        for count in counts:
            if count:
                p = count / total
                ent -= p * math.log2(p)
        return round(ent, 4)
    except Exception:
        return None


def luhn_ok(num: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", num)]
    if len(digits) < 12:
        return False
    s = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return s % 10 == 0


MAL_HEUR_PATTERNS = [
    re.compile(r'base64\.(b64decode|urlsafe_b64decode)\s*\('),
    re.compile(r'(?<!\w)(exec|eval)\s*\('),
    re.compile(r'(?<!\w)subprocess\.(Popen|call|run|check_output)\s*\('),
    re.compile(r'os\.(system|popen)\s*\('),
    re.compile(r'__import__\s*\('),
    re.compile(r'(curl|wget)\s+https?://', re.I),
    re.compile(r'PowerShell\s*.*-(?:Enc|EncodedCommand|e)\b', re.I),
    re.compile(r'(?:IEX|Invoke-Expression)\s*\(.*(?:DownloadString|Invoke-WebRequest)', re.I),
    re.compile(r'/dev/(?:tcp|udp)/[^\s/]+/\d+'),
    re.compile(r'\b(?:nc|ncat|netcat)\b.*\s-[ec]\s'),
]


def heuristic_malware_lines(text: str) -> List[int]:
    lines = text.splitlines()
    flagged = set()
    for i, line in enumerate(lines, 1):
        for rx in MAL_HEUR_PATTERNS:
            if rx.search(line):
                flagged.add(i)
    return sorted(flagged)


def detectar_secretos_en_texto(file_path: Path,
                               max_bytes: int = 1024 * 1024,
                               max_lines: int = 800,
                               encoding: str = "utf-8",
                               enable_heuristics: bool = False) -> Tuple[List[str], Dict[str, Any]]:
    secretos: List[str] = []
    extra: Dict[str, Any] = {}
    try:
        if file_path.stat().st_size > max_bytes:
            return secretos, extra
        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            lines = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                lines.append(line)
            contenido = ''.join(lines)
    except Exception:
        return secretos, extra

    return detectar_secretos_en_texto_from_text(contenido, (max_bytes, max_lines), enable_heuristics)


# =================== Hash cache + historial (SQLite) ===================
class HashCache:
    def __init__(self, db_path: Path, enable_cache: bool = True):
        self.db_path = db_path
        self.enable_cache = enable_cache
        self._ensure_schema()

    def _ensure_schema(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.db_path)) as con:
            cur = con.cursor()
            cur.execute("""CREATE TABLE IF NOT EXISTS hash_cache(
                path TEXT, size INTEGER, mtime REAL, algo TEXT, hexdigest TEXT,
                PRIMARY KEY(path, size, mtime, algo)
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS history(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, path TEXT, size INTEGER, mtime REAL, sha256 TEXT,
                options_json TEXT, info_json TEXT
            )""")
            con.commit()

    def get(self, path: Path, st, algo: str) -> Optional[str]:
        if not self.enable_cache:
            return None
        with closing(sqlite3.connect(self.db_path)) as con:
            cur = con.cursor()
            cur.execute("SELECT hexdigest FROM hash_cache WHERE path=? AND size=? AND mtime=? AND algo=?",
                        (str(path), st.st_size, st.st_mtime, algo))
            row = cur.fetchone()
            return row[0] if row else None

    def put(self, path: Path, st, algo: str, hexdigest: str) -> None:
        if not self.enable_cache:
            return
        with closing(sqlite3.connect(self.db_path)) as con:
            con.execute("INSERT OR REPLACE INTO hash_cache(path,size,mtime,algo,hexdigest) VALUES(?,?,?,?,?)",
                        (str(path), st.st_size, st.st_mtime, algo, hexdigest))
            con.commit()

    def save_history(self, path: Path, st, sha256: Optional[str], options: Dict[str, Any], info: Dict[str, Any]) -> None:
        with closing(sqlite3.connect(self.db_path)) as con:
            con.execute("INSERT INTO history(ts,path,size,mtime,sha256,options_json,info_json) VALUES(?,?,?,?,?,?,?)",
                        (time.time(), str(path), getattr(st, "st_size", None), getattr(st, "st_mtime", None),
                         sha256, json.dumps(options, ensure_ascii=False), json.dumps(info, ensure_ascii=False)))
            con.commit()

    def show_history(self, n: int) -> List[Dict[str, Any]]:
        with closing(sqlite3.connect(self.db_path)) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute("SELECT ts,path,size,mtime,sha256 FROM history ORDER BY id DESC LIMIT ?", (n,)).fetchall()
            return [dict(r) for r in rows]


def default_db_path() -> Path:
    base = Path(os.getenv("XDG_STATE_HOME") or Path.home() / ".local/state")
    return base / "sabbat_tools" / "fileinspect.db"


def calcular_hashes(file_path: Path, algos: Tuple[str, ...], cache: Optional[HashCache], st=None) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    try:
        import mmap
        use_mmap = True
    except Exception:
        use_mmap = False

    if st is None:
        try:
            st = file_path.stat()
        except Exception:
            st = None

    for algo in algos:
        try:
            hasher = hashlib.new(algo)
        except ValueError:
            hashes[algo] = T["hash_invalid_algo"]
            continue

        # cache hit?
        if cache and st:
            cached = cache.get(file_path, st, algo)
            if cached:
                hashes[algo] = cached
                continue

        try:
            with open(file_path, "rb") as f:
                if use_mmap and st and getattr(st, "st_size", 0) > 0:
                    try:
                        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                            hasher.update(mm)
                    except Exception:
                        f.seek(0)
                        for chunk in iter(lambda: f.read(1 << 20), b""):
                            hasher.update(chunk)
                else:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        hasher.update(chunk)
            digest = hasher.hexdigest()
            hashes[algo] = digest
            if cache and st:
                cache.put(file_path, st, algo, digest)
        except (OSError, IOError):
            hashes[algo] = T["hash_read_error"]
    return hashes


# =================== Seguridad de permisos / nombres / spoofing ===================
NOMBRES_RIESGO = ['.ssh', '.pem', 'id_rsa', 'id_ed25519', 'password', 'secret', '.env', '.bak', '.tmp', '~', 'credentials', '.kdbx']

DOC_OR_MEDIA_EXTS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.txt', '.csv', '.rtf', '.mp3', '.mp4', '.wav', '.avi'}
EXEC_EXTS = {'.exe', '.scr', '.pif', '.bat', '.cmd', '.com', '.ps1', '.vbs', '.js', '.jse', '.wsf', '.wsh', '.msi', '.hta', '.cpl', '.sh', '.run', '.bin', '.elf'}


def detect_double_extension(path: Path) -> Optional[str]:
    """Detecta nombres como factura.pdf.exe o documento.docx.ps1."""
    parts = path.name.lower().split(".")
    if len(parts) >= 3:
        last_ext = "." + parts[-1]
        prev_ext = "." + parts[-2]
        if last_ext in EXEC_EXTS and prev_ext in DOC_OR_MEDIA_EXTS:
            return T["double_ext"].format(name=path.name)
    return None


def detect_extension_spoofing(path: Path) -> Optional[str]:
    """Detecta si un archivo con extensión benigna contiene en realidad un ejecutable o formato distinto."""
    ext = path.suffix.lower()
    if not ext or ext not in DOC_OR_MEDIA_EXTS:
        return None
    exec_kind = is_executable_magic(path)
    if exec_kind:
        return T["ext_spoofing"].format(ext=ext, actual=exec_kind)
    builtin_mime = detect_builtin_magic_mime(path)
    if not builtin_mime:
        return None
    # Verificar discrepancias claras de formato (p.ej. .jpg que es un script o .txt que es un ZIP/PDF)
    if ext in {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'} and not builtin_mime.startswith("image/"):
        return T["ext_spoofing"].format(ext=ext, actual=builtin_mime)
    if ext == '.pdf' and builtin_mime != "application/pdf":
        return T["ext_spoofing"].format(ext=ext, actual=builtin_mime)
    return None


def analizar_riesgos_seguridad(path: Path, st, is_symlink=False) -> List[str]:
    alertas = []
    mode = st.st_mode
    if not is_symlink:
        if mode & stat.S_ISUID:
            alertas.append(T["suid"])
        if mode & stat.S_ISGID:
            alertas.append(T["sgid"])
        if (mode & 0o777) == 0o777:
            alertas.append(T["perm_777"])
        elif mode & stat.S_IWOTH:
            alertas.append(T["perm_world_writable"])
    if any(r in str(path).lower() for r in NOMBRES_RIESGO):
        alertas.append(T["sensitive_name"])
    dbl = detect_double_extension(path)
    if dbl:
        alertas.append(dbl)
    if not is_symlink and stat.S_ISREG(mode):
        spoof = detect_extension_spoofing(path)
        if spoof:
            alertas.append(spoof)
    return alertas


# =================== YARA ===================
class YaraRunner:
    def __init__(self, rule_paths: List[Path]):
        self.available = YARA_AVAILABLE
        self.compiled = None
        if not self.available or not rule_paths:
            return
        rules = {}
        for idx, p in enumerate(rule_paths):
            if p.is_file():
                rules[f"r{idx}"] = str(p)
            elif p.is_dir():
                for yr in p.rglob("*.yar"):
                    rules[f"{yr.stem}_{idx}"] = str(yr)
        if rules:
            try:
                self.compiled = yara.compile(filepaths=rules)
            except Exception as e:
                logging.error("YARA compile error: %s", e)
                self.compiled = None

    def scan_file(self, path: Path, max_bytes: int = 5_000_000) -> List[str]:
        if not self.compiled:
            return []
        try:
            with open(path, "rb") as f:
                data = f.read(max_bytes)
            matches = self.compiled.match(data=data)
            return [m.rule for m in matches]
        except Exception as e:
            logging.debug("YARA scan error on %s: %s", path, e)
            return []


# =================== Plugins ===================
class PluginManager:
    def __init__(self, dirs: List[Path]):
        self.plugins = []
        for d in dirs:
            if not d or not d.exists() or not d.is_dir():
                continue
            for py in d.glob("*.py"):
                try:
                    mod_name = f"fileinspect_plugin_{py.stem}"
                    import importlib.util
                    spec = importlib.util.spec_from_file_location(mod_name, str(py))
                    mod = importlib.util.module_from_spec(spec)
                    assert spec and spec.loader
                    spec.loader.exec_module(mod)  # type: ignore
                    if hasattr(mod, "run") and callable(mod.run):
                        self.plugins.append(mod)
                except Exception as e:
                    logging.warning("Failed to load plugin %s: %s", py, e)

    def run(self, path: Path, info: Dict[str, Any]) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        for mod in self.plugins:
            try:
                out = mod.run(path, info)  # contract: returns dict or None
                if isinstance(out, dict):
                    results.update(out)
            except Exception as e:
                logging.debug("Plugin error in %s: %s", getattr(mod, "__name__", "?"), e)
        return results


# =================== Comprimidos (zip/tar) ===================
def _is_unsafe_archive_member(name: str) -> bool:
    """Detecta intentos de Zip Slip (path traversal o rutas absolutas en archivos comprimidos)."""
    norm = name.replace("\\", "/")
    if norm.startswith("/") or re.match(r"^[A-Za-z]:/", norm):
        return True
    parts = [p for p in norm.split("/") if p]
    return ".." in parts


def detectar_secretos_en_texto_from_text(text: str,
                                         limits: Tuple[int, int],
                                         enable_heuristics: bool = False) -> Tuple[List[str], Dict[str, Any]]:
    secretos: List[str] = []
    extra: Dict[str, Any] = {}
    for patron, key in SECRET_PATTERNS:
        if patron.search(text):
            alert_txt = "🔑 " + T[key]
            if alert_txt not in secretos:
                secretos.append(alert_txt)
    for m in CARD_RE.finditer(text):
        if luhn_ok(m.group(0)):
            secretos.append("🔑 " + T["secret_card"])
            break
    for m in BASE64_RE.findall(text):
        if shannon_entropy(m) >= 4.5:
            secretos.append("🔑 " + T["secret_b64_entropy"])
            break
    for m in HEX_RE.findall(text):
        if shannon_entropy(m) >= 3.5:
            secretos.append("🔑 " + T["secret_hex_entropy"])
            break
    if enable_heuristics:
        lines = heuristic_malware_lines(text)
        if lines:
            extra["malware_heuristics"] = {"suspicious_lines": lines}
    return secretos, extra


def analyze_archives(path: Path, mode: str, text_limits: Tuple[int, int], enable_heuristics: bool = False) -> Dict[str, Any]:
    """
    mode: 'off'|'list'|'deep'
    """
    res: Dict[str, Any] = {}
    if mode == "off":
        return res

    entries: List[Dict[str, Any]] = []
    archive_alerts: List[str] = []

    def add_entry(name, size, type_="file", alerts=None):
        entries.append({"name": name, "size": size, "type": type_, "alerts": alerts or []})

    try:
        if zipfile.is_zipfile(path):
            total_uncompressed = 0
            total_compressed = 0
            with zipfile.ZipFile(path) as zf:
                for zi in zf.infolist():
                    alerts = []
                    total_uncompressed += max(0, zi.file_size)
                    total_compressed += max(0, zi.compress_size)
                    if _is_unsafe_archive_member(zi.filename):
                        slip_msg = T["archive_zip_slip"].format(entry=zi.filename)
                        alerts.append(slip_msg)
                        archive_alerts.append(slip_msg)
                    if zi.compress_size > 0 and zi.file_size > 10 * 1024 * 1024:
                        ratio = zi.file_size / zi.compress_size
                        if ratio > 100:
                            bomb_msg = T["archive_zip_bomb"].format(ratio=ratio)
                            alerts.append(bomb_msg)
                            if bomb_msg not in archive_alerts:
                                archive_alerts.append(bomb_msg)
                    add_entry(zi.filename, zi.file_size, "dir" if zi.is_dir() else "file", alerts)
                    if mode == "deep" and not zi.is_dir() and zi.file_size <= text_limits[0]:
                        try:
                            data = zf.read(zi)
                            text = data.decode("utf-8", errors="ignore")
                            secretos, extra = detectar_secretos_en_texto_from_text(text, text_limits, enable_heuristics)
                            alerts.extend(secretos)
                            if extra.get("malware_heuristics"):
                                alerts.append("malware heuristics")
                        except Exception:
                            pass
            res["archive"] = {
                "type": "zip",
                "entries": entries,
                "total_uncompressed": total_uncompressed,
                "total_compressed": total_compressed,
            }
            if archive_alerts:
                res["_archive_security_alerts"] = archive_alerts
            return res

        if tarfile.is_tarfile(path):
            total_uncompressed = 0
            with tarfile.open(path) as tf:
                for ti in tf.getmembers():
                    alerts = []
                    total_uncompressed += max(0, ti.size)
                    if _is_unsafe_archive_member(ti.name):
                        slip_msg = T["archive_zip_slip"].format(entry=ti.name)
                        alerts.append(slip_msg)
                        archive_alerts.append(slip_msg)
                    add_entry(ti.name, ti.size, "dir" if ti.isdir() else "file", alerts)
                    if mode == "deep" and ti.isfile() and ti.size <= text_limits[0]:
                        try:
                            f = tf.extractfile(ti)
                            if f:
                                data = f.read()
                                text = data.decode("utf-8", errors="ignore")
                                secretos, extra = detectar_secretos_en_texto_from_text(text, text_limits, enable_heuristics)
                                alerts.extend(secretos)
                                if extra.get("malware_heuristics"):
                                    alerts.append("malware heuristics")
                        except Exception:
                            pass
            res["archive"] = {"type": "tar", "entries": entries, "total_uncompressed": total_uncompressed}
            if archive_alerts:
                res["_archive_security_alerts"] = archive_alerts
            return res
    except Exception as e:
        logging.debug("Archive analyze error %s: %s", path, e)

    return res


# =================== Office/PDF ===================
PDF_RISKY_TAGS = (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFiles", b"/RichMedia", b"/XFA")


def analyze_office_pdf(path: Path, mime: str) -> Tuple[List[str], List[str]]:
    details: List[str] = []
    alerts: List[str] = []
    if mime == "application/pdf" or path.suffix.lower() == ".pdf":
        pages_found = False
        try:
            try:
                from pypdf import PdfReader  # type: ignore
            except ImportError:
                from PyPDF2 import PdfReader  # type: ignore
            reader = PdfReader(path)
            details.append(T["pdf_pages"].format(n=len(reader.pages)))
            pages_found = True
            if reader.metadata and "/Author" in reader.metadata:
                details.append(T["pdf_author"].format(author=reader.metadata["/Author"]))
        except Exception as e:
            logging.debug("PDF library analysis error: %s", e)

        # Escaneo nativo de estructura PDF (páginas + objetos activos sospechosos)
        try:
            with open(path, "rb") as f:
                raw_pdf = f.read(2 * 1024 * 1024)
            if not pages_found:
                page_matches = re.findall(rb"/Type\s*/Page\b", raw_pdf)
                if page_matches:
                    details.append(T["pdf_pages"].format(n=len(page_matches)))
            found_tags = []
            for tag in PDF_RISKY_TAGS:
                if re.search(re.escape(tag) + rb"\b", raw_pdf):
                    found_tags.append(tag.decode("ascii"))
            if found_tags:
                alerts.append(T["pdf_active_content"].format(tags=", ".join(found_tags)))
        except Exception as e:
            logging.debug("PDF raw scan error: %s", e)

    elif "openxmlformats" in mime or path.suffix.lower() in (".docx", ".xlsx", ".pptx"):
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                if "docProps/core.xml" in names:
                    details.append(T["office_doc"])
                if any(n.lower().endswith("vbaproject.bin") for n in names):
                    alerts.append("⚠️ VBA Macro (vbaProject.bin) detected in Office document")
        except Exception as e:
            logging.debug("Office doc analysis error: %s", e)
    return details, alerts


# =================== Media metadata ===================
def extract_media_info(path: Path) -> Dict[str, Any]:
    # Primero pymediainfo, luego ffprobe
    if MEDIAINFO_AVAILABLE:
        try:
            mi = MediaInfo.parse(str(path))
            g = mi.general_tracks[0] if mi.general_tracks else None
            if g:
                return {
                    "duration_ms": getattr(g, "duration", None),
                    "format": getattr(g, "format", None),
                    "overall_bitrate": getattr(g, "overall_bit_rate", None),
                }
        except Exception as e:
            logging.debug("pymediainfo error: %s", e)
    # ffprobe fallback
    if shutil_which("ffprobe"):
        try:
            result = subprocess.run(
                ["ffprobe", "-v", "quiet", "-print_format", "json",
                 "-show_format", "-show_streams", str(path)],
                capture_output=True, text=True, timeout=5
            )
            data = json.loads(result.stdout or "{}")
            fmt = data.get("format", {})
            if fmt:
                return {
                    "duration_ms": float(fmt.get("duration")) * 1000 if fmt.get("duration") else None,
                    "format": fmt.get("format_name"),
                    "overall_bitrate": int(fmt.get("bit_rate")) if fmt.get("bit_rate") else None,
                }
        except Exception as e:
            logging.debug("ffprobe error: %s", e)
    return {}


# =================== VirusTotal ===================
def check_virustotal(file_hash: str, api_key: Optional[str] = None) -> Optional[Dict[str, int]]:
    api_key = api_key or os.getenv("VT_API_KEY")
    if not api_key:
        return None
    try:
        import urllib.request
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": api_key})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "total": sum(int(v) for v in stats.values())
            }
    except Exception as e:
        logging.debug("VirusTotal error: %s", e)
        return None


# =================== Recorrido recursivo ===================
def match_any(name: str, patterns: List[str]) -> bool:
    if not patterns:
        return False
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def walk_filtered(root: Path, include_patterns: List[str], exclude_dirs: List[str],
                  exclude_patterns: List[str], max_depth: Optional[int]) -> Iterable[Path]:
    base_depth = len(root.resolve().parts)
    for cur, dirs, files in os.walk(root, followlinks=False):
        depth = len(Path(cur).resolve().parts) - base_depth
        if max_depth is not None and depth > max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for fn in files:
            p = Path(cur) / fn
            if exclude_patterns and match_any(fn, exclude_patterns):
                continue
            if include_patterns and not match_any(fn, include_patterns):
                continue
            yield p


# =================== Núcleo de análisis binario y multimedia ===================
def is_executable_magic(path: Path) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            head = f.read(8)
        if head.startswith(b"\x7fELF"):
            return "ELF"
        if head[:2] == b"MZ":
            return "PE"
        if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
            return "Mach-O"
    except Exception:
        pass
    return None


def analyze_pe_header(path: Path) -> Tuple[List[str], List[str]]:
    """Analiza cabeceras PE (Windows EXE/DLL) en Python puro usando struct."""
    details: List[str] = []
    alerts: List[str] = []
    try:
        with open(path, "rb") as f:
            dos = f.read(64)
            if len(dos) < 64 or dos[:2] != b"MZ":
                return details, alerts
            pe_offset = struct.unpack("<I", dos[60:64])[0]
            f.seek(pe_offset)
            pe_sig = f.read(24)
            if len(pe_sig) < 24 or pe_sig[:4] != b"PE\x00\x00":
                return details, alerts
            machine, num_sections, ts, _, _, opt_size, characteristics = struct.unpack("<HHIIIHH", pe_sig[4:24])
            arch_map = {0x014c: "x86", 0x8664: "x86_64", 0xaa64: "ARM64", 0x01c0: "ARM", 0x01c4: "ARMv7"}
            arch = arch_map.get(machine, f"0x{machine:04x}")
            is_dll = bool(characteristics & 0x2000)
            kind_str = "DLL" if is_dll else "EXE"
            ts_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts > 0 else "N/A"
            details.append(f"PE {kind_str} ({arch}), build: {ts_str}")

            if opt_size > 0:
                f.seek(pe_offset + 24 + opt_size)
            sec_names = []
            suspicious_packers = {"upx0", "upx1", "upx2", ".upx", ".aspack", ".vmp0", ".vmp1", ".themida", ".nsp0"}
            for _ in range(min(num_sections, 64)):
                sec = f.read(40)
                if len(sec) < 40:
                    break
                raw_name = sec[:8].split(b"\x00", 1)[0].decode("latin-1", errors="ignore").strip()
                if raw_name:
                    sec_names.append(raw_name)
                    if raw_name.lower() in suspicious_packers:
                        alerts.append(T["packer_detected"].format(sec=raw_name))
            if sec_names:
                details.append(f"PE Sections ({len(sec_names)}): {', '.join(sec_names[:8])}")
    except Exception as e:
        logging.debug("PE parse error: %s", e)
    return details, alerts


def analyze_elf_header(path: Path) -> List[str]:
    """Analiza cabeceras ELF en Python puro usando struct."""
    details: List[str] = []
    try:
        with open(path, "rb") as f:
            hdr = f.read(64)
        if len(hdr) < 20 or not hdr.startswith(b"\x7fELF"):
            return details
        ei_class = hdr[4]  # 1=32-bit, 2=64-bit
        ei_data = hdr[5]   # 1=little, 2=big
        bits = "64-bit" if ei_class == 2 else ("32-bit" if ei_class == 1 else "?")
        endian = "<" if ei_data == 1 else ">"
        e_type, e_machine = struct.unpack(f"{endian}HH", hdr[16:20])
        type_map = {1: "REL", 2: "EXEC", 3: "DYN/PIE", 4: "CORE"}
        mach_map = {0x03: "x86", 0x3E: "x86_64", 0x28: "ARM", 0xB7: "AArch64", 0xF3: "RISC-V"}
        details.append(f"ELF {bits} {type_map.get(e_type, str(e_type))} ({mach_map.get(e_machine, f'0x{e_machine:x}')})")
    except Exception as e:
        logging.debug("ELF parse error: %s", e)
    return details


def run_readelf_comment(path: Path, timeout=2) -> Optional[str]:
    if not shutil_which("readelf"):
        return None
    try:
        out = subprocess.run(["readelf", "-p", ".comment", str(path)],
                             capture_output=True, text=True, timeout=timeout, check=True)
        txt = out.stdout
        if "GCC:" in txt:
            line = txt.split("GCC:", 1)[1].strip().splitlines()[0]
            return f"GCC {line}"
    except Exception:
        pass
    return None


def extract_exif_summary(path: Path) -> Dict[str, Any]:
    if not PILLOW_AVAILABLE:
        return {"note": T["pillow_missing"]}
    out: Dict[str, Any] = {}
    try:
        with Image.open(path) as img:
            img.verify()
        with Image.open(path) as img:
            out["size"] = img.size
            out["format"] = img.format
            out["mode"] = img.mode
            exif = img.getexif()
            gps = {}
            fields = {}
            if exif:
                for k, v in exif.items():
                    tag = ExifTags.TAGS.get(k, str(k))
                    if tag == "GPSInfo":
                        gps = {ExifTags.GPSTAGS.get(kk, str(kk)): vv for kk, vv in v.items()} if isinstance(v, dict) else {}
                    else:
                        if tag in ("DateTimeOriginal", "Make", "Model", "Software"):
                            fields[tag] = v
            if gps:
                out["gps"] = True
            if fields:
                out["fields"] = fields
    except Exception:
        return {"error": T["img_meta_error"]}
    return out


def get_file_info(file_path_str: str,
                  follow_symlinks: bool = True,
                  utc_times: bool = False,
                  secret_limits: Tuple[int, int] = (1024 * 1024, 800),
                  yara_runner: Optional[YaraRunner] = None,
                  malware_heuristics: bool = False,
                  archives_mode: str = "off",
                  plugin_mgr: Optional[PluginManager] = None,
                  vt_api_key: Optional[str] = None) -> Dict[str, Any]:
    file_path = Path(file_path_str)
    is_symlink = file_path.is_symlink()
    if not file_path.exists() and not is_symlink:
        raise FileNotFoundError(T["file_not_found"].format(f=file_path))

    lstat_obj = file_path.lstat() if is_symlink else None
    real_path = None
    symlink_target = None
    symlink_broken = False

    if is_symlink:
        try:
            symlink_target = os.readlink(file_path)
        except OSError:
            symlink_target = T["broken_symlink"]
        if not file_path.exists():
            symlink_broken = True

    if is_symlink and follow_symlinks and not symlink_broken:
        try:
            real_path = file_path.resolve(strict=True)
        except Exception:
            real_path = None

    if not is_symlink or (follow_symlinks and not symlink_broken):
        st = file_path.stat()
    else:
        st = lstat_obj

    mode = st.st_mode
    is_regular = stat.S_ISREG(mode)
    is_dir = stat.S_ISDIR(mode)

    mime = best_mime(file_path, follow_symlinks=(not is_symlink or (follow_symlinks and not symlink_broken)))

    def fmt_ts(ts: float) -> str:
        if utc_times:
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    alertas_seg = analizar_riesgos_seguridad(file_path, st, is_symlink)
    if symlink_broken:
        alertas_seg.append(T["broken_symlink_alert"])

    info: Dict[str, Any] = {
        "lang": "en" if T is I18N["en"] else "es",
        "nombre": str(file_path),
        "realpath": str(real_path) if real_path else None,
        "tipo_mime": mime,
        "tamaño_bytes": st.st_size,
        "entropia": file_shannon_entropy(file_path) if is_regular else None,
        "permisos": format_permissions(st.st_mode),
        "propietario": safe_owner_group(st),
        "fecha_mod": fmt_ts(st.st_mtime),
        "fecha_acc": fmt_ts(st.st_atime),
        "fecha_cre": fmt_ts(st.st_ctime),
        "inodo": getattr(st, "st_ino", None),
        "es_symlink": is_symlink,
        "destino_symlink": symlink_target,
        "detalles_contextuales": [],
        "detalles_avanzados": [],
        "alertas_seguridad": alertas_seg,
    }

    if is_dir:
        try:
            entries = sum(1 for _ in os.scandir(file_path))
            info["detalles_contextuales"].append(T["directory"].format(n=entries))
        except Exception:
            info["detalles_contextuales"].append("Directory (?)")
        return info

    if not is_regular:
        info["detalles_contextuales"].append(T["non_regular"])
        return info

    # Text / scripts
    if mime.startswith("text/") or mime in ("application/json", "application/xml", "application/javascript"):
        encoding_hint = "utf-8"
        if CHARDET_AVAILABLE:
            try:
                with open(file_path, "rb") as f:
                    raw = f.read(4096)
                det = chardet.detect(raw)
                if det.get("encoding") and det.get("confidence", 0) > 0.5:
                    encoding_hint = det["encoding"]
                    info["detalles_contextuales"].append(T["encoding"].format(enc=encoding_hint, conf=det["confidence"] * 100))
            except Exception:
                pass
        try:
            with open(file_path, "r", encoding=encoding_hint, errors="ignore") as f:
                num_lineas = sum(1 for _ in f)
            info["detalles_contextuales"].append(T["lines"].format(n=num_lineas))
        except Exception:
            info["detalles_contextuales"].append(T["cant_count_lines"])
        secretos, extra = detectar_secretos_en_texto(file_path, max_bytes=secret_limits[0],
                                                     max_lines=secret_limits[1], encoding=encoding_hint,
                                                     enable_heuristics=malware_heuristics)
        info["alertas_seguridad"].extend(secretos)
        if extra:
            info.update(extra)

        # patrones rápidos
        quick_patterns = [
            (re.compile(r'(?<!\w)eval\s*\('), "⚠️ eval()"),
            (re.compile(r'(?<!\w)exec\s*\('), "⚠️ exec()"),
            (re.compile(r'__import__\s*\('), "⚠️ dynamic import"),
            (re.compile(r'(subprocess\.call|os\.system)'), "⚠️ shell execution"),
            (re.compile(r'base64\.b64decode'), "⚠️ base64 decode"),
        ]
        try:
            with open(file_path, 'r', encoding=encoding_hint, errors='ignore') as f:
                sample = f.read(100_000)
            for rx, label in quick_patterns:
                if rx.search(sample):
                    info["alertas_seguridad"].append(label)
        except Exception:
            pass

    elif mime.startswith("image/"):
        meta = extract_exif_summary(file_path)
        if "error" in meta:
            info["detalles_contextuales"].append(T["img_meta_error"])
        else:
            detl = []
            if "size" in meta:
                detl.append(T["img_dim"].format(w=meta["size"][0], h=meta["size"][1]))
            if "format" in meta:
                detl.append(T["img_fmt"].format(fmt=meta["format"]))
            if "mode" in meta:
                detl.append(T["img_mode"].format(mode=meta["mode"]))
            if meta.get("gps") or meta.get("fields"):
                detl.append(T["media_meta_present"])
            if detl:
                info["detalles_contextuales"].append(", ".join(detl))

    else:
        kind = is_executable_magic(file_path)
        if kind:
            info["detalles_contextuales"].append(T["exec_file"].format(k=kind))
            if kind == "ELF":
                info["detalles_avanzados"].extend(analyze_elf_header(file_path))
                comp = run_readelf_comment(file_path)
                if comp:
                    info["detalles_contextuales"].append(f"{T['compiler']} {comp}")
            elif kind == "PE":
                pe_det, pe_alerts = analyze_pe_header(file_path)
                info["detalles_avanzados"].extend(pe_det)
                info["alertas_seguridad"].extend(pe_alerts)
            if info.get("entropia") and info["entropia"] >= 7.2:
                info["alertas_seguridad"].append(T["high_entropy_exec"].format(ent=info["entropia"]))
        media = extract_media_info(file_path)
        if media:
            det = []
            if media.get("duration_ms"):
                det.append(T["media_duration"].format(dur=media["duration_ms"] / 1000.0))
            if media.get("overall_bitrate"):
                det.append(T["media_bitrate"].format(br=media["overall_bitrate"] // 1000))
            if det:
                info["detalles_avanzados"].extend(det)

    # Office/PDF
    pdf_det, pdf_alerts = analyze_office_pdf(file_path, mime)
    info["detalles_avanzados"].extend(pdf_det)
    info["alertas_seguridad"].extend(pdf_alerts)

    # Comprimidos
    if archives_mode in ("list", "deep"):
        arch = analyze_archives(file_path, archives_mode, secret_limits, enable_heuristics=malware_heuristics)
        if arch:
            arch_alerts = arch.pop("_archive_security_alerts", [])
            if arch_alerts:
                info["alertas_seguridad"].extend(arch_alerts)
            info.update(arch)

    # YARA
    if yara_runner:
        matches = yara_runner.scan_file(file_path)
        if matches:
            info["yara_matches"] = matches

    # Plugins
    if plugin_mgr:
        plug_out = plugin_mgr.run(file_path, info)
        if plug_out:
            info.update(plug_out)

    # VirusTotal (defer hasta calcular hashes)
    if vt_api_key:
        info["_vt_defer"] = True

    return info


# =================== Export (HTML/PDF) ===================
DEFAULT_TEMPLATE = """<!DOCTYPE html>
<html lang="{lang}"><head>
<meta charset="utf-8"><title>fileinspect report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;margin:2rem;background:#f5f7fb}
h1{margin-top:0}
.card{background:#fff;border:1px solid #e6e8ef;border-radius:12px;box-shadow:0 2px 8px rgba(10,10,20,.04);margin:1rem 0;padding:1rem 1.25rem}
.grid{display:grid;grid-template-columns:180px 1fr;gap:.5rem .75rem;margin:.5rem 0}
.badge{display:inline-block;background:#fff7d6;border:1px solid #f0c36d;padding:.1rem .4rem;border-radius:.3rem;margin:.12rem .25rem .12rem 0}
.kv{font-family:ui-monospace,Consolas,monospace;white-space:pre-wrap}
small{color:#666}
details{margin-top:.5rem}
summary{cursor:pointer}
table{border-collapse:collapse;width:100%;margin:.5rem 0}
th,td{border:1px solid #e6e8ef;padding:6px 8px;vertical-align:top}
th{background:#fafbfd;text-align:left}
</style>
</head><body>
<h1>🔍 fileinspect report</h1>
<p><small>Generated at {now}</small></p>
{body}
</body></html>
"""


def render_html_report(results: List[Dict[str, Any]]) -> str:
    rows = []
    for info in results:
        alerts = "".join(f'<span class="badge">{_html.escape(str(a))}</span>' for a in info.get("alertas_seguridad", []))
        det = "<br>".join(_html.escape(str(x)) for x in info.get("detalles_contextuales", []))
        adv = "<br>".join(_html.escape(str(x)) for x in info.get("detalles_avanzados", []))
        hashes = info.get("hashes", {})
        htable = "".join(f"<div class='kv'>{_html.escape(k.upper())}: {_html.escape(str(v))}</div>" for k, v in hashes.items())
        arch = info.get("archive")
        arch_html = ""
        if arch:
            arch_rows = "".join(
                f"<tr><td>{_html.escape(str(e['name']))}</td><td>{_html.escape(str(e['size']))}</td>"
                f"<td>{_html.escape(str(e['type']))}</td><td>{_html.escape(' '.join(e.get('alerts', [])))}</td></tr>"
                for e in arch.get("entries", [])
            )
            arch_html = (
                f"<details><summary>Archive: {_html.escape(str(arch.get('type')))}</summary>"
                f"<table><tr><th>Name</th><th>Size</th><th>Type</th><th>Alerts</th></tr>{arch_rows}</table></details>"
            )
        yara_html = ""
        if info.get("yara_matches"):
            yara_html = f"<div><strong>YARA:</strong> {_html.escape(' ,'.join(info['yara_matches']))}</div>"
        rows.append(f"""
        <div class="card">
            <div class="grid">
                <div><strong>{_html.escape(T['file'])}</strong></div><div>{_html.escape(str(info['nombre']))}</div>
                <div><strong>{_html.escape(T['mime'])}</strong></div><div>{_html.escape(str(info.get('tipo_mime', '')))}</div>
                <div><strong>{_html.escape(T['size'])}</strong></div><div>{_html.escape(str(info.get('tamaño_formateado', format_size_iec(info.get('tamaño_bytes', 0)))))}</div>
                <div><strong>{_html.escape(T['perms'])}</strong></div><div>{_html.escape(str(info.get('permisos', '')))}</div>
                <div><strong>{_html.escape(T['owner'])}</strong></div><div>{_html.escape(str(info.get('propietario', '')))}</div>
                <div><strong>{_html.escape(T['alerts'])}</strong></div><div>{alerts}</div>
            </div>
            <div>{det}</div>
            <div>{adv}</div>
            {arch_html}
            {yara_html}
            <div>{htable}</div>
        </div>""")
    body = "\n".join(rows)
    # SAFE format (CSS braces)
    html = safe_format(DEFAULT_TEMPLATE,
                       lang=("en" if T is I18N["en"] else "es"),
                       now=datetime.now().isoformat(),
                       body=body)
    return html


def export_report(results: List[Dict[str, Any]], kind: str, template_path: Optional[Path], out_base: Path) -> List[Path]:
    if template_path:
        # Permitir plantillas con CSS; solo {data} será placeholder
        template_text = template_path.read_text(encoding="utf-8")
        html = safe_format(template_text, data=json.dumps(results, ensure_ascii=False, indent=2))
    else:
        html = render_html_report(results)

    out_paths: List[Path] = []
    html_path = out_base.with_suffix(".html")
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(html, encoding="utf-8")
    print(T["export_html_done"].format(p=html_path))
    out_paths.append(html_path)
    if kind == "pdf":
        if not WEASYPRINT_AVAILABLE:
            print(T["export_pdf_unavailable"], file=sys.stderr)
        else:
            pdf_path = out_base.with_suffix(".pdf")
            WEASY_HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            print(T["export_pdf_done"].format(p=pdf_path))
            out_paths.append(pdf_path)
    return out_paths


# =================== Dependencias (safety / npm audit) ===================
def analyze_dependencies(path: Path) -> List[str]:
    details = []
    if path.name == "requirements.txt" and shutil_which("safety"):
        try:
            result = subprocess.run(
                ["safety", "check", "--file", str(path), "--json"],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode != 0:
                details.append(T["dep_vuln"])
        except Exception as e:
            logging.debug("Safety check error: %s", e)
    elif path.name == "package.json" and shutil_which("npm"):
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True, text=True, timeout=30, cwd=str(path.parent)
            )
            data = json.loads(result.stdout or "{}")
            vulns = data.get("metadata", {}).get("vulnerabilities", {})
            total = sum(vulns.values()) if isinstance(vulns, dict) else 0
            if total > 0:
                details.append(T["dep_vuln"])
        except Exception as e:
            logging.debug("npm audit error: %s", e)
    return details


# =================== CLI ===================
def parse_algos(s: str) -> Tuple[str, ...]:
    parts = [p.strip().lower() for p in s.split(",") if p.strip()]
    if not parts:
        raise argparse.ArgumentTypeError("Empty algorithm list")
    return tuple(parts)


def main(argv: Optional[List[str]] = None) -> int:
    _ensure_utf8_stdio()
    global T
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--jsonl", action="store_true")
    parser.add_argument("-o", "--output", type=str, help="Output file path")
    parser.add_argument("--fail-on-alert", "--strict", dest="fail_on_alert", action="store_true")
    parser.add_argument("--nofollow", action="store_true")
    parser.add_argument("--utc", action="store_true")
    parser.add_argument("--lang", choices=["auto", "en", "es"], default="auto")

    # Verbose / debug
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("--debug", action="store_true")

    # Recursivo y filtros
    parser.add_argument("-r", "--recursive", action="store_true")
    parser.add_argument("--include-pattern", default="", help="Comma globs, e.g. *.py,*.json")
    parser.add_argument("--exclude-dir", default="__pycache__,.git,.hg,.svn,.venv,node_modules")
    parser.add_argument("--exclude-pattern", default="")
    parser.add_argument("--max-depth", type=int)

    # Tamaño
    size_group = parser.add_mutually_exclusive_group()
    size_group.add_argument("-b", "--bytes", action="store_true")
    size_group.add_argument("-k", "--kb", action="store_true")
    size_group.add_argument("-m", "--mb", action="store_true")
    size_group.add_argument("-g", "--gb", action="store_true")

    # Hashes / secretos
    parser.add_argument("--no-hash", action="store_true")
    parser.add_argument("--hash", type=parse_algos, default=("sha256",))
    parser.add_argument("--max-secret-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--max-secret-lines", type=int, default=800)

    # Extras
    parser.add_argument("--compare", help="FILE2")
    parser.add_argument("--export", choices=["html", "pdf"])
    parser.add_argument("--template")
    parser.add_argument("--html", help="Back-compat: export only HTML to this file")
    parser.add_argument("--db-path", default=str(default_db_path()))
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--archives", choices=["off", "list", "deep"], default="off")
    parser.add_argument("--yara-rules", default="")
    parser.add_argument("--malware-heuristics", action="store_true")
    parser.add_argument("--plugins-dir", default="")
    parser.add_argument("--history-show", type=int, default=0)
    parser.add_argument("--vt-api-key", type=str)

    parser.add_argument("path", nargs='?')

    # pre-parse para idioma / logging
    args, _ = parser.parse_known_args(argv)
    lang = choose_lang(args.lang)
    T = I18N[lang]

    if args.help or (not args.path and not args.history_show):
        # USAR safe_format para imprimir ayuda con llaves literales
        print(safe_format(T["usage"], prog=Path(sys.argv[0]).name))
        return 0

    # logging
    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2 or args.debug:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    # Historial
    db_path = Path(args.db_path)
    cache = HashCache(db_path, enable_cache=not args.no_cache)
    if args.history_show:
        rows = cache.show_history(args.history_show)
        if args.json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        elif args.jsonl:
            for r in rows:
                print(json.dumps(r, ensure_ascii=False))
        else:
            for r in rows:
                ts = datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S")
                print(f"{ts}  {r['path']}  sha256={r.get('sha256')}  size={r.get('size')}")
        return 0

    include_patterns = [p for p in (args.include_pattern.split(",") if args.include_pattern else []) if p]
    exclude_dirs = [d for d in (args.exclude_dir.split(",") if args.exclude_dir else []) if d]
    exclude_patterns = [p for p in (args.exclude_pattern.split(",") if args.exclude_pattern else []) if p]

    yara_runner = None
    if args.yara_rules:
        if not YARA_AVAILABLE:
            print(T["yara_missing"], file=sys.stderr)
        else:
            rules_paths = [Path(p.strip()) for p in args.yara_rules.split(",") if p.strip()]
            yara_runner = YaraRunner(rules_paths)

    plugin_mgr = None
    if args.plugins_dir:
        plugin_mgr = PluginManager([Path(args.plugins_dir)])
        print(T["plugins_loaded"].format(n=len(plugin_mgr.plugins)))

    # Tamaño
    size_opt = "auto"
    if args.bytes:
        size_opt = "bytes"
    elif args.kb:
        size_opt = "kb"
    elif args.mb:
        size_opt = "mb"
    elif args.gb:
        size_opt = "gb"

    path = Path(args.path) if args.path else None
    if not path or (not path.exists() and not path.is_symlink()):
        print(f"{T['error']}: " + T["file_not_found"].format(f=path), file=sys.stderr)
        return 1

    # Objetivos
    targets: List[Path] = []
    if (path.is_dir() and not (path.is_symlink() and args.nofollow)) or args.recursive:
        root = path if path.is_dir() else path.parent
        for p in walk_filtered(root, include_patterns, exclude_dirs, exclude_patterns, args.max_depth):
            targets.append(p)
        if path.is_file() or path.is_symlink():
            targets.append(path)
        seen = set()
        uniq = []
        for p in targets:
            if p in seen:
                continue
            seen.add(p)
            uniq.append(p)
        targets = uniq
    else:
        targets = [path]

    # Comparación de dos ficheros (modo simple)
    if args.compare:
        file2 = Path(args.compare)
        if not file2.exists():
            print(f"{T['error']}: " + T["file_not_found"].format(f=file2), file=sys.stderr)
            return 1
        st1 = path.stat()
        st2 = file2.stat()
        hashes1 = calcular_hashes(path, args.hash, cache, st1) if not args.no_hash else {}
        hashes2 = calcular_hashes(file2, args.hash, cache, st2) if not args.no_hash else {}
        comp = []
        any_diff = False
        for algo in args.hash:
            v1, v2 = hashes1.get(algo), hashes2.get(algo)
            same = (v1 == v2) and v1 not in (None, T["hash_read_error"], T["hash_invalid_algo"])
            if not same:
                any_diff = True
            comp.append({"algo": algo, "same": same, "a": v1, "b": v2})
        out = {"compare": {"a": str(path), "b": str(file2), "diffs": comp}}
        if args.json:
            print(json.dumps(out, indent=2, ensure_ascii=False))
            return 2 if (args.fail_on_alert and any_diff) else 0
        print(c(T["compare_header"], "1;36"))
        for d in comp:
            msg = T["compare_same"] if d["same"] else T["compare_diff"]
            print(" - " + msg.format(algo=d["algo"].upper()))
        return 2 if (args.fail_on_alert and any_diff) else 0

    # Procesamiento
    results: List[Dict[str, Any]] = []
    for p in targets:
        try:
            info = get_file_info(
                str(p),
                follow_symlinks=not args.nofollow,
                utc_times=args.utc,
                secret_limits=(args.max_secret_bytes, args.max_secret_lines),
                yara_runner=yara_runner,
                malware_heuristics=args.malware_heuristics,
                archives_mode=args.archives,
                plugin_mgr=plugin_mgr,
                vt_api_key=(args.vt_api_key or os.getenv("VT_API_KEY")),
            )
            # tamaño formateado
            size_bytes = info.get("tamaño_bytes", 0)
            if size_opt == "bytes":
                size_fmt = f"{size_bytes:,} B"
            elif size_opt == "kb":
                size_fmt = f"{size_bytes / 1000:.2f} KB"
            elif size_opt == "mb":
                size_fmt = f"{size_bytes / 1_000_000:.2f} MB"
            elif size_opt == "gb":
                size_fmt = f"{size_bytes / 1_000_000_000:.2f} GB"
            else:
                size_fmt = format_size_iec(size_bytes)
            info["tamaño_formateado"] = size_fmt

            st = None
            try:
                st = Path(info["nombre"]).stat() if not (info.get("es_symlink") and args.nofollow) else Path(info["nombre"]).lstat()
            except Exception:
                pass

            if not args.no_hash and st and stat.S_ISREG(st.st_mode):
                info["hashes"] = calcular_hashes(Path(info["nombre"]), args.hash, cache, st)
            else:
                info["hashes"] = {}

            # VirusTotal si procede
            if info.get("_vt_defer"):
                sha256 = info["hashes"].get("sha256")
                if sha256 and "ERROR" not in sha256:
                    vt = check_virustotal(sha256, args.vt_api_key)
                    if vt:
                        if vt["malicious"] == 0 and vt["suspicious"] == 0:
                            info["detalles_avanzados"].append(T["vt_clean"].format(total=vt["total"]))
                        else:
                            info["alertas_seguridad"].append(
                                T["vt_suspicious"].format(mal=vt["malicious"], sus=vt["suspicious"], total=vt["total"])
                            )
                    else:
                        info["detalles_avanzados"].append(T["vt_error"])
                info.pop("_vt_defer", None)

            # dependencias típicas
            info["alertas_seguridad"].extend(analyze_dependencies(Path(info["nombre"])))

            # guardar historial
            sha256 = info["hashes"].get("sha256")
            opts_for_hist = {
                "utc": args.utc, "nofollow": args.nofollow, "hash": list(args.hash),
                "archives": args.archives, "malware_heuristics": args.malware_heuristics
            }
            try:
                cache.save_history(Path(info["nombre"]), st, sha256, opts_for_hist, info)
            except Exception as e:
                logging.debug("history save error: %s", e)

            results.append(info)
        except FileNotFoundError as e:
            logging.error(str(e))
        except Exception as e:
            logging.error("%s: %s", T["error"], e)

    # Salidas
    if args.export or args.html:
        out_base = Path(args.html) if args.html else (Path(args.output) if args.output else (Path.cwd() / f"fileinspect_report_{int(time.time())}"))
        template_path = Path(args.template) if args.template else None
        export_kind = "html" if args.html else args.export
        export_report(results, export_kind, template_path, out_base)

    if args.jsonl:
        lines = [json.dumps(r, ensure_ascii=False) for r in results]
        payload = "\n".join(lines) + ("\n" if lines else "")
        if args.output and not (args.export or args.html):
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(payload, encoding="utf-8")
        else:
            print(payload, end="")
    elif args.json:
        payload = json.dumps(results if len(results) != 1 else results[0], indent=2, ensure_ascii=False)
        if args.output and not (args.export or args.html):
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(payload + "\n", encoding="utf-8")
        else:
            print(payload)
    elif not args.export and not args.html:
        for info in results:
            print(c(T["file"], "1;36"), f"     {info['nombre']}")
            if info.get("realpath") and info["realpath"] != info["nombre"]:
                print(c(T["realpath"], "1;36"), f"   {info['realpath']}")
            if info.get("es_symlink"):
                print(c(T["symlink"], "1;36"), f"    {T['details_arrow']} {info.get('destino_symlink')}")
            print(c(T["mime"], "1;36"), f" {info.get('tipo_mime', '')}")
            print(c(T["size"], "1;36"), f"    {info.get('tamaño_formateado', '')}")
            if info.get("entropia") is not None:
                print(c(T["entropy"], "1;36"), f" {info['entropia']:.2f} / 8.00 bits/byte")
            print("-" * 40)
            print(c(T["perms"], "1;36"), f" {info.get('permisos', '')} (Inodo: {info.get('inodo')})")  # noqa
            print(c(T["owner"], "1;36"), f" {info.get('propietario', '')}")  # noqa
            if info.get('alertas_seguridad'):
                print(c(T["alerts"], "1;33"))
                for a in info['alertas_seguridad']:
                    print(f"  - {a}")
            print("-" * 40)
            print(c(T["modified"], "1;36"), f"  {info.get('fecha_mod')}")
            print(c(T["accessed"], "1;36"), f"  {info.get('fecha_acc')}")
            print(c(T["created"], "1;36"), f"  {info.get('fecha_cre')}")
            if info.get('detalles_contextuales'):
                print("-" * 40)
                for d in info['detalles_contextuales']:
                    print(c(T["details_arrow"], "1;32"), d)
            if info.get('detalles_avanzados'):
                print("-" * 40)
                print(c(T["advanced"], "1;35"))
                for d in info['detalles_avanzados']:
                    print(c(T["details_arrow"], "1;35"), d)
            if info.get("archive"):
                print("-" * 40)
                print("Archive:", info["archive"].get("type"))
                for e in info["archive"].get("entries", []):
                    print(f"   - {e['name']} ({e['size']}) [{e['type']}] {' '.join(e.get('alerts', []))}")
            if info.get("yara_matches"):
                print("-" * 40)
                print("YARA:", ", ".join(info["yara_matches"]))
            print("-" * 40)
            print(c(T["integrity"], "1;36"))
            for algo, h in info.get("hashes", {}).items():
                print(f"  {algo.upper()}: {h}")
            print()

    if args.fail_on_alert:
        has_alerts = any(
            bool(r.get("alertas_seguridad")) or bool(r.get("yara_matches")) or bool(r.get("malware_heuristics"))
            for r in results
        )
        if has_alerts:
            return 2

    return 0


def cli_main():
    raise SystemExit(main())


if __name__ == "__main__":
    cli_main()
