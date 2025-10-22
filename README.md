````markdown
<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [🧰 sabbat-tools — System & Security CLI Toolbox](#-sabbat-tools--system--security-cli-toolbox)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Requirements & Extras](#requirements--extras)
  - [Commands](#commands)
    - [📊 sabbat-loganalyce — Advanced Log Analyzer](#-sabbat-loganalyce--advanced-log-analyzer)
    - [🕵️ sabbat-fileinspect — File Inspector](#-sabbat-fileinspect--file-inspector)
    - [🔧 sabbat-syscheck — System Auditor (read-only)](#-sabbat-syscheck--system-auditor-read-only)
      - [cronaudit subcommand (Cron + systemd timers)](#cronaudit-subcommand-cron--systemd-timers)
    - [📝 sabbat-rawtext — Plain-Text Extractor (.docx/.odt/.ods/.txt)](#-sabbat-rawtext--plaintext-extractor-docxodtodsTxt)
    - [🌐 sabbat-netinspect — Network & Connections Inspector](#-sabbat-netinspect--network--connections-inspector)
  - [Troubleshooting](#troubleshooting)
  - [Development](#development)
  - [Contributing](#contributing)
  - [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# 🧰 sabbat-tools — System & Security CLI Toolbox

[![CI](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci-lean.yml/badge.svg)](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci-lean.yml)
![Python Versions](https://img.shields.io/badge/python-3.8--3.12-informational)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#license)

**sabbat-tools** is a collection of production-ready command-line utilities for sysadmins, SREs and security engineers.

- Bilingual UX (auto/en/es) where applicable
- Automation-friendly (clean JSON/JSONL & predictable exit codes)
- Thoughtful hardening: input limits, ReDoS-safe regex paths, safe output confinement

> **Español**: ¿Prefieres documentación en español? [🇪🇸 Español](README-ES.md)
---

---
## Table of Contents
- [Installation](#installation)
- [Requirements & Extras](#requirements--extras)
- [Commands](#commands)
  - [📊 sabbat-loganalyce — Advanced Log Analyzer](#-sabbat-loganalyce--advanced-log-analyzer)
  - [🕵️ sabbat-fileinspect — File Inspector](#-sabbat-fileinspect--file-inspector)
  - [🔧 sabbat-syscheck — System Auditor (read-only)](#-sabbat-syscheck--system-auditor-read-only)
  - [📝 sabbat-rawtext — Plain-Text Extractor (.docx/.odt/.ods/.txt)](#-sabbat-rawtext--plaintext-extractor-docxodtodsTxt)
  - [🌐 sabbat-netinspect — Network & Connections Inspector](#-sabbat-netinspect--network--connections-inspector)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)
---

## Installation

```bash
# Clone (dev)
git clone https://github.com/Sabbat-cloud/sabbat-tools
cd sabbat-tools

# Recommended: all features
pip install -e ".[full]"

# or user-wide isolated:
# pipx install "sabbat-tools[full]"
````

After install, you’ll have the `sabbat-loganalyce`, `sabbat-fileinspect`, `sabbat-syscheck`, **`sabbat-rawtext`**, and `sabbat-netinspect` commands on PATH.

---

## Requirements & Extras

* Python ≥ 3.8
* Optional extras:

  * `hardened`: `regex` (ReDoS-resistant scanning). `re2` intentionally excluded for portability.
  * `geoip`: `geoip2` + **MaxMind GeoLite2-Country.mmdb** (put it in `/var/lib/GeoIP/` or pass `--geoip-db`).
  * `detect`: `chardet` and `python-magic` (or `python-magic-bin` on Windows) for robust MIME/encoding detection.
  * `images`: `Pillow` to safely read image metadata.
  * `sys`: `psutil`, `distro`, `humanfriendly`.
  * `net`: `psutil`, `ifaddr`, `dnspython`, `requests`, (`pyroute2` on Linux).
  * **`codecs` (new)**: `zstandard` to read `.zst` logs in **sabbat-loganalyce** (other formats built-in: `.gz`, `.bz2`, `.xz`, `.lzma`).
  * **`text` (new)**: `python-docx`, `odfpy` for **sabbat-rawtext** (DOCX/ODT/ODS → TXT).

---

## Commands

### 📊 sabbat-loganalyce — Advanced Log Analyzer

[Manual](docs/LOGANALYCE.md) · [In Spanish](docs/LOGANALYCE-ES.md)

Reads plain logs or compressed logs by **magic bytes**: `.gz`, `.bz2`, `.xz`, `.lzma`, and `.zst` (if `zstandard` installed). Supports stdin, time filters, GeoIP, multi-threaded stats, and hardened regex mode.

**Highlights (recent)**

* Compression auto-detect by magic bytes (no need to rely on file extension).
* Permission-aware errors with i18n messages.
* Early **large-log prescan** + byte/line safety caps.
* Hardened regex option (`--hardened-regex`) using the `regex` module.
* Predictable exit codes: `0` ok · `1` runtime error · `2` security alerts or permission/unsupported codec errors.
* Safe output confinement (CWD) unless `--unsafe-output`.
* Stdin enable/disable with `--deny-stdin`.
* Better JSON schema + GeoIP LRU cache.

**Examples**

```bash
# Full analysis (columns)
sabbat-loganalyce samples/access.log

# Read compressed (auto-detect): gz/bz2/xz/lzma/zst*
sabbat-loganalyce logs/access.log.gz
sabbat-loganalyce logs/access.log.bz2
sabbat-loganalyce logs/access.log.xz
sabbat-loganalyce logs/access.log.lzma
sabbat-loganalyce logs/access.log.zst       # requires: pip install zstandard

# Pattern search (first 50, ordered)
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50

# JSON output + hardened regex + time window
sabbat-loganalyce app.log --json --hardened-regex --since "2025-09-01" --until "2025-09-30 23:59:59"
```

**Exit codes**

* `0` success (no security alerts)
* `2` security alerts detected (SQLi/XSS/traversal) **or** permission/unsupported codec errors
* `1` other runtime errors

---

### 🕵️ sabbat-fileinspect — File Inspector

[Manual](docs/FILEINSPECT.md) · [In Spanish](docs/FILEINSPECT-ES.md)

Security-focused, portable file inspector. Understands text, images and common binary types.

```bash
# Force Spanish + UTC + multiple hashes + JSON
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts
```

---

### 🔧 sabbat-syscheck — System Auditor (read-only)

[Manual](docs/SYSCHECK.md) · [In Spanish](docs/SYSCHECK-ES.md)

Lightweight, non-intrusive auditor inspired by tools like Lynis. Scans SSH configuration, permissions, users and cron.

**Examples**

```bash
# Run all modules (default)
sabbat-syscheck

# JSON for dashboards/ingestion
sabbat-syscheck --json > syscheck.json
sabbat-syscheck --jsonl | jq .

# Raw TSV (easy grepping)
sabbat-syscheck --raw --no-group | column -t -s $'\t'
```

#### cronaudit subcommand (Cron + systemd timers)

**What it does**

* Unified listing of **cron jobs** (system/user) & **systemd timers**.
* Detects **dangerous patterns**: `rm -rf /`, `curl|bash`, `wget|bash`, `chmod 777`, base64→shell, `nc -e`, reverse shells, cryptominers, `http://` fetch.
* **Path/Resolution**: non-absolute first token, unresolved binary.
* **Env vars**: `$VAR` / `${VAR}` without default `${VAR:-def}`.
* **Privileges**: tasks likely needing root vs. running as root without indication.
* **Orphans**: missing user, missing binary, missing `.service` behind a timer.
* JSON output ready for SIEM ingestion.

**Examples**

```bash
# Full audit + JSON saved
sabbat-syscheck cronaudit --json --output audits/cron_$(date +%Y%m%d).json

# Only suspicious commands (danger patterns or your regex)
sabbat-syscheck cronaudit --check-dangerous --pattern 'rm -rf|wget|curl.*pipe'

# Privilege focus (root/excess/mismatch)
sabbat-syscheck cronaudit --check-privileges --user root

# Only systemd timers
sabbat-syscheck cronaudit --only timers
```

---

### 📝 sabbat-rawtext — Plain-Text Extractor (.docx/.odt/.ods/.txt)

Convert Office/OpenDocument files to clean **UTF-8 `.txt`** locally. Preserves reading order, flattens tables (row → line, cells joined by spaces) and saves robustly on Windows (sanitized names, fallback to *Documents*/temp, `-1`, `-2` suffixes if busy).

**Requires**: extra `text` (`python-docx`, `odfpy`) — included in `[full]`.

**Examples**

```bash
# Interactive (asks for a file path)
sabbat-rawtext

# Non-interactive (one or more files)
sabbat-rawtext "Report Q3.docx" sheet.ods notes.odt

# Wildcards (on Windows, globs are expanded internally)
sabbat-rawtext *.docx docs/*.odt "invoices 2025/*.ods"
```

**Notes**

* Supported: `.docx`, `.odt`, `.ods`, `.txt` (re-normalizes).
* Legacy `.doc` → not supported (convert to `.docx` first).
* Exit code: `0` all OK, `1` if any target failed (unsupported/read/save).

---

### 🌐 sabbat-netinspect — Network & Connections Inspector

[Manual](docs/NETINSPECT.md) · [In Spanish](docs/NETINSPECT-ES.md)
See [Troubleshooting](docs/NETINSPECT-TROUBLESHOOTING-ES.md)

Portable (psutil-based) inspector for live network state: connections, listening ports, process correlation, optional GeoIP, local threat intel, port whitelist checks, snapshots & diffs.

**Examples**

```bash
# JSON with GeoIP and connection cap
sabbat-netinspect --json --geoip-db /var/lib/GeoIP/GeoLite2-Country.mmdb --max-conns 500

# Threat-intel CSV + whitelist check for listening ports
sabbat-netinspect --check-threat-intel --ti-csv feeds/blacklist.csv                       --check-ports --whitelist /etc/allowed_ports.conf
```

---

## Troubleshooting

* `re2` not available: safe to ignore; `regex` provides hardened engine.
* GeoIP DB missing: use `--geoip-db` or skip GeoIP features.
* Colors in CI: export `NO_COLOR=1`.
* **Compressed logs**: `.zst` requires `pip install zstandard`. Other formats work out-of-the-box.
* **Permissions**: if you get “permission denied”, try `sudo` or adjust ACLs on the log path.

---

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

Project layout (simplified):

```
sabbat_tools/
    ├── CHANGELOG.md
    ├── LICENSE
    ├── MANIFEST.in
    ├── Makefile
    ├── README-ES.md
    ├── README.md
    ├── docs
    │   ├── FILEINSPECT-ES.md
    │   ├── FILEINSPECT.md
    │   ├── LOGANALYCE-ES.md
    │   ├── LOGANALYCE.md
    │   ├── NETINSPECT-ES.md
    │   ├── NETINSPECT-TROUBLESHOOTING-ES.md
    │   ├── NETINSPECT-TROUBLESHOOTING.md
    │   ├── NETINSPECT.md
    │   ├── SYSCHECK-ES.md
    │   └── SYSCHECK.md
    ├── pyproject.toml
    ├── pytest.ini
    ├── requirements-dev.txt
    ├── requirements.txt
    ├── sabbat_tools
    │   ├── __init__.py
    │   ├── audits
    │   ├── fileinspect.py
    │   ├── loganalyce.py
    │   ├── netinspect.py
    │   ├── rawtext.py
    │   └── syscheck.py
    ├── scripts
    │   └── gen_toc.py
    ├── tests
    │   ├── conftest.py
    │   ├── pysql
    │   ├── test_fileinspect.py
    │   ├── test_loganalyce.py
    │   ├── test_netinspect.py
    │   └── test_syscheck.py
    └── tree.txt
```

---

## Contributing

PRs and issues welcome. Please keep the philosophy:

* Safe-by-default, robust tests, clear UX.
* New commands should come with tests and a README section.

---

## License

MIT © Óscar Giménez Blasco

```


