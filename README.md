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
    - [🌐 sabbat-netinspect — Network & Connections Inspector](#-sabbat-netinspect--network--connections-inspector)
      - [cronaudit subcommand (Cron + systemd timers)](#cronaudit-subcommand-cron--systemd-timers)
  - [Troubleshooting](#troubleshooting)
  - [Development](#development)
  - [Contributing](#contributing)
  - [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# 🧰 sabbat-tools — System & Security CLI Toolbox

[![CI](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci-lean.yml/badge.svg)](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci-lean.yml)
![Python Versions](https://img.shields.io/badge/python-3.8--3.12-informational)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#license)

**sabbat-tools** is a collection of production-ready command‑line utilities for sysadmins, SREs and security engineers.

- Bilingual UX (auto/en/es) where applicable
- Automation‑friendly (clean JSON/JSONL & predictable exit codes)
- Thoughtful hardening: input limits, ReDoS‑safe regex paths, safe output confinement

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
```

After install, you’ll have the `sabbat-loganalyce`, `sabbat-fileinspect`, `sabbat-syscheck` and `sabbat-netinspect` commands on PATH.

---

## Requirements & Extras

* Python ≥ 3.8
* Optional extras:
  * `hardened`: `regex` (ReDoS‑resistant scanning). `re2` intentionally excluded for portability.
  * `geoip`: `geoip2` + **MaxMind GeoLite2‑Country.mmdb** (put it in `/var/lib/GeoIP/` or pass `--geoip-db`).
  * `detect`: `chardet` and `python-magic` (or `python-magic-bin` on Windows) for robust MIME/encoding detection.
  * `images`: `Pillow` to safely read image metadata.
  * `sys`: `psutil`, `distro`, `humanfriendly`.
  * `net`: `psutil`, `ifaddr`, `dnspython`, `requests`, (`pyroute2` on Linux).

---

## Commands

### 📊 sabbat-loganalyce — Advanced Log Analyzer
[Manual](docs/LOGANALYCE.md) · [In Spanish](docs/LOGANALYCE-ES.md)

Reads plain or `.gz` logs (also from stdin) and outputs statistics, security signals and JSON/JSONL.

**Examples**
```bash
# Full analysis (columns)
sabbat-loganalyce samples/access.log

# Pattern search (first 50, ordered)
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50

# JSON output
sabbat-loganalyce app.log --json
```

---

### 🕵️ sabbat-fileinspect — File Inspector
[Manual](docs/FILEINSPECT.md) · [In Spanish](docs/FILEINSPECT-ES.md)

Security‑focused, portable file inspector. Understands text, images and common binary types.

```bash
# Force Spanish + UTC + multiple hashes + JSON
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts
```

---

### 🔧 sabbat-syscheck — System Auditor (read-only)
[Manual](docs/SYSCHECK.md) · [In Spanish](docs/SYSCHECK-ES.md)

Lightweight, non‑intrusive auditor inspired by tools like Lynis. Scans SSH configuration, permissions, users and cron.

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
- Unified listing of **cron jobs** (system/user) & **systemd timers**.
- Detects **dangerous patterns**: `rm -rf /`, `curl|bash`, `wget|bash`, `chmod 777`, base64→shell, `nc -e`, reverse shells, cryptominers, `http://` fetch.
- **Path/Resolution**: non-absolute first token, unresolved binary.
- **Env vars**: `$VAR` / `${VAR}` without default `${VAR:-def}`.
- **Privileges**: tasks likely needing root vs. running as root without indication.
- **Orphans**: missing user, missing binary, missing `.service` behind a timer.
- JSON output ready for SIEM ingestion.

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

### 🌐 sabbat-netinspect — Network & Connections Inspector
[Manual](docs/NETINSPECT.md) · [In Spanish](docs/NETINSPECT-ES.md)
See [Troubleshooting](docs/NETINSPECT-TROUBLESHOOTING-ES.md)

Portable (psutil‑based) inspector for live network state: connections, listening ports, process correlation, optional GeoIP, local threat intel, port whitelist checks, snapshots & diffs.

**Examples**
```bash
# JSON with GeoIP and connection cap
sabbat-netinspect --json --geoip-db /var/lib/GeoIP/GeoLite2-Country.mmdb --max-conns 500

# Threat‑intel CSV + whitelist check for listening ports
sabbat-netinspect --check-threat-intel --ti-csv feeds/blacklist.csv                       --check-ports --whitelist /etc/allowed_ports.conf
```
---

## Troubleshooting
- `re2` not available: safe to ignore; `regex` provides hardened engine.
- GeoIP DB missing: use `--geoip-db` or skip GeoIP features.
- Colors in CI: export `NO_COLOR=1`.

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
    │   ├── FILEINSPECT-ES.md
    │   ├── FILEINSPECT.md
    │   ├── LOGANALYCE-ES.md
    │   ├── LOGANALYCE.md
    │   ├── NETINSPECT-ES.md
    │   ├── NETINSPECT-TROUBLESHOOTING-ES.md
    │   ├── NETINSPECT-TROUBLESHOOTING.md
    │   ├── NETINSPECT.md
    │   ├── SYSCHECK-ES.md
    │   └── SYSCHECK.md
    ├── pyproject.toml
    ├── pytest.ini
    ├── requirements-dev.txt
    ├── requirements.txt
    ├── sabbat_tools
    │   ├── __init__.py
    │   ├── audits
    │   ├── fileinspect.py
    │   ├── loganalyce.py
    │   ├── netinspect.py
    │   └── syscheck.py
    ├── scripts
    │   └── gen_toc.py
    ├── tests
    │   ├── conftest.py
    │   ├── pysql
    │   ├── test_fileinspect.py
    │   ├── test_loganalyce.py
    │   ├── test_netinspect.py
    │   └── test_syscheck.py
    └── tree.txt
```

---

## Contributing
PRs and issues welcome. Please keep the philosophy:
- Safe‑by‑default, robust tests, clear UX.
- New commands should come with tests and a README section.

---

## License
MIT © Óscar Giménez Blasco

