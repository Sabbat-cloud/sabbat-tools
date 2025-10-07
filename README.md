# 🧰 sabbat-tools — System & Security CLI Toolbox
[![Docs](https://img.shields.io/badge/Docs-English%20%7C%20Espa%C3%B1ol-blue)](README.md)
[🇬🇧 English](README.md) · [🇪🇸 Español](README-ES.md)


[![CI](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/sabbat-tools.svg)](https://pypi.org/project/sabbat-tools/)
![Python Versions](https://img.shields.io/pypi/pyversions/sabbat-tools.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#license)

**sabbat-tools** is a collection of production-ready command-line utilities for sysadmins, SREs, and security engineers.

- ✅ Bilingual UX (`auto`/`en`/`es`) where applicable
- ✅ Safe-by-default & automation-friendly (clean JSON modes & stable exit codes)
- ✅ Thoughtful hardening: input limits, ReDoS-safe regex paths, safe output confinement

> **Español**: ¿Prefieres documentación en español? Lee [README-ES.md](./README-ES.md).

---
<!-- toc -->
- [🧰 sabbat-tools — System & Security CLI Toolbox](#sabbat-tools-system-security-cli-toolbox)
  - [📚 Table of Contents](#table-of-contents)
  - [Installation](#installation)
- [Base install (adds CLIs to PATH)](#base-install-adds-clis-to-path)
- [Recommended for full features:](#recommended-for-full-features)
  - [Requirements & Extras](#requirements-extras)
  - [Commands](#commands)
    - [📊 sabbat-loganalyce — Advanced Log Analyzer](#sabbat-loganalyce-advanced-log-analyzer)
- [Full analysis (columns)](#full-analysis-columns)
- [Pattern search (first 50, ordered)](#pattern-search-first-50-ordered)
- [JSON output](#json-output)
    - [🕵️ sabbat-fileinspect — File Inspector](#sabbat-fileinspect-file-inspector)
- [Force Spanish + UTC + multiple hashes + JSON](#force-spanish-utc-multiple-hashes-json)
    - [🔧 sabbat-syscheck — System Auditor (read-only)](#sabbat-syscheck-system-auditor-read-only)
- [Run all modules (default)](#run-all-modules-default)
- [JSON for dashboards/ingestion](#json-for-dashboardsingestion)
- [Raw TSV (easy grepping)](#raw-tsv-easy-grepping)
- [Limit permissions scan](#limit-permissions-scan)
      - [cronaudit subcommand (Cron + systemd timers)](#cronaudit-subcommand-cron-systemd-timers)
- [Full audit + JSON saved](#full-audit-json-saved)
- [Only suspicious commands (danger patterns or your regex)](#only-suspicious-commands-danger-patterns-or-your-regex)
- [Privilege focus (root/excess/mismatch)](#privilege-focus-rootexcessmismatch)
- [Only systemd timers](#only-systemd-timers)
    - [🌐 sabbat-netinspect — Network & Connections Inspector](#sabbat-netinspect-network-connections-inspector)
- [JSON with GeoIP and connection cap](#json-with-geoip-and-connection-cap)
- [TI (local CSV) + whitelist check for listening ports](#ti-local-csv-whitelist-check-for-listening-ports)
- [Snapshot & diff](#snapshot-diff)
- [comments allowed](#comments-allowed)
  - [Best Practices](#best-practices)
  - [JSON & Exit Codes](#json-exit-codes)
  - [Troubleshooting](#troubleshooting)
  - [Development](#development)
- [Install local (editable) with common extras](#install-local-editable-with-common-extras)
- [Run tests (verbose)](#run-tests-verbose)
- [Lint (ruff)](#lint-ruff)
  - [Contributing](#contributing)
  - [License](#license)
    - [Project Footer](#project-footer)
<!-- tocstop -->


## 📚 Table of Contents

- [Installation](#installation)
- [Requirements & Extras](#requirements--extras)
- [Commands](#commands)
  - [📊 sabbat-loganalyce — Advanced Log Analyzer](#-sabbat-loganalyce--advanced-log-analyzer)
  - [🕵️ sabbat-fileinspect — File Inspector](#-sabbat-fileinspect--file-inspector)
  - [🔧 sabbat-syscheck — System Auditor (read-only)](#-sabbat-syscheck--system-auditor-read-only)
    - [cronaudit subcommand (Cron + systemd timers)](#cronaudit-subcommand-cron--systemd-timers)
- [Best Practices](#best-practices)
- [JSON & Exit Codes](#json--exit-codes)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## Installation

```bash
git clone https://github.com/Sabbat-cloud/sabbat-tools
cd sabbat-tools

# Base install (adds CLIs to PATH)
pip install .

# Recommended for full features:
pip install -e ".[geoip,images,detect,hardened]"
```

> After install, you’ll have the `sabbat-loganalyce`, `sabbat-fileinspect`, and `sabbat-syscheck` commands on PATH.

---

## Requirements & Extras

* **Python** ≥ 3.8
* Optional extras:
  * `hardened`: `regex` (and optionally `re2` if available) for ReDoS-resistant scanning
  * `geoip`: `geoip2` + **MaxMind GeoLite2-Country.mmdb** (place in `/var/lib/GeoIP/` or pass `--geoip-db`)
  * `detect`: `chardet` and `python-magic`/`file(1)` for robust MIME detection in `sabbat-fileinspect`
  * `images`: `Pillow` to safely parse image metadata

---

## Commands

### 📊 sabbat-loganalyce — Advanced Log Analyzer

Reads plain or `.gz` logs, supports `stdin`, and outputs rich statistics, security signals, and JSON.

**Language**
* Auto: `--lang auto` (default)
* Force: `--lang {en|es}`

**Quick Examples**
```bash
# Full analysis (columns)
sabbat-loganalyce access.log

# Pattern search (first 50, ordered)
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50

# JSON output
sabbat-loganalyce app.log --json
```

---

### 🕵️ sabbat-fileinspect — File Inspector

Security-focused, portable file inspector. It understands text, images, and common binary types.

```bash
# Force Spanish + UTC + multiple hashes + JSON
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts
```

---

### 🔧 sabbat-syscheck — System Auditor (read-only)

Lightweight, non-intrusive auditor inspired by tools like Lynis. It scans SSH, file permissions, users, and cron to spot common misconfigurations. **Read-only**, CI-friendly, bilingual (EN/ES), and with stable JSON/JSONL output.

**Modules**
- `--check-ssh` — parse `sshd_config` (e.g., `PermitRootLogin`, `PasswordAuthentication`, `X11Forwarding`, `MaxAuthTries`).
- `--check-perms` — world-writable files/dirs under critical roots (`/etc`, `/var`, `/usr/bin`), sticky-bit aware (1777 → INFO).
- `--check-users` — flags UID 0 duplicates, empty passwords, and system accounts with interactive shells.
- `--check-cron` — robust parser for system/user crons; detects relative commands, `/tmp` usage, and world-writable scripts.

**Output & Exit codes**
- Human: grouped (`--group`/`--no-group`), `--group-show N`
- Machine: `--json`, `--jsonl`, `--raw` (TSV: `RISK\tMODULE\tMESSAGE\tPATH\tEVIDENCE`)
- Exit codes: `0` OK · `1` runtime error · `2` MEDIUM/HIGH findings

**Examples**
```bash
# Run all modules (default)
sabbat-syscheck

# JSON for dashboards/ingestion
sabbat-syscheck --json > syscheck.json
sabbat-syscheck --jsonl | jq .

# Raw TSV (easy grepping)
sabbat-syscheck --raw --no-group | column -t -s $'\t'

# Limit permissions scan
sabbat-syscheck --check-perms --max-files 50000 --exclude /var/lib/docker /snap
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

**Exit codes**
- Classic: `0` if no MEDIUM/HIGH, `2` otherwise.
- `cronaudit`: `0` if no HIGH/CRITICAL findings (or `--dry-run`), `2` otherwise.

**JSON shape**
```json
{
  "ts": "2025-10-07T09:54:21+02:00",
  "host": "node01",
  "tool": "sabbat-syscheck",
  "module": "cronaudit",
  "version": "1.0.0",
  "findings": [
    {
      "kind": "cron",
      "id": "cron:/etc/cron.d/backup:root:...",
      "user": "root",
      "command": "/usr/local/bin/backup ...",
      "issues": [{"code": "cmd.dangerous_pattern", "severity": "critical"}],
      "orphaned": false
    }
  ]
}
```

---

### 🌐 sabbat-netinspect — Network & Connections Inspector

Portable (psutil-based) inspector for **live** network state: active connections, listening ports, process correlation, optional GeoIP, local threat intel (CSV), port whitelist checks, snapshots & diffs.

See [Troubleshooting](docs/NETINSPECT-TROUBLESHOOTING.md)

**Key features**
- TCP/UDP (IPv4/IPv6) + PID→Process correlation (`psutil`)
- Filters: `--proto`, `--state`, `--pid`, `--user`, `--lport`, `--rport`, `--include-unix`
- GeoIP (optional): `--geoip-db /var/lib/GeoIP/GeoLite2-Country.mmdb` (requires `geoip2`)
- Local Threat Intel: `--check-threat-intel --ti-csv feeds/blacklist.csv` (no online calls)
- Whitelist of listening ports: `--check-ports --whitelist /etc/allowed_ports.conf`
- Reverse DNS opt-in: `--rdns`
- Snapshots & diff: `--snapshot --output ...` / `--diff prev.json`
- Outputs: human, `--raw` (TSV), `--json`, `--jsonl`
- Privacy by default (`--sanitize`). Use `--unsafe-proc-cmdline` to include full cmdline.

**Examples**
```bash
# JSON with GeoIP and connection cap
sabbat-netinspect --json --geoip-db /var/lib/GeoIP/GeoLite2-Country.mmdb --max-conns 500

# TI (local CSV) + whitelist check for listening ports
sabbat-netinspect --check-threat-intel --ti-csv feeds/blacklist.csv \
                  --check-ports --whitelist /etc/allowed_ports.conf

# Snapshot & diff
sabbat-netinspect --snapshot --output snapshots/net_$(date +%F).json
sabbat-netinspect --diff snapshots/net_2025-10-07.json --json
```

**Whitelist format**

```
# comments allowed
tcp/22
tcp/443
udp/53
tcp/*        # allow all tcp (dev only)
```

**Threat intel CSV (minimal)**

```csv
ip,source,confidence
203.0.113.50,local-blacklist,95
198.51.100.23,dfir-feed,80
```

**Exit codes**

* `0` = no suspicious findings
* `2` = suspicious flags present (e.g. `ti_blacklisted`, `not_in_whitelist`, `exposed_high_port`)

```

---
## Best Practices

* ReDoS hardening: use `--hardened-regex` (install `regex`).
* GeoIP: download & configure GeoLite2-Country.mmdb and pass `--geoip-db` if needed.
* CI: export `NO_COLOR=1` for consistent outputs.

---

## JSON & Exit Codes

Each command has stable JSON outputs and predictable exit codes for CI pipelines (see command sections).

---

## Troubleshooting

* **`re2` not available**: Safe to ignore; `regex` covers hardened engine.
* **GeoIP DB missing**: Use `--geoip-db` or skip GeoIP features.
* **Colors in CI**: `NO_COLOR=1`.

---

## Development

```bash
# Install local (editable) with common extras
pip install -e ".[detect,images,hardened]"

# Run tests (verbose)
pytest -vv

# Lint (ruff)
ruff check .
```

**Project layout**
```
sabbat_tools/
  ├─ loganalyce.py      # sabbat-loganalyce
  ├─ fileinspect.py     # sabbat-fileinspect
  └─ syscheck.py        # sabbat-syscheck (with 'cronaudit' subcommand)
tests/
  ├─ conftest.py
  └─ test_syscheck.py
```

---

## Contributing

PRs and issues welcome. Please keep the philosophy:

* Safe-by-default, robust tests, clear UX.
* New commands should come with tests and a README section.

---

## License

MIT © Óscar Giménez Blasco

---

### Project Footer

© 2025 Óscar Giménez Blasco — Released under the [MIT License](LICENSE).

