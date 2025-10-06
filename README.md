---

````markdown
# README.md

# 🧰 sabbat-tools — System & Security CLI Toolbox

[![CI](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/sabbat-tools.svg)](https://pypi.org/project/sabbat-tools/) <!-- publish to PyPI to activate -->
![Python Versions](https://img.shields.io/pypi/pyversions/sabbat-tools.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#license)

**sabbat-tools** is a collection of production-ready command-line utilities for sysadmins, SREs, and security engineers.

- ✅ Bilingual UX (auto/en/es) where applicable  
- ✅ Safe-by-default & automation-friendly (clean JSON modes)  
- ✅ Thoughtful hardening: input limits, ReDoS-safe regex paths, safe output confinement

> **Español**: ¿Prefieres documentación en español? Lee [README-ES.md](./README-ES.md).

---

## 📚 Table of Contents

- [Installation](#installation)
- [Requirements & Extras](#requirements--extras)
- [Commands](#commands)
  - [📊 sabbat-loganalyce — Advanced Log Analyzer](#-sabbat-loganalyce--advanced-log-analyzer)
  - [🕵️ sabbat-fileinspect — File Inspector](#-sabbat-fileinspect--file-inspector)
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
````

> After install, you’ll have the `sabbat-loganalyce` and `sabbat-fileinspect` commands on PATH.

---

## Requirements & Extras

* **Python** ≥ 3.8
* Optional extras:

  * `hardened`: `regex` (and optionally `re2` if available) for ReDoS-resistant scanning
  * `geoip`: `geoip2` + **MaxMind GeoLite2-Country.mmdb** (place in `/var/lib/GeoIP/` or pass `--geoip-db`)
  * `detect`: `chardet` and `python-magic`/`file(1)` for robust MIME detection in `sabbat-fileinspect`
  * `images`: `Pillow` to safely parse image metadata

> If `re2` wheels aren’t available on your platform, it will be skipped; `regex` alone already hardens most paths.

---

## Commands

### 📊 sabbat-loganalyce — Advanced Log Analyzer

> *“Your logs have a story to tell. sabbat-loganalyce deciphers it for you.”*

Reads plain or `.gz` logs, supports `stdin`, and outputs rich statistics, security signals, and JSON.

**Language**

* Auto: `--lang auto` (default)
* Force: `--lang {en|es}`

**Highlights**

* **Security**: safe output confinement (`--output` confined to CWD unless `--unsafe-output`), ANSI sanitization, ReDoS mitigation (`--hardened-regex` if `regex` installed)
* **Performance**: multithreaded stats (`--threads`, `--batch-size`), bounded futures pipeline
* **UX**: columns or list views, configurable tops, enriched JSON
* **Early large-log warning**: fast pre-scan before full analysis (`--large-threshold`)

**Quick Examples**

```bash
# Full analysis (columns)
sabbat-loganalyce access.log

# List view
sabbat-loganalyce access.log --list-view

# Pattern search (first 50, ordered)
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50

# JSON output
sabbat-loganalyce app.log --json

# Save JSON (confined to CWD unless --unsafe-output)
sabbat-loganalyce app.log --json --output reports/result.json

# Time filter (UTC)
sabbat-loganalyce access.log --since 2024-01-01 --until "2024-01-31 23:59:59"

# Pipe .gz via stdin
zcat access.log.gz | sabbat-loganalyce - --json
```

**Core Options**

* Input: `file | -` (stdin), `--encoding`, `--max-line-chars`, `--max-bytes`, `--deny-stdin`
* Views: `--list-view`, `--top-urls N`, `--top-uas N`, `--top-ips N`
* Security: `--hardened-regex`, `--unsafe-output`, `--force`, `--no-sanitize-ansi`
* Time: `--since`, `--until` (UTC)
* GeoIP: `--geoip-db PATH`
* Perf: `--threads N`, `--batch-size N`, **pre-scan** `--large-threshold N`
* Pattern search: `-p REGEX`, `-c N` (ordered, single-thread)

---

### 🕵️ sabbat-fileinspect — File Inspector

Security-focused, portable file inspector. It understands text, images, and common binary types.

**Language**

* `--lang {auto,en,es}`

**Highlights**

* Robust MIME: `python-magic` → `file(1)` (with timeout) → `mimetypes`
* Hashes: `--hash sha256,sha1,md5` (default `sha256`) or `--no-hash` (mmap when possible)
* Secret scanning: common patterns + high-entropy (base64/hex), adjustable limits
* Images: safe verification (`Pillow`) and metadata
* Binaries: header detection (ELF/PE/Mach-O), optional `readelf` (with timeout)
* Time: `--utc` (ISO 8601)
* Respects `NO_COLOR`; clean JSON output

**Quick Examples**

```bash
# Basic inspection (auto language)
sabbat-fileinspect /etc/passwd

# Force Spanish + UTC + multiple hashes + JSON
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts

# No hashes, do not follow symlinks
sabbat-fileinspect --no-hash --nofollow /path/to/link

# Limit secrets scan
sabbat-fileinspect --max-secret-bytes 262144 --max-secret-lines 300 app.env
```

**Core Options**

* Language & formatting: `--lang`, `--json`, `--utc`, NO_COLOR
* Size: `-b/--bytes`, `-k/--kb`, `-m/--mb`, `-g/--gb`
* Hashes: `--no-hash` or `--hash sha256,sha1,md5`
* Symlinks: `--nofollow`
* Secret scan limits: `--max-secret-bytes N`, `--max-secret-lines N`

---

## Best Practices

* Huge logs: use `--large-threshold` and/or `--max-bytes`.
* ReDoS hardening: enable `--hardened-regex` (install `regex`).
* GeoIP: download & configure GeoLite2-Country.mmdb and pass `--geoip-db` if needed.
* Secrets: tune `--max-secret-bytes/lines` for large files.
* CI: export `NO_COLOR=1` for consistent outputs.

---

## JSON & Exit Codes

**sabbat-loganalyce**

* JSON includes: `schema_version`, `generated_at`, `lang`, `summary { file, total_lines, total_errors, total_warnings, period }`, `parameters_used`, `security_alerts`, `http_methods`, `http_status_codes`, `top_urls`, `top_user_agents`, `top_errors`, `top_ips`, `truncated_lines`, `bytes_read`.
* Exit code:

  * `0` success
  * `1` usage or runtime error
  * `2` **security alerts detected** (CI-friendly)

**sabbat-fileinspect**

* JSON includes stable keys for pipelines: file identity, realpath/symlink, MIME, sizes, permissions/inode, owner, dates, context details, security alerts, hashes.
* Exit code:

  * `0` success
  * `1` error

---

## Troubleshooting

* **`re2` not available**: Safe to ignore; `regex` covers hardened engine. Use `pip install -e ".[hardened]"`—it will skip `re2` if unsupported.
* **GeoIP DB missing**: You’ll see a warning; countries will be “GeoIP not available”. Install `geoip2` and place GeoLite2 in `/var/lib/GeoIP/` or use `--geoip-db`.
* **Windows MIME**: Prefer `python-magic`; `file(1)` may be unavailable.
* **Colors in CI**: `NO_COLOR=1`.

---

## Development

```bash
# Install local (editable) with common extras
pip install -e ".[detect,images,hardened]"

# Run tests (verbose)
pytest -vv

# Lint (optional)
pip install ruff
ruff check .
```

**Project layout**

```
sabbat_tools/
  ├─ loganalyce.py     # sabbat-loganalyce
  └─ fileinspect.py    # sabbat-fileinspect
tests/
  ├─ conftest.py
  ├─ test_fileinspect.py
  └─ test_loganalyce.py
```

---

## Contributing

PRs and issues welcome. Please keep the philosophy:

* Safe-by-default, robust tests, clear UX.
* New commands should come with tests and a README section.

---

## License

MIT © Óscar Giménez Blasco

````
