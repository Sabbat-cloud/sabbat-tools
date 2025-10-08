# Changelog — sabbat-tools
All notable changes to this project will be documented in this file.

This format follows **[Keep a Changelog](https://keepachangelog.com/en/1.1.0/)**
and **[Semantic Versioning](https://semver.org/spec/v2.0.0.html)**.  
_All dates in UTC._

## [Unreleased]
### Planned
- Add more `sabbat-*` utilities.
- Extended per-command manuals with practical examples.
- Publish to PyPI and add PyPI badge.
- Optional structured logging flags (`--log-file`, `--log-json`).

---

## [0.4.0] - 2025-10-08
### Added
- **Installation via `pipx`** documented; quick-start examples for the four CLIs.
- **Samples**: `samples/access.log` for quick local tests.
- **Minimal CI** (GitHub Actions: Linux, Python 3.10/3.12) running `ruff` + `pytest`.

### Changed
- **Packaging/extras**: flattened `full` extra (no self-references) and consolidated optional deps.
- **Regex hardening**: rely on `regex` by default; `re2` removed from default/full due to portability.
- Cleaned up project scaffolding and clarified optional dependencies in `pyproject.toml`.

### Fixed
- Editable installs with extras now resolve cleanly (no `UNKNOWN 0.0.0`, no broken `full`).

### Docs
- New lean README with five real examples (JSON/JSONL, GeoIP, detect, sys, net).
- `CHANGELOG.md` converted to Keep-a-Changelog style.
- Simple roadmap and issue/PR templates (optional starter pack).

### Notes / Compatibility
- Python **3.8–3.12** supported. Windows/macOS partial support (documented caveats).
- GeoIP still requires downloading GeoLite2 DB separately (license MaxMind).

---

## Tool-specific history (earlier)
### sabbat-fileinspect **0.2.0** — 2025-10-03
**Added**
- Full **i18n (en/es)** with autodetect (`--lang {auto,en,es}`).
- Robust MIME detection: `python-magic` → `file(1)` with timeout → `mimetypes`.
- Secret scanning improvements (patterns + entropy heuristics) with tunables.
- Configurable hashes: `--hash sha256,sha1,md5`; `--no-hash` to disable.
- Images: optional `Pillow`; `Image.verify()` and safe metadata reads.
- Binaries: header detection (ELF/PE/Mach-O) + optional `readelf` with timeout.
- Timestamps: `--utc` (ISO 8601). Respects `NO_COLOR`.

**Changed**
- Use `pwd/grp` only where available; clearer errors & UX.

---

### sabbat-loganalyce **1.3.1** — 2025-10-03
**Added**
- Early large-log warning with fast line count; `--large-threshold`.
- Exit code **2** if security alerts detected (CI-friendly).

**Changed**
- Bounded futures to reduce memory pressure; better time normalization.
- Improved fallbacks for UA parsing and IP extraction; safer output confinement.

**Fixed**
- Avoid hangs on `.gz` with odd encodings; safer GeoIP loader handling.

---

### Earlier summary (pre-2025-10-03)
- 1.3.0: Multithreaded stats; ReDoS mitigation; input validations; GeoIP LRU cache; JSON metrics.
- 1.2.x: Stable columns/list views and basic JSON outputs.

[Unreleased]: https://github.com/Sabbat-cloud/sabbat-tools/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Sabbat-cloud/sabbat-tools/releases/tag/v0.4.0

