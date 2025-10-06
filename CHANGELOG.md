---

```markdown
# CHANGELOG.md

# Changelog — sabbat-tools

> All dates in UTC. / Todas las fechas en UTC.

## Index

- [Unreleased](#unreleased)
- [sabbat-fileinspect 0.2.0 — 2025-10-03](#sabbat-fileinspect-020--2025-10-03)
- [sabbat-loganalyce 1.3.1 — 2025-10-03](#sabbat-loganalyce-131--2025-10-03)
- [Earlier History (summary)](#earlier-history-summary)

---

## Unreleased

- Add more `sabbat-*` utilities.
- Extended docs per command.
- (Planned) Publish to PyPI and enable PyPI badge.

---

## sabbat-fileinspect 0.2.0 — 2025-10-03

### Added
- Full **i18n (en/es)** with autodetect (`--lang {auto,en,es}`).
- **Robust MIME detection**: `python-magic` → `file(1)` with timeout → `mimetypes`.
- **Secret scanning** improvements:
  - Common patterns (password/API keys/private keys/AWS/GitHub/cards).
  - **High-entropy** heuristics (base64/hex) with sensible thresholds.
  - Tunables: `--max-secret-bytes`, `--max-secret-lines`.
- **Configurable hashes**: `--hash sha256,sha1,md5` (default `sha256`); `--no-hash`.
- **Images**: optional `Pillow`; `Image.verify()` and safe metadata reads.
- **Binaries**: header detection (ELF/PE/Mach-O) + optional `readelf` with timeout.
- **Timestamps**: `--utc` (ISO 8601).
- **NO_COLOR** respected; clean JSON output.

### Changed
- `pwd/grp` used only where available; portable fallback on Windows.
- Clearer error messages and UX (EN/ES).

---

## sabbat-loganalyce 1.3.1 — 2025-10-03

### Added
- **Early large-log warning** *before* analysis:
  - Fast binary line count for regular (non-compressed) files.
  - Configurable threshold: `--large-threshold`.
- Exit code **2** if security alerts detected (CI-friendly).

### Changed
- Bounded futures pipeline to avoid excessive memory pressure in multithreaded runs.
- Robust time normalization (ISO offsets ±HH:MM).
- Better fallbacks for User-Agent parsing and IP extraction.
- Safer output confinement and symlink checks.

### Fixed
- Avoid hangs on `.gz` with odd encodings.
- GeoIP loader errors and safe close handling.

---

## Earlier History (summary)

### 1.3.0
- Multithreaded statistics; ReDoS mitigation; input validations; GeoIP LRU cache; JSON metrics (`truncated_lines`, `bytes_read`).

### 1.2.x
- Stable columns/list views and basic JSON outputs.
````

---

