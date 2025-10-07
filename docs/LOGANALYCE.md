# sabbat-loganalyce — Advanced Log Analyzer (Full Manual)

A practical, security‑oriented log analyzer that reads plain or `.gz` logs (or stdin), extracts signals,
and produces human and machine‑readable output.

---
## Synopsis
```
sabbat-loganalyce [OPTIONS] <file|->
```

Reads plain or `.gz` logs (or stdin), produces security signals and stats, and supports JSON for automation.

## Common options
- `--lang {auto,en,es}`: UI language (default: auto).
- `--list-view`: print as list instead of columns.
- `--json`: emit JSON (pretty by default).
- `-p/--pattern REGEX`: ordered scan (single-thread) for matches.
- `-c N`: limit number of matches with `--pattern`.
- Size limits: `--max-bytes`, `--max-line-chars`.
- Performance: `--threads N`, `--batch-size N`, `--large-threshold N`.

## Quick examples
```bash
sabbat-loganalyce access.log
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50
sabbat-loganalyce app.log --json
zcat access.log.gz | sabbat-loganalyce - --json
```
---

## Overview
- **Inputs:** text log files or `-` (stdin). `.gz` is supported via stdin (e.g., `zcat file.gz | sabbat-loganalyce -`).
- **Focus:** security hints (SQLi/XSS/auth anomalies), quick stats (top URLs, IPs, status codes), and JSON for automation.
- **Design:** safe defaults, bounded processing, ReDoS‑aware regex paths (enable with the `regex` module).

## Installation
```bash
# Recommended extras for best experience
pip install -e ".[detect,hardened]"
# Smoke test
sabbat-loganalyce -h
```

## Quickstart
```bash
# Columns view with roll‑up stats
sabbat-loganalyce access.log

# JSON for dashboards (pretty by default)
sabbat-loganalyce app.log --json > reports/app.json

# Read from stdin (.gz ok)
zcat access.log.gz | sabbat-loganalyce - --json | jq '.summary'
```

## Key Options
- Language: `--lang {auto,en,es}`
- Views: `--list-view` (instead of columns)
- JSON: `--json` or JSON Lines: `--jsonl`
- Pattern scan: `-p/--pattern REGEX` (+ `-c N` to cap number of matches)
- Time filters (UTC): `--since`, `--until`
- Performance/limits: `--threads`, `--batch-size`, `--large-threshold`, `--max-bytes`, `--max-line-chars`
- Security hardening: `--hardened-regex` (requires `regex` package)

## Practical Examples (from simple to advanced)

### 1) Quick health read
```bash
sabbat-loganalyce access.log
```
What you get: #lines, HTTP status distribution, top URLs, User‑Agents, security alerts summary.

### 2) Narrow to a time window
```bash
sabbat-loganalyce access.log --since "2025-10-06" --until "2025-10-07 23:59:59"
```

### 3) Ordered hunting for errors
```bash
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50
```
Why ordered? Keeps original log order (single‑thread) → great for triage.

### 4) Large‑file guardrails
```bash
sabbat-loganalyce big.log --large-threshold 2000000 --max-bytes 200MB
```

### 5) Security signal extraction to CI
```bash
sabbat-loganalyce access.log --json | jq '[.security_alerts[] | select(.type=="sqli" or .type=="xss")] | length' \
  | awk '{ exit ($1>0?2:0) }'
```
Exit non‑zero if suspicious payloads were detected.

## JSON (abridged & stable)
```jsonc
{
  "schema_version": "1.x",
  "generated_at": "ISO-8601",
  "lang": "en",
  "summary": {
    "file": "access.log",
    "total_lines": 12345,
    "total_errors": 12,
    "period": {"since":"...","until":"..."}
  },
  "parameters_used": {...},
  "security_alerts": [
    {"type": "auth_fail", "count": 42},
    {"type": "sqli", "count": 5},
    {"type": "xss", "count": 3}
  ],
  "http_status_codes": [{"code":200,"count":1000}],
  "top_urls": [{"path":"/api","count":100}],
  "top_ips": [{"ip":"203.0.113.1","count":42}]
}
```

## Exit Codes
- `0` success
- `1` usage/runtime error
- `2` security alerts detected

## Tips & Troubleshooting
- Use `--large-threshold` and/or `--max-bytes` for huge logs.
- Install `regex` and pass `--hardened-regex` to mitigate catastrophic backtracking risks.
- Set `NO_COLOR=1` in CI for colorless output.
