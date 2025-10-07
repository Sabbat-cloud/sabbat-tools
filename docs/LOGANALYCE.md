# sabbat-loganalyce — Advanced Log Analyzer

Small manual with practical examples.

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

## JSON shape (abridged)
```jsonc
{
  "schema_version": "...",
  "generated_at": "ISO-8601",
  "lang": "en",
  "summary": {"file":"access.log","total_lines":12345},
  "parameters_used": {...},
  "security_alerts": [{"type":"sqli","count":5}],
  "top_urls": [{"path":"/api","count":100}],
  "top_ips": [{"ip":"203.0.113.1","count":42}]
}
```

## Exit codes
- `0` success
- `1` usage/runtime error
- `2` security alerts detected

## Tips
- Large logs: bump `--large-threshold` or use `--max-bytes`.
- Harden regex with `pip install regex` and `--hardened-regex`.
