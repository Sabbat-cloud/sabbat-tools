# sabbat-fileinspect — File Inspector (Full Manual)

Security‑focused inspector for text/images/binaries with stable JSON output.

---
## Synopsis
```
sabbat-fileinspect [OPTIONS] <path...>
```

## Options
- `--lang {auto,en,es}`
- Hashing: `--hash sha256,sha1,md5` or `--no-hash`
- Symlinks: `--nofollow`
- Secrets: `--max-secret-bytes`, `--max-secret-lines`
- Output: `--json`, `--utc`

## Examples
```bash
sabbat-fileinspect /etc/passwd
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts
sabbat-fileinspect --no-hash --nofollow /path/to/link
```
---

## Overview
- Detects **MIME/type**, **permissions**, **ownership**, **timestamps**.
- Computes **hashes** (SHA‑256 default; SHA‑1/MD5 optional).
- Optional **secret scanning** (patterns + entropy), safe size limits.
- Symlink handling with `--nofollow`.

## Installation
```bash
pip install -e ".[detect,images]"
sabbat-fileinspect -h
```

## Quickstart
```bash
sabbat-fileinspect /etc/passwd
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts
sabbat-fileinspect --no-hash --nofollow /path/to/link
```

## Practical Scenarios
### Inventory + checksums
```bash
find ./release -maxdepth 1 -type f -print0 | xargs -0 sabbat-fileinspect --json > release.json
```

### Secret scanning with limits
```bash
sabbat-fileinspect .env --max-secret-bytes 262144 --max-secret-lines 400 --json
```

### Image metadata (if Pillow installed)
```bash
sabbat-fileinspect image.jpg --json
```

## JSON (abridged)
```jsonc
{
  "file": {"path":"...", "realpath":"...", "mimetype":"...", "encoding":"..."},
  "stat": {"mode":"0644","uid":0,"gid":0,"size":123},
  "hashes": {"sha256":"...","sha1":"..."},
  "secrets": [{"kind":"base64_high_entropy","line":42,"excerpt":"..."}]
}
```

## Exit Codes
- `0` success
- `1` error

## Tips
- Prefer `--nofollow` for untrusted symlinks.
- Tune `--max-secret-bytes/lines` for large config files.

