# sabbat-fileinspect — File Inspector

Security-focused inspector with JSON output.

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

