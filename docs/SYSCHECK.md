# sabbat-syscheck — System Auditor (Full Manual)

Read‑only auditor for common Linux misconfigurations: **SSH**, **permissions**, **users**, **cron**.
Includes **`cronaudit`** to unify cron + systemd timers with extra security checks.

---
SSH, permissions, users, cron; plus **cronaudit**.

## Synopsis
```
sabbat-syscheck [--check-ssh|--check-perms|--check-users|--check-cron|--all] [--json|--jsonl|--raw]

sabbat-syscheck cronaudit [flags]
```

## Examples
```bash
sabbat-syscheck --all
sabbat-syscheck --check-perms --max-files 50000 --exclude /var/lib/docker /snap
sabbat-syscheck --json > syscheck.json

sabbat-syscheck cronaudit --json --output audits/cron_$(date +%Y%m%d).json
sabbat-syscheck cronaudit --check-dangerous --pattern 'rm -rf|wget|curl.*pipe'
sabbat-syscheck cronaudit --check-privileges --user root
sabbat-syscheck cronaudit --only timers
```
---

## Quickstart
```bash
sabbat-syscheck --all
sabbat-syscheck --json > syscheck.json
```

## Classic Modules
- `--check-ssh` — `PermitRootLogin`, `PasswordAuthentication`, `X11Forwarding`, `MaxAuthTries`.
- `--check-perms` — world‑writable files/dirs in critical paths; sticky aware (1777 → INFO).
- `--check-users` — extra UID 0 accounts, empty passwords, system accounts with interactive shells.
- `--check-cron` — relative paths, `/tmp` usage, world‑writable scripts.

### Examples
```bash
# Permissions scope and excludes
sabbat-syscheck --check-perms --roots /etc /usr/local --exclude /var/lib/docker /snap --max-files 50000

# Raw TSV (greppable) without grouping
sabbat-syscheck --raw --no-group | column -t -s $'\t'
```

## `cronaudit` Subcommand
**Purpose:** inventory **cron jobs** (system + per-user) and **systemd timers**, detect issues:
- Dangerous patterns: `rm -rf /`, `curl|bash`, `wget|bash`, base64→shell, `nc -e`, reverse shells, cryptominers, plain `http://` fetch.
- Path/resolution: first token not absolute, unresolved binaries.
- Env vars pitfalls: `$VAR`/`${VAR}` without default `${VAR:-def}`.
- Privileges: likely need root vs. running as root without evidence.
- Orphans: missing user, missing script/binary, timer without `.service`.

### Examples
```bash
# Full audit + JSON saved
sabbat-syscheck cronaudit --json --output audits/cron_$(date +%F).json

# Dangerous commands only
sabbat-syscheck cronaudit --check-dangerous --pattern 'rm -rf|wget|curl.*pipe'

# Privilege checks (root focus)
sabbat-syscheck cronaudit --check-privileges --user root

# Only systemd timers
sabbat-syscheck cronaudit --only timers
```

## Output & Exit Codes
- Human grouped by default; machine formats: `--json`, `--jsonl`, `--raw`.
- Exit: `0` OK · `1` error · `2` MEDIUM/HIGH (classic) · `2` HIGH/CRITICAL (`cronaudit`).

## Troubleshooting
- Run with sufficient privileges to read `/etc/cron.*` and systemd unit files.
- Use `--group-show N` to display more sample paths per finding group.
