# sabbat-syscheck — System Auditor (read-only)

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

