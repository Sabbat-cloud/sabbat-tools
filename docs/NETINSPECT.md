# sabbat-netinspect — Network & Connections Inspector (Full Manual)

Portable, psutil‑based inspector for **live** connections and listening ports with process correlation,
optional GeoIP, local threat‑intel CSV, whitelist checks, snapshots & diffs.

---
## Synopsis
```
sabbat-netinspect [OPTIONS]
```

## Examples
```bash
sabbat-netinspect --json --max-conns 300
sabbat-netinspect --check-ports --whitelist /etc/allowed_ports.conf
sabbat-netinspect --check-threat-intel --ti-csv feeds/blacklist.csv
sabbat-netinspect --snapshot --output snapshots/net_$(date +%F).json
sabbat-netinspect --diff snapshots/net_2025-10-07.json --json
```
---

## Installation
```bash
pip install -e .
pip install geoip2  # optional
sabbat-netinspect -h
```

## Quickstart
```bash
# Human summary
sabbat-netinspect

# JSON for automation
sabbat-netinspect --json | jq '.summary, .findings[:3]'
```

## Filters & Scopes
- Protocol: `--proto {tcp,udp,all}`
- State: `--state {listening,established,all}`
- Scope: `--scope {own,all}` (note: `all` may require root; `own` filters to current user)
- PID / User / Process filters: `--pid`, `--user`, `--proc <substring>`
- IP / CIDR filters: `--laddr 127.0.0.1,10.0.0.0/8`, `--raddr 203.0.113.0/24`
- Ports: `--lport 80,443,8000-8100`, `--rport 53,123`
- Quick security filters: `--only-public` (only global remote IPs), `--only-suspicious` (only flagged connections)
- Include UNIX sockets: `--include-unix`

## Enrichment
- Reverse DNS: `--rdns` (concurrent batch resolution with cache and `--deadline-sec` budget)
- GeoIP: `--geoip-db /path/to/GeoLite2-Country.mmdb` (requires `geoip2`, cached per IP)
- Linux `systemd` service correlation via `/proc/<pid>/cgroup`

## Policy Checks & Security Heuristics
- Built-in security flags:
  - `exposed_sensitive_port`: critical service (Redis, MongoDB, Docker API, MySQL, PostgreSQL, RDP, SMB, Telnet, FTP, etc.) listening on `0.0.0.0` or `::`
  - `exposed_high_port`: high port ($\ge 1024$) listening on wildcard `0.0.0.0` or `::`
  - `c2_like_port`: established connection to known C2/IRC/cryptominer/Tor ports
  - `proc_suspicious_path`: process running from `/tmp`, `/var/tmp`, `/dev/shm`, or `Temp`
- Whitelist listening ports:
```bash
sabbat-netinspect --check-ports --whitelist /etc/allowed_ports.conf
```
Whitelist file format (supports single ports, ranges, and wildcards):
```
# comments allowed
tcp/22
tcp/443
tcp/8000-8010
udp/53
tcp/*      # allow all tcp (dev only)
```

- Local Threat‑Intel CSV (supports exact IPs and IPv4/IPv6 CIDR subnets):
```bash
sabbat-netinspect --check-threat-intel --ti-csv feeds/blacklist.csv --json
```
CSV minimal columns:
```csv
ip,source,confidence
203.0.113.50,local,95
198.51.100.0/24,spamhaus_drop,90
```

## Snapshots & Diffs
```bash
# Save current snapshot
sabbat-netinspect --snapshot --output snapshots/net_$(date +%F).json

# Compare later
sabbat-netinspect --diff snapshots/net_2025-10-07.json --json
```

## Limits & Privacy
- Stop early: `--max-conns N`, `--deadline-sec S`
- Privacy defaults: `--sanitize`; use `--unsafe-proc-cmdline` to include full process cmdline.

## Exit Codes
- `0` = no suspicious flags
- `2` = suspicious flags (e.g., `ti_blacklisted`, `not_in_whitelist`, `exposed_high_port`)

## Troubleshooting
- On Linux, `--scope all` may need root or relaxed `/proc` (no `hidepid=2`).
- Namespaces/containers can hide connections—run inside the target namespace.
- Keep reverse DNS budgets sensible (`--deadline-sec`).
