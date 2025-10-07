# sabbat-netinspect — Troubleshooting

## Permissions / Scope
- `--scope all` may require elevated privileges on Linux to see connections from other users.
  - If you only need your user, use `--scope own`.
  - On hardened systems, even root may have restricted visibility depending on proc/sys settings.

## psutil visibility gaps
- If `psutil.net_connections()` returns fewer items than expected, check:
  - Kernel settings like `net.ipv4.ip_local_port_range` and proc filters.
  - Containers/namespace separation: run inside the target namespace or use `nsenter`.
  - Try increasing limits or run with elevated privileges if appropriate.

## GeoIP not working
- Ensure `geoip2` is installed: `pip install geoip2`.
- Provide a valid DB: GeoLite2-Country.mmdb and pass `--geoip-db /path/to/db`.
- The tool won’t make network calls; missing GeoIP only affects the `geoip.country` field.

## Threat intel (local CSV)
- The MVP uses **local CSV** (`--ti-csv`) and **does not** call external APIs.
- CSV format (minimal):
  ```csv
  ip,source,confidence
  203.0.113.50,local-blacklist,95
  ```
- If you plan to go online later, implement a provider plugin (AbuseIPDB, VT) with cache and rate-limiting.

## Whitelist
- File format:
  ```
  tcp/22
  tcp/443
  udp/53
  tcp/*
  ```
- Only affects **LISTEN** sockets and adds `not_in_whitelist` flag.

## RDNS timeouts
- Reverse DNS is opt-in (`--rdns`). Each lookup has a short timeout (~1.5s).

## Snapshot/Diff tips
- Snapshots are plain JSON with stable IDs (proto/state/laddr/pid[/raddr]).
- Diffs report `added`, `removed`, and `changed` findings. Use them in CI to detect drift.

