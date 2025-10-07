# sabbat-netinspect — Network & Connections Inspector

Live network inspector with process correlation, whitelist, local TI, snapshots.

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

