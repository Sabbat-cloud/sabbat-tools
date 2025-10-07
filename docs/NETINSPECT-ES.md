# sabbat-netinspect — Inspector de Red y Conexiones

Inspector en vivo con correlación de procesos, whitelist, TI local, snapshots.

## Sinopsis
```
sabbat-netinspect [OPCIONES]
```

## Ejemplos
```bash
sabbat-netinspect --json --max-conns 300
sabbat-netinspect --check-ports --whitelist /etc/allowed_ports.conf
sabbat-netinspect --check-threat-intel --ti-csv feeds/blacklist.csv
sabbat-netinspect --snapshot --output snapshots/net_$(date +%F).json
sabbat-netinspect --diff snapshots/net_2025-10-07.json --json
```

