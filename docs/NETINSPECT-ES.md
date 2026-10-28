# sabbat-netinspect — Inspector de Red y Conexiones (Manual Completo)

Inspector portable basado en `psutil` para el **estado en vivo**: conexiones y puertos en escucha con
correlación de procesos, GeoIP opcional, TI local (CSV), whitelist, snapshots y diffs.

---
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
---

## Instalación
```bash
pip install -e .
pip install geoip2  # opcional
sabbat-netinspect -h
```

## Inicio rápido
```bash
sabbat-netinspect
sabbat-netinspect --json | jq '.summary, .findings[:3]'
```

## Filtros y alcance
- Protocolo: `--proto {tcp,udp,all}`
- Estado: `--state {listening,established,all}`
- Alcance: `--scope {own,all}` (nota: `all` puede requerir root; `own` filtra por el usuario actual)
- PID / Usuario / Proceso: `--pid`, `--user`, `--proc <subcadena>`
- Direcciones IP / CIDR: `--laddr 127.0.0.1,10.0.0.0/8`, `--raddr 203.0.113.0/24`
- Puertos: `--lport 80,443,8000-8100`, `--rport 53,123`
- Filtros rápidos de seguridad: `--only-public` (solo IPs remotas públicas/globales), `--only-suspicious` (solo conexiones con alertas)
- Incluir UNIX sockets: `--include-unix`

## Enriquecido
- Reverse DNS: `--rdns` (resolución concurrente en lote con caché y presupuesto `--deadline-sec`)
- GeoIP: `--geoip-db /ruta/GeoLite2-Country.mmdb` (requiere `geoip2`, con caché por IP)
- Correlación con unidades `systemd` en Linux mediante `/proc/<pid>/cgroup`

## Políticas y heurísticas de seguridad
- Flags de seguridad integradas:
  - `exposed_sensitive_port`: servicio sensible (Redis, MongoDB, Docker API, MySQL, PostgreSQL, RDP, SMB, Telnet, FTP, etc.) escuchando en `0.0.0.0` o `::`
  - `exposed_high_port`: puerto alto ($\ge 1024$) escuchando en `0.0.0.0` o `::`
  - `c2_like_port`: conexión establecida hacia puertos típicos de C2, IRC, *cryptominers* o Tor
  - `proc_suspicious_path`: proceso ejecutándose desde `/tmp`, `/var/tmp`, `/dev/shm` o `Temp`
- Whitelist de puertos en escucha:
```bash
sabbat-netinspect --check-ports --whitelist /etc/allowed_ports.conf
```
Formato whitelist (admite puertos individuales, rangos y comodines):
```
# comentarios
tcp/22
tcp/443
tcp/8000-8010
udp/53
tcp/*
```

- TI local (CSV con soporte de IPs exactas y subredes CIDR IPv4/IPv6):
```bash
sabbat-netinspect --check-threat-intel --ti-csv feeds/blacklist.csv --json
```
CSV mínimo:
```csv
ip,source,confidence
203.0.113.50,local,95
198.51.100.0/24,spamhaus_drop,90
```

## Snapshots y diffs
```bash
sabbat-netinspect --snapshot --output snapshots/net_$(date +%F).json
sabbat-netinspect --diff snapshots/net_2025-10-07.json --json
```

## Límites y privacidad
- Parada temprana: `--max-conns N`, `--deadline-sec S`
- Privacidad por defecto: `--sanitize`; usa `--unsafe-proc-cmdline` para cmdline completo.

## Códigos de salida
- `0` = sin flags sospechosas
- `2` = hay flags sospechosas (p.ej., `ti_blacklisted`, `not_in_whitelist`, `exposed_high_port`)

## Problemas comunes
- En Linux, `--scope all` puede requerir root o `/proc` sin `hidepid=2`.
- Namespaces/containers pueden ocultar conexiones: ejecuta dentro del namespace objetivo.
- Mantén presupuestos de RDNS razonables (`--deadline-sec`).
