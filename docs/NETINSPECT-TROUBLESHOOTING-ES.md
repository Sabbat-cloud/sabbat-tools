# sabbat-netinspect — Problemas comunes (Troubleshooting)

## Permisos / Alcance (scope)
- `--scope all` puede requerir privilegios elevados en Linux para ver conexiones de otros usuarios.
  - Si solo necesitas las tuyas, usa `--scope own`.
  - En sistemas endurecidos, incluso root puede tener visibilidad limitada según opciones de proc/sys.

## psutil ve menos de lo esperado
- Si `psutil.net_connections()` devuelve menos conexiones de las esperadas, revisa:
  - Parámetros del kernel como `net.ipv4.ip_local_port_range` y filtros de /proc.
  - Separación por contenedores/namespaces: ejecuta dentro del namespace objetivo o usa `nsenter`.
  - Prueba con privilegios más altos si procede.

## GeoIP no funciona
- Asegúrate de tener `geoip2` instalado: `pip install geoip2`.
- Proporciona la DB válida: GeoLite2-Country.mmdb y usa `--geoip-db /ruta/db`.
- La herramienta **no** hará llamadas a Internet; sin GeoIP solo faltará `geoip.country`.

## Threat intel (CSV local)
- El MVP usa **CSV local** (`--ti-csv`) y **no** llama a APIs externas.
- Formato mínimo:
  ```csv
  ip,source,confidence
  203.0.113.50,local-blacklist,95
  ```
- Si más adelante usas APIs (AbuseIPDB, VT), añade plugin con caché y rate limit.

## Whitelist
- Formato del fichero:
  ```
  tcp/22
  tcp/443
  udp/53
  tcp/*
  ```
- Solo afecta a sockets en **LISTEN** y añade la flag `not_in_whitelist`.

## RDNS y tiempos de espera
- Reverse DNS es opt-in (`--rdns`). Cada lookup tiene timeout corto (~1.5s).

## Consejos para Snapshot/Diff
- Los snapshots son JSON con IDs estables (proto/state/laddr/pid[/raddr]).
- El diff informa `added`, `removed` y `changed`. Útiles en CI para detectar cambios no autorizados.

