# sabbat-syscheck — Auditor de Sistema (Manual Completo)

Auditor **solo lectura** para desconfiguraciones comunes: **SSH**, **permisos**, **usuarios**, **cron**.
Incluye **`cronaudit`** para inventario unificado de cron + systemd timers con comprobaciones extra.

---
## Sinopsis
```
sabbat-syscheck [--check-ssh|--check-perms|--check-users|--check-cron|--all] [--json|--jsonl|--raw]

sabbat-syscheck cronaudit [flags]
```

## Ejemplos
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

## Inicio rápido
```bash
sabbat-syscheck --all
sabbat-syscheck --json > syscheck.json
```

## Módulos clásicos
- `--check-ssh` — `PermitRootLogin`, `PasswordAuthentication`, `X11Forwarding`, `MaxAuthTries`.
- `--check-perms` — ficheros/dirs world‑writable en rutas críticas; sensible a sticky (1777 → INFO).
- `--check-users` — UID 0 adicionales, contraseñas vacías, cuentas de sistema con shell interactivo.
- `--check-cron` — rutas relativas, uso de `/tmp`, scripts world‑writable.

### Ejemplos
```bash
# Alcance de permisos y exclusiones
sabbat-syscheck --check-perms --roots /etc /usr/local --exclude /var/lib/docker /snap --max-files 50000

# TSV sin agrupar (greppable)
sabbat-syscheck --raw --no-group | column -t -s $'\t'
```

## Subcomando `cronaudit`
**Objetivo:** inventario de **crons** (sistema/usuarios) y **timers** de systemd; detecta:
- Patrones peligrosos: `rm -rf /`, `curl|bash`, `wget|bash`, base64→shell, `nc -e`, reverse shells, cryptominers, descargas `http://`.
- Rutas/resolución: primer token no absoluto, binarios no resolubles.
- Variables: `$VAR`/`${VAR}` sin default `${VAR:-def}`.
- Privilegios: tareas que probablemente requieren root vs. ejecución como root sin evidencia.
- Huérfanos: usuario/binario ausente, timer sin `.service`.

### Ejemplos
```bash
sabbat-syscheck cronaudit --json --output audits/cron_$(date +%F).json
sabbat-syscheck cronaudit --check-dangerous --pattern 'rm -rf|wget|curl.*pipe'
sabbat-syscheck cronaudit --check-privileges --user root
sabbat-syscheck cronaudit --only timers
```

## Salida y códigos
- Humano agrupado por defecto; máquina: `--json`, `--jsonl`, `--raw`.
- Exit: `0` OK · `1` error · `2` MEDIO/ALTO (clásico) · `2` ALTO/CRÍTICO (`cronaudit`).

## Problemas comunes
- Ejecuta con permisos suficientes para leer `/etc/cron.*` y unidades de systemd.
- `--group-show N` para mostrar más ejemplos por grupo.
