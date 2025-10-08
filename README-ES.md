<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [🧰 sabbat-tools — Caja de Herramientas CLI de Sistema y Seguridad](#-sabbat-tools--caja-de-herramientas-cli-de-sistema-y-seguridad)
  - [Índice](#%C3%8Dndice)
  - [Instalación](#instalaci%C3%B3n)
  - [Requisitos y Extras](#requisitos-y-extras)
  - [Comandos](#comandos)
    - [📊 sabbat-loganalyce — Analizador Avanzado de Logs](#-sabbat-loganalyce--analizador-avanzado-de-logs)
    - [🕵️ sabbat-fileinspect — Inspector de Ficheros](#-sabbat-fileinspect--inspector-de-ficheros)
    - [🔧 sabbat-syscheck — Auditor de Sistema (solo lectura)](#-sabbat-syscheck--auditor-de-sistema-solo-lectura)
      - [Subcomando cronaudit (Cron + systemd timers)](#subcomando-cronaudit-cron--systemd-timers)
    - [🌐 sabbat-netinspect — Inspector de Red y Conexiones](#-sabbat-netinspect--inspector-de-red-y-conexiones)
  - [Solución de Problemas](#soluci%C3%B3n-de-problemas)
  - [Desarrollo](#desarrollo)
  - [Contribuir](#contribuir)
  - [Licencia](#licencia)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# 🧰 sabbat-tools — Caja de Herramientas CLI de Sistema y Seguridad

[![CI](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci-lean.yml/badge.svg)](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci-lean.yml)
![Python Versions](https://img.shields.io/badge/python-3.8--3.12-informational)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#licencia)

**sabbat-tools** es un conjunto de utilidades de línea de comandos, enfocadas en producción, para sysadmins, SREs y equipos de seguridad.

- UX bilingüe (auto/en/es) donde aplica
- Amigable para automatización (JSON/JSONL limpios y *exit codes* predecibles)
- Endurecimiento: límites de entrada, rutas regex resistentes a ReDoS, confinamiento seguro de salidas

> **English**: [🇬🇧 English](README.md) · [🇪🇸 Español](README-ES.md)

---
---
## Instalación

```bash
# Clonar (desarrollo)
git clone https://github.com/Sabbat-cloud/sabbat-tools
cd sabbat-tools

# Recomendado: todas las características
pip install -e ".[full]"

# o en entorno aislado de usuario:
# pipx install "sabbat-tools[full]"
```

Tras instalar, tendrás `sabbat-loganalyce`, `sabbat-fileinspect`, `sabbat-syscheck` y `sabbat-netinspect` en el PATH.

---

## Requisitos y Extras

* Python ≥ 3.8
* Extras opcionales:
  * `hardened`: `regex` (motor endurecido contra ReDoS). `re2` se excluye por portabilidad.
  * `geoip`: `geoip2` + **MaxMind GeoLite2-Country.mmdb** (colócala en `/var/lib/GeoIP/` o usa `--geoip-db`).
  * `detect`: `chardet` y `python-magic` (o `python-magic-bin` en Windows) para detección robusta de MIME/codificación.
  * `images`: `Pillow` para leer metadatos de imagen de forma segura.
  * `sys`: `psutil`, `distro`, `humanfriendly`.
  * `net`: `psutil`, `ifaddr`, `dnspython`, `requests` y `pyroute2` (solo Linux).

---

## Comandos

### 📊 sabbat-loganalyce — Analizador Avanzado de Logs
[Manual rápido](docs/LOGANALYCE-ES.md) · [In English](docs/LOGANALYCE.md)

Lee logs planos o `.gz` (también desde `stdin`) y saca estadísticas, señales de seguridad y JSON/JSONL.

**Ejemplos**
```bash
# Análisis completo (columnas)
sabbat-loganalyce samples/access.log

# Búsqueda por patrón (primeros 50, ordenado)
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50

# Salida JSON
sabbat-loganalyce app.log --json
```

---

### 🕵️ sabbat-fileinspect — Inspector de Ficheros
[Manual rápido](docs/FILEINSPECT-ES.md) · [In English](docs/FILEINSPECT.md)

Inspector portable con foco en seguridad. Entiende texto, imágenes y binarios comunes.

```bash
# Forzar español + UTC + varios hashes + JSON
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts
```

---

### 🔧 sabbat-syscheck — Auditor de Sistema (solo lectura)
[Manual rápido](docs/SYSCHECK-ES.md) · [In English](docs/SYSCHECK.md)

Auditor ligero inspirado en Lynis. Revisa SSH, permisos, usuarios y cron para detectar desconfiguraciones comunes. **Solo lectura**, apto para CI, bilingüe y con salidas JSON/JSONL estables.

**Módulos**
- `--check-ssh` — parsea `sshd_config` (ej.: `PermitRootLogin`, `PasswordAuthentication`, `X11Forwarding`, `MaxAuthTries`).
- `--check-perms` — ficheros/dirs escribibles por todos bajo rutas críticas (`/etc`, `/var`, `/usr/bin`), con sensibilidad a sticky-bit (1777 → INFO).
- `--check-users` — UID 0 duplicados, contraseñas vacías y cuentas de sistema con shells interactivos.
- `--check-cron` — parser robusto de crons de sistema/usuario; detecta rutas relativas, uso de `/tmp` y scripts world‑writable.

**Salida y *Exit codes***
- Humano: agrupado (`--group`/`--no-group`), `--group-show N`
- Máquina: `--json`, `--jsonl`, `--raw` (TSV: `RISK\tMODULE\tMESSAGE\tPATH\tEVIDENCE`)
- Códigos de salida: `0` OK · `1` error de ejecución · `2` hallazgos MEDIO/ALTO

**Ejemplos con modulo cronaudit**
```bash
# Auditoría completa + JSON a fichero
sabbat-syscheck cronaudit --json --output audits/cron_$(date +%Y%m%d).json

# Solo sospechosos (patrones peligrosos o tu regex)
sabbat-syscheck cronaudit --check-dangerous --pattern 'rm -rf|wget|curl.*pipe'

# Foco en privilegios (root/excesos/mismatch)
sabbat-syscheck cronaudit --check-privileges --user root

# Solo timers de systemd
sabbat-syscheck cronaudit --only timers
```
**Ejemplos**

```bash
# Ejecutar todo (por defecto)
sabbat-syscheck

# JSON para dashboards/ingestión
sabbat-syscheck --json > syscheck.json
sabbat-syscheck --jsonl | jq .

# TSV sin agrupar (greppable)
sabbat-syscheck --raw --no-group | column -t -s $'\t'

# Limitar escaneo de permisos
sabbat-syscheck --check-perms --max-files 50000 --exclude /var/lib/docker /snap
```

#### Subcomando cronaudit (Cron + systemd timers)

**Qué hace**
- Listado unificado de **cron jobs** (sistema/usuarios) y **systemd timers**.
- Detecta **patrones peligrosos**: `rm -rf /`, `curl|bash`, `wget|bash`, `chmod 777`, base64→shell, `nc -e`, reverse shells, cryptominers, descargas `http://`.
- **Rutas/Resolución**: primer token no absoluto, binario no resoluble.
- **Variables**: `$VAR` / `${VAR}` sin default `${VAR:-def}`.
- **Privilegios**: tareas que probablemente requieran root vs. ejecución como root sin indicios.
- **Huérfanos**: usuario inexistente, binario faltante, `.service` ausente detrás de un timer.
- Salida JSON apta para SIEM.

**Ejemplos**
```bash
# Ejecutar todo (por defecto)
sabbat-syscheck

# JSON para dashboards/ingestión
sabbat-syscheck --json > syscheck.json
sabbat-syscheck --jsonl | jq .

# TSV sin agrupar (greppable)
sabbat-syscheck --raw --no-group | column -t -s $'\t'

# Limitar escaneo de permisos
sabbat-syscheck --check-perms --max-files 50000 --exclude /var/lib/docker /snap
```

---

### 🌐 sabbat-netinspect — Inspector de Red y Conexiones
[Manual rápido](docs/NETINSPECT-ES.md) · [In English](docs/NETINSPECT.md)
Ver [Troubleshooting](docs/NETINSPECT-TROUBLESHOOTING-ES.md)

Inspector **en vivo** del estado de red: conexiones activas, puertos en escucha, correlación con procesos, GeoIP opcional, inteligencia de amenazas local (CSV), whitelist de puertos, snapshots y diffs.

**Ejemplos**
```bash
# JSON con GeoIP y límite de conexiones
sabbat-netinspect --json --geoip-db /var/lib/GeoIP/GeoLite2-Country.mmdb --max-conns 500

# TI local + whitelist de puertos
sabbat-netinspect --check-threat-intel --ti-csv feeds/blacklist.csv                       --check-ports --whitelist /etc/allowed_ports.conf
```

---

## Solución de Problemas
- `re2` no disponible: se puede ignorar; `regex` cubre el endurecimiento.
- Base GeoIP ausente: usa `--geoip-db` o desactiva funciones GeoIP.
- Colores en CI: exporta `NO_COLOR=1`.

---

## Desarrollo

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

Estructura del proyecto (resumen):
```
sabbat_tools/
    ├── CHANGELOG.md
    ├── LICENSE
    ├── MANIFEST.in
    ├── Makefile
    ├── README-ES.md
    ├── README.md
    ├── docs
    │   ├── FILEINSPECT-ES.md
    │   ├── FILEINSPECT.md
    │   ├── LOGANALYCE-ES.md
    │   ├── LOGANALYCE.md
    │   ├── NETINSPECT-ES.md
    │   ├── NETINSPECT-TROUBLESHOOTING-ES.md
    │   ├── NETINSPECT-TROUBLESHOOTING.md
    │   ├── NETINSPECT.md
    │   ├── SYSCHECK-ES.md
    │   └── SYSCHECK.md
    ├── pyproject.toml
    ├── pytest.ini
    ├── requirements-dev.txt
    ├── requirements.txt
    ├── sabbat_tools
    │   ├── __init__.py
    │   ├── audits
    │   ├── fileinspect.py
    │   ├── loganalyce.py
    │   ├── netinspect.py
    │   └── syscheck.py
    ├── scripts
    │   └── gen_toc.py
    ├── tests
    │   ├── conftest.py
    │   ├── pysql
    │   ├── test_fileinspect.py
    │   ├── test_loganalyce.py
    │   ├── test_netinspect.py
    │   └── test_syscheck.py
    └── tree.txt
```

---

## Contribuir
¡PRs e issues bienvenidos! Filosofía:
- Seguro por defecto, tests robustos, UX clara.
- Nuevos comandos deben venir con tests y sección en README.

---

## Licencia
MIT © Óscar Giménez Blasco
