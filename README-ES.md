# 🧰 sabbat-tools — Caja de Herramientas CLI de Sistema y Seguridad
[![Docs](https://img.shields.io/badge/Docs-Ingl%C3%A9s%20%7C%20Espa%C3%B1ol-blue)](README-ES.md)
[🇬🇧 English](README.md) · [🇪🇸 Español](README-ES.md)


[![CI](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/sabbat-tools.svg)](https://pypi.org/project/sabbat-tools/)
![Python Versions](https://img.shields.io/pypi/pyversions/sabbat-tools.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#licencia)

**sabbat-tools** es un conjunto de utilidades de línea de comandos listas para producción para sysadmins, SREs y equipos de seguridad.

- ✅ UX bilingüe (`auto`/`en`/`es`) donde aplica
- ✅ Seguro por defecto y amigable para automatización (modos JSON limpios y *exit codes* estables)
- ✅ Endurecido: límites de entrada, rutas regex resistentes a ReDoS, confinamiento seguro de salidas

---
<!-- toc -->
- [🧰 sabbat-tools — Caja de Herramientas CLI de Sistema y Seguridad](#sabbat-tools-caja-de-herramientas-cli-de-sistema-y-seguridad)
  - [📚 Índice](#ndice)
  - [Instalación](#instalacin)
- [Instalación base (añade CLIs al PATH)](#instalacin-base-aade-clis-al-path)
- [Recomendado (todas las características):](#recomendado-todas-las-caractersticas)
  - [Requisitos y Extras](#requisitos-y-extras)
  - [Comandos](#comandos)
    - [📊 sabbat-loganalyce — Analizador Avanzado de Logs](#sabbat-loganalyce-analizador-avanzado-de-logs)
- [Análisis completo (columnas)](#anlisis-completo-columnas)
- [Búsqueda por patrón (primeros 50, ordenado)](#bsqueda-por-patrn-primeros-50-ordenado)
- [Salida JSON](#salida-json)
    - [🕵️ sabbat-fileinspect — Inspector de Ficheros](#sabbat-fileinspect-inspector-de-ficheros)
- [Forzar español + UTC + varios hashes + JSON](#forzar-espaol-utc-varios-hashes-json)
    - [🔧 sabbat-syscheck — Auditor de Sistema (solo lectura)](#sabbat-syscheck-auditor-de-sistema-solo-lectura)
- [Ejecutar todo (por defecto)](#ejecutar-todo-por-defecto)
- [JSON para dashboards/ingestión](#json-para-dashboardsingestin)
- [TSV sin agrupar (greppable)](#tsv-sin-agrupar-greppable)
- [Limitar escaneo de permisos](#limitar-escaneo-de-permisos)
      - [Subcomando cronaudit (Cron + systemd timers)](#subcomando-cronaudit-cron-systemd-timers)
- [Auditoría completa + JSON a fichero](#auditora-completa-json-a-fichero)
- [Solo sospechosos (patrones peligrosos o tu regex)](#solo-sospechosos-patrones-peligrosos-o-tu-regex)
- [Foco en privilegios (root/excesos/mismatch)](#foco-en-privilegios-rootexcesosmismatch)
- [Solo timers de systemd](#solo-timers-de-systemd)
    - [🌐 sabbat-netinspect — Inspector de Red y Conexiones](#sabbat-netinspect-inspector-de-red-y-conexiones)
- [JSON con GeoIP y límite de conexiones](#json-con-geoip-y-lmite-de-conexiones)
- [TI local + whitelist de puertos](#ti-local-whitelist-de-puertos)
- [Snapshot y diff](#snapshot-y-diff)
- [comentarios](#comentarios)
  - [Buenas Prácticas](#buenas-prcticas)
  - [JSON y Códigos de Salida](#json-y-cdigos-de-salida)
  - [Solución de Problemas](#solucin-de-problemas)
  - [Desarrollo](#desarrollo)
- [Instalación editable con extras comunes](#instalacin-editable-con-extras-comunes)
- [Tests (verboso)](#tests-verboso)
- [Linter (ruff)](#linter-ruff)
  - [Contribuir](#contribuir)
  - [Licencia](#licencia)
    - [Pie de proyecto](#pie-de-proyecto)
<!-- tocstop -->


## 📚 Índice

- [Instalación](#instalación)
- [Requisitos y Extras](#requisitos-y-extras)
- [Comandos](#comandos)
  - [📊 sabbat-loganalyce — Analizador Avanzado de Logs](#-sabbat-loganalyce--analizador-avanzado-de-logs)
  - [🕵️ sabbat-fileinspect — Inspector de Ficheros](#-sabbat-fileinspect--inspector-de-ficheros)
  - [🔧 sabbat-syscheck — Auditor de Sistema (solo lectura)](#-sabbat-syscheck--auditor-de-sistema-solo-lectura)
    - [Subcomando cronaudit (Cron + systemd timers)](#subcomando-cronaudit-cron--systemd-timers)
- [Buenas Prácticas](#buenas-prácticas)
- [JSON y Códigos de Salida](#json-y-códigos-de-salida)
- [Solución de Problemas](#solución-de-problemas)
- [Desarrollo](#desarrollo)
- [Contribuir](#contribuir)
- [Licencia](#licencia)

---

## Instalación

```bash
git clone https://github.com/Sabbat-cloud/sabbat-tools
cd sabbat-tools

# Instalación base (añade CLIs al PATH)
pip install .

# Recomendado (todas las características):
pip install -e ".[geoip,images,detect,hardened]"
```

> Tras instalar, tendrás `sabbat-loganalyce`, `sabbat-fileinspect` y `sabbat-syscheck` en el PATH.

---

## Requisitos y Extras

* **Python** ≥ 3.8
* Extras opcionales:
  * `hardened`: `regex` (y `re2` si hay ruedas) para escaneos resistentes a ReDoS
  * `geoip`: `geoip2` + **MaxMind GeoLite2-Country.mmdb** (en `/var/lib/GeoIP/` o usar `--geoip-db`)
  * `detect`: `chardet` y `python-magic`/`file(1)` para detección MIME robusta en `sabbat-fileinspect`
  * `images`: `Pillow` para analizar imágenes de forma segura

---

## Comandos

### 📊 sabbat-loganalyce — Analizador Avanzado de Logs

Lee logs planos o `.gz`, soporta `stdin` y saca estadísticas, señales de seguridad y JSON.

**Ejemplos rápidos**
```bash
# Análisis completo (columnas)
sabbat-loganalyce access.log

# Búsqueda por patrón (primeros 50, ordenado)
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50

# Salida JSON
sabbat-loganalyce app.log --json
```

---

### 🕵️ sabbat-fileinspect — Inspector de Ficheros

Inspector portable con foco en seguridad. Entiende texto, imágenes y binarios comunes.

```bash
# Forzar español + UTC + varios hashes + JSON
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts
```

---

### 🔧 sabbat-syscheck — Auditor de Sistema (solo lectura)

Auditor ligero, inspirado en Lynis. Revisa SSH, permisos de ficheros, usuarios y cron para detectar desconfiguraciones comunes. **Solo lectura**, apto para CI, bilingüe (EN/ES) y con salidas JSON/JSONL estables.

**Módulos**
- `--check-ssh` — parsea `sshd_config` (ej.: `PermitRootLogin`, `PasswordAuthentication`, `X11Forwarding`, `MaxAuthTries`).  
- `--check-perms` — ficheros/dirs escribibles por todos bajo rutas críticas (`/etc`, `/var`, `/usr/bin`), con sensibilidad a sticky-bit (1777 → INFO).
- `--check-users` — UID 0 duplicados, contraseñas vacías y cuentas de sistema con shells interactivos.
- `--check-cron` — parser robusto de crons de sistema/usuario; detecta rutas relativas, uso de `/tmp` y scripts world‑writable.

**Salida y *Exit codes***
- Humano: agrupado (`--group`/`--no-group`), `--group-show N`
- Máquina: `--json`, `--jsonl`, `--raw` (TSV: `RISK\tMODULE\tMESSAGE\tPATH\tEVIDENCE`)
- Códigos de salida: `0` OK · `1` error de ejecución · `2` hallazgos MEDIO/ALTO

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
# Auditoría completa + JSON a fichero
sabbat-syscheck cronaudit --json --output audits/cron_$(date +%Y%m%d).json

# Solo sospechosos (patrones peligrosos o tu regex)
sabbat-syscheck cronaudit --check-dangerous --pattern 'rm -rf|wget|curl.*pipe'

# Foco en privilegios (root/excesos/mismatch)
sabbat-syscheck cronaudit --check-privileges --user root

# Solo timers de systemd
sabbat-syscheck cronaudit --only timers
```

**Códigos de salida**
- Clásico: `0` si no hay MEDIO/ALTO, `2` en caso contrario.
- `cronaudit`: `0` si no hay HIGH/CRITICAL (o con `--dry-run`), `2` si los hay.

**Formato JSON**
```json
{
  "ts": "2025-10-07T09:54:21+02:00",
  "host": "node01",
  "tool": "sabbat-syscheck",
  "module": "cronaudit",
  "version": "1.0.0",
  "findings": [
    {
      "kind": "cron",
      "id": "cron:/etc/cron.d/backup:root:...",
      "user": "root",
      "command": "/usr/local/bin/backup ...",
      "issues": [{"code": "cmd.dangerous_pattern", "severity": "critical"}],
      "orphaned": false
    }
  ]
}
```

---

### 🌐 sabbat-netinspect — Inspector de Red y Conexiones

Inspector **en vivo** del estado de red: conexiones activas, puertos en escucha, correlación con procesos, GeoIP opcional, inteligencia de amenazas local (CSV), comprobación de whitelist de puertos, snapshots y diffs.

**Características Clave**
- TCP/UDP (IPv4/IPv6) + correlación PID→Proceso (`psutil`)
- Filtros: `--proto`, `--state`, `--pid`, `--user`, `--lport`, `--rport`, `--include-unix`
- GeoIP (opcional): `--geoip-db /var/lib/GeoIP/GeoLite2-Country.mmdb` (requiere `geoip2`)
- Threat Intel local: `--check-threat-intel --ti-csv feeds/blacklist.csv` (sin llamadas online)
- Whitelist de puertos en escucha: `--check-ports --whitelist /etc/allowed_ports.conf`
- Reverse DNS opcional: `--rdns`
- Snapshots y diffs: `--snapshot --output ...` / `--diff prev.json`
- Salidas: humana, `--raw` (TSV), `--json`, `--jsonl`
- Privacidad por defecto (`--sanitize`). Usa `--unsafe-proc-cmdline` para incluir `cmdline` completo.

**Ejemplos**
```bash
# JSON con GeoIP y límite de conexiones
sabbat-netinspect --json --geoip-db /var/lib/GeoIP/GeoLite2-Country.mmdb --max-conns 500

# TI local + whitelist de puertos
sabbat-netinspect --check-threat-intel --ti-csv feeds/blacklist.csv \
                  --check-ports --whitelist /etc/allowed_ports.conf

# Snapshot y diff
sabbat-netinspect --snapshot --output snapshots/net_$(date +%F).json
sabbat-netinspect --diff snapshots/net_2025-10-07.json --json
````

**Formato whitelist**

```
# comentarios
tcp/22
tcp/443
udp/53
tcp/*        # permitir todos los tcp (solo dev)
```

**CSV de Threat Intel (mínimo)**

```csv
ip,source,confidence
203.0.113.50,local-blacklist,95
198.51.100.23,dfir-feed,80
```

**Códigos de salida**

* `0` = sin flags sospechosas
* `2` = hay flags sospechosas (p.ej. `ti_blacklisted`, `not_in_whitelist`, `exposed_high_port`)

````
---

## Buenas Prácticas

* Endurecimiento ReDoS: usa `--hardened-regex` (instala `regex`).
* GeoIP: descarga y configura GeoLite2-Country.mmdb y pásalo con `--geoip-db` si aplica.
* CI: exporta `NO_COLOR=1` para salidas consistentes.

---

## JSON y Códigos de Salida

Cada comando ofrece JSON estable y códigos de salida previsibles para pipelines de CI (ver secciones de cada comando).

---

## Solución de Problemas

* **`re2` no disponible**: se puede ignorar; `regex` cubre la mayoría de casos.
* **Base de GeoIP ausente**: usa `--geoip-db` o desactiva funciones GeoIP.
* **Colores en CI**: `NO_COLOR=1`.

---

## Desarrollo

```bash
# Instalación editable con extras comunes
pip install -e ".[detect,images,hardened]"

# Tests (verboso)
pytest -vv

# Linter (ruff)
ruff check .
```

**Estructura del proyecto**
```
sabbat_tools/
  ├─ loganalyce.py      # sabbat-loganalyce
  ├─ fileinspect.py     # sabbat-fileinspect
  └─ syscheck.py        # sabbat-syscheck (con subcomando 'cronaudit')
tests/
  ├─ conftest.py
  └─ test_syscheck.py
```

---

## Contribuir

¡PRs e issues bienvenidos! Mantén la filosofía:

* Seguro por defecto, tests robustos, UX clara.
* Nuevos comandos siempre con tests y su sección en README.

---

## Licencia

MIT © Óscar Giménez Blasco

---

### Pie de proyecto

© 2025 Óscar Giménez Blasco — Publicado bajo [Licencia MIT](LICENSE).

