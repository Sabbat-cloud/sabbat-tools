<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Tabla de Contenidos**

- [🧰 sabbat-tools — Caja de Herramientas CLI de Sistema y Seguridad](#-sabbat-tools--caja-de-herramientas-cli-de-sistema-y-seguridad)
  - [Tabla de contenidos](#tabla-de-contenidos)
  - [Instalación](#instalación)
  - [Requisitos y Extras](#requisitos-y-extras)
  - [Comandos](#comandos)
    - [📊 sabbat-loganalyce — Analizador Avanzado de Logs](#-sabbat-loganalyce--analizador-avanzado-de-logs)
    - [🕵️ sabbat-fileinspect — Inspector de Ficheros](#-sabbat-fileinspect--inspector-de-ficheros)
    - [🔧 sabbat-syscheck — Auditor del Sistema (solo lectura)](#-sabbat-syscheck--auditor-del-sistema-solo-lectura)
      - [Subcomando cronaudit (Cron + systemd timers)](#subcomando-cronaudit-cron--systemd-timers)
    - [📝 sabbat-rawtext — Extractor de Texto Plano (.docx/.odt/.ods/.txt)](#-sabbat-rawtext--extractor-de-texto-plano-docxodtods-txt)
    - [🌐 sabbat-netinspect — Inspector de Red y Conexiones](#-sabbat-netinspect--inspector-de-red-y-conexiones)
  - [Solución de problemas](#solución-de-problemas)
  - [Desarrollo](#desarrollo)
  - [Contribuir](#contribuir)
  - [Licencia](#licencia)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# 🧰 sabbat-tools — Caja de Herramientas CLI de Sistema y Seguridad

[![CI](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci-lean.yml/badge.svg)](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci-lean.yml)
![Versiones de Python](https://img.shields.io/badge/python-3.8--3.12-informational)
[![Licencia: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#licencia)

**sabbat-tools** es una colección de utilidades de línea de comandos listas para producción para sysadmins, SREs y equipos de seguridad.

- UX bilingüe (auto/en/es) cuando aplica
- Amigable para automatización (JSON/JSONL limpios y códigos de salida predecibles)
- Endurecido con cariño: límites de entrada, rutas regex seguras contra ReDoS, confinamiento seguro de salida

> **English**: Prefer docs in English? [🇬🇧 English](README.md)
---

---
## Tabla de contenidos
- [Instalación](#instalación)
- [Requisitos y Extras](#requisitos-y-extras)
- [Comandos](#comandos)
  - [📊 sabbat-loganalyce — Analizador Avanzado de Logs](#-sabbat-loganalyce--analizador-avanzado-de-logs)
  - [🕵️ sabbat-fileinspect — Inspector de Ficheros](#-sabbat-fileinspect--inspector-de-ficheros)
  - [🔧 sabbat-syscheck — Auditor del Sistema (solo lectura)](#-sabbat-syscheck--auditor-del-sistema-solo-lectura)
  - [📝 sabbat-rawtext — Extractor de Texto Plano (.docx/.odt/.ods/.txt)](#-sabbat-rawtext--extractor-de-texto-plano-docxodtods-txt)
  - [🌐 sabbat-netinspect — Inspector de Red y Conexiones](#-sabbat-netinspect--inspector-de-red-y-conexiones)
- [Solución de problemas](#solución-de-problemas)
- [Desarrollo](#desarrollo)
- [Contribuir](#contribuir)
- [Licencia](#licencia)
---

## Instalación

```bash
# Clonar (desarrollo)
git clone https://github.com/Sabbat-cloud/sabbat-tools
cd sabbat-tools

# Recomendado: todas las funciones
pip install -e ".[full]"

# o aislado para usuario:
# pipx install "sabbat-tools[full]"
```

Tras la instalación, tendrás en el PATH los comandos `sabbat-loganalyce`, `sabbat-fileinspect`, `sabbat-syscheck`, **`sabbat-rawtext`** y `sabbat-netinspect`.

---

## Requisitos y Extras

* Python ≥ 3.8
* Extras opcionales:
  * `hardened`: `regex` (escaneo resistente a ReDoS). `re2` se excluye a propósito por portabilidad.
  * `geoip`: `geoip2` + **MaxMind GeoLite2-Country.mmdb** (ponlo en `/var/lib/GeoIP/` o usa `--geoip-db`).
  * `detect`: `chardet` y `python-magic` (o `python-magic-bin` en Windows) para detección robusta de MIME/codificación.
  * `images`: `Pillow` para leer metadatos de imagen de forma segura.
  * `sys`: `psutil`, `distro`, `humanfriendly`.
  * `net`: `psutil`, `ifaddr`, `dnspython`, `requests` (y `pyroute2` en Linux).
  * **`codecs` (nuevo)**: `zstandard` para leer logs `.zst` en **sabbat-loganalyce** (otros formatos incorporados: `.gz`, `.bz2`, `.xz`, `.lzma`).
  * **`text` (nuevo)**: `python-docx`, `odfpy` para **sabbat-rawtext** (DOCX/ODT/ODS → TXT).

---

## Comandos

### 📊 sabbat-loganalyce — Analizador Avanzado de Logs
[Manual](docs/LOGANALYCE-ES.md) · [In English](docs/LOGANALYCE.md)

Lee logs planos o comprimidos por **magic bytes**: `.gz`, `.bz2`, `.xz`, `.lzma` y `.zst` (si instalas `zstandard`). Soporta stdin, filtros de tiempo, GeoIP, estadísticas multihilo y modo regex endurecido.

**Novedades (reciente)**
- Auto‑detección por magic bytes (sin depender de la extensión).
- Errores con contexto de permisos y mensajes i18n.
- **Pre‑escaneo** de logs grandes + límites de seguridad por bytes/líneas.
- Opción de regex endurecida (`--hardened-regex`) usando `regex`.
- Códigos de salida predecibles: `0` ok · `1` error runtime · `2` alertas de seguridad o permisos/códecs no soportados.
- Confinamiento seguro de salida (CWD) salvo `--unsafe-output`.
- Habilitar/deshabilitar stdin con `--deny-stdin`.
- Mejor esquema JSON + caché LRU para GeoIP.

**Ejemplos**
```bash
# Análisis completo (columnas)
sabbat-loganalyce samples/access.log

# Comprimidos (auto): gz/bz2/xz/lzma/zst*
sabbat-loganalyce logs/access.log.gz
sabbat-loganalyce logs/access.log.bz2
sabbat-loganalyce logs/access.log.xz
sabbat-loganalyce logs/access.log.lzma
sabbat-loganalyce logs/access.log.zst       # requiere: pip install zstandard

# Búsqueda de patrones (primeros 50, ordenados)
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50

# Salida JSON + regex endurecida + ventana temporal
sabbat-loganalyce app.log --json --hardened-regex --since "2025-09-01" --until "2025-09-30 23:59:59"
```

**Códigos de salida**
- `0` éxito (sin alertas de seguridad)
- `2` alertas de seguridad detectadas (SQLi/XSS/traversal) **o** errores de permisos/códec no soportado
- `1` otros errores de ejecución

---

### 🕵️ sabbat-fileinspect — Inspector de Ficheros
[Manual](docs/FILEINSPECT-ES.md) · [In English](docs/FILEINSPECT.md)

Inspector portable con foco en seguridad y peritaje forense para texto, imágenes, comprimidos, documentos y binarios.

**Novedades (reciente)**
- **Motor nativo de *magic bytes* y detección de *spoofing***: identifica `ELF`, `PE`, `Mach-O`, `PDF`, `ZIP/OOXML`, comprimidos, imágenes y texto plano sin depender de librerías externas, alertando ante discrepancias extensión/contenido (p. ej. un ejecutable PE camuflado como `.jpg`) y dobles extensiones sospechosas (`factura.pdf.exe`).
- **Entropía de Shannon y cabeceras binarias nativas**: calcula la entropía del fichero (`0.0–8.0` bits/byte) para detectar binarios empaquetados o cifrados, y analiza cabeceras **PE** (arquitectura, `EXE`/`DLL`, fecha de compilación UTC, secciones de *packers* como `UPX0`) y **ELF** en Python puro.
- **Escaneo ampliado de secretos y heurísticas de malware**: detecta contraseñas, API keys, tokens **JWT**, **Slack**, **Google Cloud**, **Stripe**, **AWS**, **URIs de bases de datos con credenciales**, tarjetas (Luhn), *cradles* de PowerShell y *reverse shells*.
- **Endurecimiento en comprimidos y documentos**: detecta **Zip Slip** (*path traversal*) y **Zip Bombs** en `.zip`/`.tar*`, así como etiquetas activas peligrosas en PDF (`/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFiles`) y macros VBA en Office (`vbaProject.bin`).
- **Listo para CI/CD y automatización**: `--json`, `--jsonl`, `-o / --output`, informes HTML/PDF protegidos contra XSS, caché de hashes en SQLite y `--fail-on-alert` (`--strict`) con código de salida `2` si hay hallazgos.

**Ejemplos**
```bash
# Forzar español + UTC + múltiples hashes + JSON
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts

# Escaneo recursivo de secretos y heurísticas a JSONL (sale con código 2 si hay alertas)
sabbat-fileinspect -r . --include-pattern "*.py,*.sh,*.env" --malware-heuristics --fail-on-alert --jsonl -o scan.jsonl

# Análisis profundo de archivos comprimidos (detecta Zip Slip, Zip Bombs y secretos internos)
sabbat-fileinspect backup.zip --archives deep --malware-heuristics --json
```

---

### 🔧 sabbat-syscheck — Auditor del Sistema (solo lectura)
[Manual](docs/SYSCHECK-ES.md) · [In English](docs/SYSCHECK.md)

Auditor ligero e inocuo (inspirado en Lynis). Revisa configuración de SSH, permisos, usuarios y cron.

**Ejemplos**
```bash
# Ejecutar todos los módulos (por defecto)
sabbat-syscheck

# JSON para paneles/ingestión
sabbat-syscheck --json > syscheck.json
sabbat-syscheck --jsonl | jq .

# TSV crudo (grepping fácil)
sabbat-syscheck --raw --no-group | column -t -s $'	'
```
#### Subcomando cronaudit (Cron + systemd timers)

**Qué hace**
- Listado unificado de **cron** (sistema/usuario) y **systemd timers**.
- Detecta **patrones peligrosos**: `rm -rf /`, `curl|bash`, `wget|bash`, `chmod 777`, base64→shell, `nc -e`, *reverse shells*, *cryptominers*, *http://* fetch.
- **Ruta/Resolución**: primer token no absoluto, binario no resoluble.
- **Variables de entorno**: `$VAR` / `${VAR}` sin default `${VAR:-def}`.
- **Privilegios**: tareas que probablemente requieren root vs. ejecutándose como root sin indicarlo.
- **Huérfanos**: usuario faltante, binario faltante, `.service` inexistente detrás de un *timer*.
- Salida JSON lista para SIEM.

**Ejemplos**
```bash
# Auditoría completa + JSON guardado
sabbat-syscheck cronaudit --json --output audits/cron_$(date +%Y%m%d).json

# Solo comandos sospechosos (patrones peligrosos o tu regex)
sabbat-syscheck cronaudit --check-dangerous --pattern 'rm -rf|wget|curl.*pipe'

# Enfoque en privilegios (root/exceso/desajuste)
sabbat-syscheck cronaudit --check-privileges --user root

# Solo systemd timers
sabbat-syscheck cronaudit --only timers
```
---

### 📝 sabbat-rawtext — Extractor de Texto Plano (.docx/.odt/.ods/.txt)

Convierte ficheros Office/OpenDocument a **`.txt` UTF‑8** limpio de forma local. Mantiene el orden de lectura, aplana tablas (fila → línea, celdas unidas por espacios) y guarda de forma robusta en Windows (nombres saneados, fallback a *Documentos*/temporal, sufijos `-1`, `-2` si el destino está ocupado).

**Requiere**: extra `text` (`python-docx`, `odfpy`) — incluido en `[full]`.

**Ejemplos**
```bash
# Interactivo (pregunta la ruta del archivo)
sabbat-rawtext

# No interactivo (uno o varios archivos)
sabbat-rawtext "Informe Q3.docx" hoja.ods notas.odt

# Comodines (en Windows, los globs se expanden internamente)
sabbat-rawtext *.docx docs/*.odt "facturas 2025/*.ods"
```

**Notas**
- Soportados: `.docx`, `.odt`, `.ods`, `.txt` (re‑normaliza).  
- `.doc` (legado) → no soportado (convierte a `.docx` primero).
- Código de salida: `0` todo OK, `1` si falla algún objetivo (no soportado/lectura/guardado).

---

### 🌐 sabbat-netinspect — Inspector de Red y Conexiones
[Manual](docs/NETINSPECT-ES.md) · [In English](docs/NETINSPECT.md)  
Ver [Solución de problemas](docs/NETINSPECT-TROUBLESHOOTING-ES.md)

Inspector portable (basado en `psutil`) del estado de red en vivo: conexiones, puertos en escucha, correlación de procesos y unidades `systemd`, GeoIP opcional, *threat intel* local, lista blanca de puertos, snapshots y diffs.

**Novedades (reciente)**
- **Filtrado avanzado**: filtra por `--proto {tcp,udp,all}`, `--state`, `--scope {all,own}`, `--pid`, `--user`, `--proc <nombre>`, `--laddr <IP/CIDR>`, `--raddr <IP/CIDR>`, `--lport`, `--rport`, `--only-public` y `--only-suspicious`.
- **Threat Intel con soporte CIDR y Whitelist por rangos**: el CSV de Threat Intel (`--ti-csv`) soporta tanto IPs exactas como subredes CIDR IPv4/IPv6 (`198.51.100.0/24`); la lista blanca de puertos admite puertos individuales (`tcp/22`), rangos (`tcp/8000-8100`) y comodines (`tcp/*`).
- **Heurísticas de seguridad**: detecta servicios críticos expuestos en `0.0.0.0`/`::` (`exposed_sensitive_port` para Redis, MongoDB, Docker API, MySQL, PostgreSQL, RDP, SMB, etc.), puertos de C2/minería (`c2_like_port`), procesos ejecutándose desde `/tmp` o `/dev/shm` (`proc_suspicious_path`) y puertos fuera de whitelist (`not_in_whitelist`).
- **Enriquecimiento concurrente y rápido**: resolución inversa DNS (`--rdns`) en paralelo con caché y límite global `--deadline-sec`, caché de GeoIP y comparativas detalladas entre snapshots (`--snapshot`, `--diff`).

**Ejemplos**
```bash
# JSON con GeoIP y límite de conexiones
sabbat-netinspect --json --geoip-db /var/lib/GeoIP/GeoLite2-Country.mmdb --max-conns 500

# Solo conexiones establecidas hacia IPs públicas o solo conexiones sospechosas
sabbat-netinspect --only-public --state established
sabbat-netinspect --only-suspicious

# CSV de threat-intel (IPs + CIDR) + comprobación de puertos permitidos
sabbat-netinspect --check-threat-intel --ti-csv feeds/blacklist.csv \
                  --check-ports --whitelist /etc/allowed_ports.conf
```
---

## Solución de problemas
- `re2` no disponible: puedes ignorarlo; `regex` aporta el motor endurecido.
- Falta DB de GeoIP: usa `--geoip-db` o evita funciones de GeoIP.
- Colores en CI: exporta `NO_COLOR=1`.
- **Logs comprimidos**: `.zst` requiere `pip install zstandard`. Otros formatos funcionan de serie.
- **Permisos**: si ves “permission denied”, prueba con `sudo` o ajusta ACLs de la ruta.

---

## Desarrollo

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

Estructura del proyecto (simplificada):
```
sabbat_tools/
    ├── CHANGELOG.md
    ├── LICENSE
    ├── MANIFEST.in
    ├── Makefile
    ├── README-ES.md
    ├── README.md
    ├── docs
    │   ├── FILEINSPECT-ES.md
    │   ├── FILEINSPECT.md
    │   ├── LOGANALYCE-ES.md
    │   ├── LOGANALYCE.md
    │   ├── NETINSPECT-ES.md
    │   ├── NETINSPECT-TROUBLESHOOTING-ES.md
    │   ├── NETINSPECT-TROUBLESHOOTING.md
    │   ├── NETINSPECT.md
    │   ├── SYSCHECK-ES.md
    │   └── SYSCHECK.md
    ├── pyproject.toml
    ├── pytest.ini
    ├── requirements-dev.txt
    ├── requirements.txt
    ├── sabbat_tools
    │   ├── __init__.py
    │   ├── audits
    │   ├── fileinspect.py
    │   ├── loganalyce.py
    │   ├── netinspect.py
    │   ├── rawtext.py
    │   └── syscheck.py
    ├── scripts
    │   └── gen_toc.py
    ├── tests
    │   ├── conftest.py
    │   ├── pysql
    │   ├── test_fileinspect.py
    │   ├── test_loganalyce.py
    │   ├── test_netinspect.py
    │   └── test_syscheck.py
    └── tree.txt
```

---

## Contribuir
PRs e issues bienvenidos. Mantén la filosofía:
- Seguro por defecto, tests robustos, UX clara.
- Los nuevos comandos deben venir con tests y su sección de README.

---

## Licencia
MIT © Óscar Giménez Blasco
