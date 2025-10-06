```markdown
# README-ES.md

# 🧰 sabbat-tools — Caja de herramientas CLI de sistema y seguridad

[![CI](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/Sabbat-cloud/sabbat-tools/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/sabbat-tools.svg)](https://pypi.org/project/sabbat-tools/) <!-- se activará al publicar -->
![Python Versions](https://img.shields.io/pypi/pyversions/sabbat-tools.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#licencia)

**sabbat-tools** es una colección de utilidades de línea de comandos para administración de sistemas, SRE y seguridad.

- ✅ Interfaz bilingüe (auto/en/es) cuando aplica  
- ✅ Seguro por defecto y listo para automatización (salidas JSON limpias)  
- ✅ Endurecimiento: límites de entrada, rutas regex anti-ReDoS, confinamiento de salida

> **English**: Prefer the English docs? Read [README.md](./README.md).

---

## 📚 Índice

- [Instalación](#instalación)
- [Requisitos y Extras](#requisitos-y-extras)
- [Comandos](#comandos)
  - [📊 sabbat-loganalyce — Analizador Avanzado de Logs](#-sabbat-loganalyce--analizador-avanzado-de-logs)
  - [🕵️ sabbat-fileinspect — Inspector de Ficheros](#-sabbat-fileinspect--inspector-de-ficheros)
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

# Instalación base (añade los CLIs al PATH)
pip install .

# Recomendado para todas las funciones:
pip install -e ".[geoip,images,detect,hardened]"
````

> Tras instalar, tendrás `sabbat-loganalyce` y `sabbat-fileinspect` en tu PATH.

---

## Requisitos y Extras

* **Python** ≥ 3.8
* Extras opcionales:

  * `hardened`: `regex` (y opcional `re2` si hay wheel) para endurecer rutas regex (anti-ReDoS)
  * `geoip`: `geoip2` + **MaxMind GeoLite2-Country.mmdb** (en `/var/lib/GeoIP/` o `--geoip-db`)
  * `detect`: `chardet` y `python-magic`/`file(1)` para detección MIME robusta en `sabbat-fileinspect`
  * `images`: `Pillow` para metadatos de imágenes

> Si `re2` no está disponible, se omite; `regex` ya aporta endurecimiento suficiente.

---

## Comandos

### 📊 sabbat-loganalyce — Analizador Avanzado de Logs

Lee logs planos o `.gz`, soporta `stdin` y genera estadísticas, señales de seguridad y JSON.

**Idioma**

* Auto: `--lang auto` (por defecto)
* Forzar: `--lang {en|es}`

**Novedades**

* **Seguridad**: confinamiento de salida (`--output` confinado al CWD salvo `--unsafe-output`), sanitiza ANSI, mitigación ReDoS (`--hardened-regex` si `regex`)
* **Rendimiento**: estadísticas multihilo (`--threads`, `--batch-size`), pipeline de *futures* acotado
* **UX**: vista columnas/lista, tops configurables, JSON enriquecido
* **Aviso temprano de logs grandes**: pre-escaneo rápido antes del análisis (`--large-threshold`)

**Ejemplos**

```bash
# Análisis completo (columnas)
sabbat-loganalyce access.log

# Vista lista
sabbat-loganalyce access.log --list-view

# Búsqueda de patrón (primeras 50, ordenadas)
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50

# Salida JSON
sabbat-loganalyce app.log --json

# Guardar JSON (confinado al CWD)
sabbat-loganalyce app.log --json --output reports/result.json

# Filtro temporal (UTC)
sabbat-loganalyce access.log --since 2024-01-01 --until "2024-01-31 23:59:59"

# stdin
zcat access.log.gz | sabbat-loganalyce - --json
```

**Opciones clave**

* Entrada: `file | -` (stdin), `--encoding`, `--max-line-chars`, `--max-bytes`, `--deny-stdin`
* Vistas: `--list-view`, `--top-urls N`, `--top-uas N`, `--top-ips N`
* Seguridad: `--hardened-regex`, `--unsafe-output`, `--force`, `--no-sanitize-ansi`
* Tiempo: `--since`, `--until` (UTC)
* GeoIP: `--geoip-db PATH`
* Rendimiento: `--threads N`, `--batch-size N`, **pre-scan** `--large-threshold N`
* Búsqueda: `-p REGEX`, `-c N` (ordenada, mono-hilo)

---

### 🕵️ sabbat-fileinspect — Inspector de Ficheros

Inspector portable con foco en seguridad. Entiende texto, imágenes y binarios comunes.

**Idioma**

* `--lang {auto,en,es}`

**Novedades**

* MIME robusto: `python-magic` → `file(1)` (con *timeout*) → `mimetypes`
* Hashes: `--hash sha256,sha1,md5` (por defecto `sha256`) o `--no-hash` (usa `mmap` cuando procede)
* Secretos: patrones comunes + alta entropía (base64/hex), límites configurables
* Imágenes: verificación segura (`Pillow`) y metadatos
* Binarios: detección por cabecera (ELF/PE/Mach-O) + `readelf` opcional (con *timeout*)
* Tiempo: `--utc` (ISO 8601)
* Respeta `NO_COLOR`; JSON estable

**Ejemplos**

```bash
# Inspección básica (idioma automático)
sabbat-fileinspect /etc/passwd

# Forzar español + UTC + hashes múltiples + JSON
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts

# Sin hashes y sin seguir symlinks
sabbat-fileinspect --no-hash --nofollow /ruta/a/enlace

# Limitar escaneo de secretos
sabbat-fileinspect --max-secret-bytes 262144 --max-secret-lines 300 app.env
```

**Opciones clave**

* Idioma y formato: `--lang`, `--json`, `--utc`, NO_COLOR
* Tamaño: `-b/--bytes`, `-k/--kb`, `-m/--mb`, `-g/--gb`
* Hashes: `--no-hash` o `--hash sha256,sha1,md5`
* Symlinks: `--nofollow`
* Secretos: `--max-secret-bytes N`, `--max-secret-lines N`

---

## Buenas Prácticas

* Logs enormes: usa `--large-threshold` y/o `--max-bytes`.
* ReDoS: activa `--hardened-regex` si instalas `regex`.
* GeoIP: instala GeoLite2-Country.mmdb y usa `--geoip-db` si no está en la ruta por defecto.
* Secretos: ajusta `--max-secret-bytes/lines`.
* CI: `NO_COLOR=1`.

---

## JSON y Códigos de Salida

**sabbat-loganalyce**

* JSON: `schema_version`, `generated_at`, `lang`, `summary`, `parameters_used`, `security_alerts`, `http_*`, `tops`, `truncated_lines`, `bytes_read`.
* Códigos:

  * `0` ok
  * `1` error
  * `2` **alertas de seguridad detectadas** (útil en CI)

**sabbat-fileinspect**

* JSON con claves estables: identidad de fichero, realpath/symlink, MIME, tamaños, permisos/inodo, owner, fechas, detalles, alertas, hashes.
* Códigos:

  * `0` ok
  * `1` error

---

## Solución de Problemas

* **`re2` no disponible**: ignorable; `regex` ya cubre el endurecimiento. `pip install -e ".[hardened]"` lo omite si no hay wheel.
* **GeoIP ausente**: verás un aviso; los países aparecerán como “GeoIP no disponible”.
* **Windows & MIME**: usa `python-magic`; `file(1)` puede no estar.
* **Colores en CI**: `NO_COLOR=1`.

---

## Desarrollo

```bash
# Instalación editable con extras comunes
pip install -e ".[detect,images,hardened]"

# Tests (verboso)
pytest -vv

# Lint (opcional)
pip install ruff
ruff check .
```

**Estructura**

```
sabbat_tools/
  ├─ loganalyce.py
  └─ fileinspect.py
tests/
  ├─ conftest.py
  ├─ test_fileinspect.py
  └─ test_loganalyce.py
```

---

## Contribuir

Issues y PRs bienvenidos. Mantén:

* Seguro por defecto, tests robustos, UX clara.
* Nuevos comandos con tests y sección en el README.

---

## Licencia

MIT © Óscar Giménez Blasco

````
