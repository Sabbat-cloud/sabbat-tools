---

# 🧰 sabbat-tools — CLI toolbox

**ES:** Colección de utilidades de sistema y seguridad.
**EN:** Collection of system & security command-line tools.

* ✅ **ES:** Bilingüe (auto/en/es) cuando aplica · **EN:** Bilingual (auto/en/es) where applicable
* ✅ **ES:** Seguro por defecto, listo para producción · **EN:** Safe-by-default, production-ready
* ✅ **ES:** Pensado para automatización (JSON limpio) · **EN:** Designed for automation (clean JSON modes)

---

## 📑 Índice / Table of Contents

* [🚀 Instalación / Installation](#-instalación--installation)
* [🧱 Requisitos / Requirements](#-requisitos--requirements)
* [🧭 Comandos / Commands](#-comandos--commands)

  * [📊 sabbat-loganalyce — Advanced Log Analyzer](#-sabbat-loganalyce--advanced-log-analyzer)
  * [🕵️ sabbat-fileinspect — File Inspector](#-sabbat-fileinspect--file-inspector)
* [✅ Buenas prácticas / Best Practices](#-buenas-prácticas--best-practices)
* [🧪 Pruebas rápidas / Quick Tests](#-pruebas-rápidas--quick-tests)
* [🛠️ Contribuir / Contributing](#️-contribuir--contributing)
* [📜 Licencia / License](#-licencia--license)

---

## 🚀 Instalación / Installation

```bash
git clone https://github.com/Sabbat-cloud/sabbat-tools
cd sabbat-tools

# ES: Instalación editable (desarrollo)
# EN: Editable install (development)
pip install -e .

# ES: Extras opcionales / EN: Optional extras
#  - geoip:      geoip2
#  - images:     Pillow
#  - detect:     chardet + python-magic (o python-magic-bin en Windows)
#  - hardened:   regex (ReDoS mitigation for loganalyce)
pip install -e ".[geoip,images,detect,hardened]"
```

**ES:** Tras instalar, tendrás los comandos **`sabbat-loganalyce`** y **`sabbat-fileinspect`** en tu **PATH**.
**EN:** After installing, the CLIs **`sabbat-loganalyce`** and **`sabbat-fileinspect`** will be on your **PATH**.

> **Nota/Note:** El proyecto **no** requiere `re2` para funcionar. Si decides usarlo, su disponibilidad depende de la plataforma/Python y no se incluye en `hardened`.

---

## 🧱 Requisitos / Requirements

* **ES:** Python ≥ 3.8
  **EN:** Python ≥ 3.8
* **ES:** Opcional (recomendado) → `regex`, `geoip2` + **GeoLite2-Country.mmdb**, `python-magic`/`python-magic-bin`, `Pillow`, `chardet`
  **EN:** Optional (recommended) → `regex`, `geoip2` + **GeoLite2-Country.mmdb**, `python-magic`/`python-magic-bin`, `Pillow`, `chardet`

---

## 🧭 Comandos / Commands

### 📊 sabbat-loganalyce — Advanced Log Analyzer

> **EN:** “Your logs have a story to tell. sabbat-loganalyce deciphers it for you.”
> **ES:** “Tus logs tienen una historia que contar. sabbat-loganalyce la descifra por ti.”

**ES:** Analizador de logs listo para producción. Lee ficheros estándar o `.gz`, soporta `stdin`, muestra estadísticas ricas, señales de seguridad y salida JSON.
**EN:** Production-ready log analyzer. Reads plain or `.gz`, supports `stdin`, outputs rich stats, security signals, and JSON.

#### 🌍 Idioma / Language

* **ES:** Auto: `--lang auto` (por defecto) · Forzar: `--lang {en|es}`
* **EN:** Auto-detect: `--lang auto` (default) · Force: `--lang {en|es}`

#### ✨ Destacados / Highlights

* **Seguridad / Security**

  * **ES:** Confinamiento de salida al CWD (`--output` restringido salvo `--unsafe-output`)
    **EN:** Output confinement to CWD (`--unsafe-output` to bypass)
  * **ES/EN:** Sanitización de ANSI / ANSI sanitization by default
  * **ES/EN:** ReDoS mitigation (bounded patterns; `--hardened-regex` uses `regex`)
* **Rendimiento / Performance**

  * **ES/EN:** Estadísticas multihilo (`--threads`, `--batch-size`)
  * **ES/EN:** Cola de *futures* acotada para memoria estable
* **UX**

  * **ES/EN:** Vista columnas (por defecto) o lista (`--list-view`)
  * **ES/EN:** Tops configurables (`--top-urls`, `--top-uas`, `--top-ips`)
  * **ES/EN:** JSON enriquecido con metadatos/metrics

> **ES:** La búsqueda por patrón (`-p/--pattern`) es **ordenada y monohilo** (primeras N coincidencias).
> **EN:** Pattern search (`-p/--pattern`) is **ordered & single-thread** (first N matches).

#### 📦 Ejemplos / Examples

```bash
# ES: Análisis completo (columnas) / EN: Full analysis (columns)
sabbat-loganalyce access.log

# ES/EN: List view
sabbat-loganalyce access.log --list-view

# ES: Búsqueda de patrón (primeras 50) / EN: Pattern search (first 50)
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50

# ES/EN: JSON output
sabbat-loganalyce app.log --json

# ES: Guardar JSON (confinado al CWD) / EN: Save JSON (confined to CWD)
sabbat-loganalyce app.log --json --output reports/result.json

# ES/EN: Time filter (UTC)
sabbat-loganalyce access.log --since 2024-01-01 --until "2024-01-31 23:59:59"

# ES/EN: stdin (pipeline)
zcat access.log.gz | sabbat-loganalyce - --json
```

#### ⚙️ Opciones / Options

* **ES/EN (Input)**: `file` o `-` (stdin)
* **ES/EN (Language)**: `--lang {auto,en,es}`
* **ES/EN (Patterns)**: `-p/--pattern`, `-c/--count`
* **ES/EN (Output)**: `--json`, `--output PATH`, `--force`, `--unsafe-output`, `--no-sanitize-ansi`
* **ES/EN (Views)**: `--list-view`
* **ES/EN (Time)**: `--since`, `--until` (UTC)
* **ES/EN (Tops/Cap)**: `--top-urls`, `--top-uas`, `--top-ips`, `--max-ips`, `--max-errors`
* **ES/EN (GeoIP)**: `--geoip-db PATH`
* **ES/EN (Perf & Safety)**: `--threads`, `--batch-size`, `--encoding`, `--max-line-chars`, `--max-bytes`, `--deny-stdin`, `--hardened-regex`

**ES:** Devuelve código de salida **2** si se detectan alertas de seguridad (útil en CI).
**EN:** Returns **exit code 2** when security alerts are detected (useful in CI).

---

### 🕵️ sabbat-fileinspect — File Inspector

**ES:** Inspector de ficheros con foco en **seguridad** y **portabilidad**.
**EN:** Security-focused, portable file inspector.

#### ✨ Características / Features

* **ES/EN:** i18n → `--lang {auto,en,es}`
* **ES/EN:** MIME robusto → `python-magic` → `file(1)` (timeout) → `mimetypes`
* **ES/EN:** Hashes → `--hash sha256,sha1,md5` (por defecto `sha256`) o `--no-hash`
* **ES/EN:** Secret scanning → patrones comunes + alta entropía (base64/hex), límites configurables
* **ES/EN:** Imágenes → `Pillow` opcional; `Image.verify()` + metadatos seguros
* **ES/EN:** Binarios → cabecera (ELF/PE/Mach-O) + `readelf` opcional
* **ES/EN:** Fechas → `--utc` (ISO 8601), respeta `NO_COLOR`
* **ES/EN:** JSON limpio y estable (ideal para pipelines)

#### 📦 Ejemplos / Examples

```bash
# ES: Inspección básica (auto idioma) / EN: Basic inspection (auto language)
sabbat-fileinspect /etc/passwd

# ES: Español + UTC + hashes múltiples + JSON / EN: Spanish + UTC + multi-hash + JSON
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts

# ES: Sin hashes, sin seguir symlinks / EN: No hashes, do not follow symlinks
sabbat-fileinspect --no-hash --nofollow /ruta/al/enlace

# ES/EN: Límites de escaneo de secretos / Secrets scan limits
sabbat-fileinspect --max-secret-bytes 262144 --max-secret-lines 300 app.env
```

#### ⚙️ Opciones / Options

* **ES/EN:** `--lang {auto,en,es}`, `--json`, `--nofollow`, `--utc`
* **ES/EN (Size)**: `-b/--bytes`, `-k/--kb`, `-m/--mb`, `-g/--gb`
* **ES/EN (Hashes)**: `--no-hash` o `--hash sha256,sha1,md5`
* **ES/EN (Secrets)**: `--max-secret-bytes N`, `--max-secret-lines N`

**Salida humana / Human output**

* **ES/EN:** File, Realpath, Symlink, MIME type, Formatted size, Permissions & inode, Owner, Dates
* **ES/EN:** Context details (text, image, binary), Security alerts, Integrity (hashes)

**Salida JSON / JSON output**

* **ES/EN:** Stable keys → great for automation.

---

## ✅ Buenas prácticas / Best Practices

* **ES (Logs enormes)**: `sabbat-loganalyce` → usa `--max-bytes` y límites por línea; activa `--hardened-regex` si instalas `regex`.
  **EN (Huge logs)**: `sabbat-loganalyce` → use `--max-bytes` and line limits; enable `--hardened-regex` if `regex` is installed.
* **ES (GeoIP)**: instala `geoip2` y configura **GeoLite2-Country.mmdb** (p. ej. `/var/lib/GeoIP/`).
  **EN (GeoIP)**: install `geoip2` and configure **GeoLite2-Country.mmdb** (e.g., `/var/lib/GeoIP/`).
* **ES (Secretos)**: ajusta `--max-secret-bytes/lines` para evitar procesar ficheros gigantes.
  **EN (Secrets)**: tune `--max-secret-bytes/lines` to avoid scanning huge files.
* **ES/EN (Colores/Colors)**: export `NO_COLOR=1` in CI.

---

## 🧪 Pruebas rápidas / Quick Tests

```bash
# sabbat-loganalyce — multihilo + endurecido + límites
sabbat-loganalyce access.log \
  --threads 8 --batch-size 5000 --hardened-regex \
  --max-line-chars 4096 --max-bytes 500000000 \
  --top-urls 10 --top-uas 10 --top-ips 50

# sabbat-fileinspect — JSON + secretos + hashes múltiples
sabbat-fileinspect --lang es --utc \
  --hash sha256,sha1 \
  --max-secret-bytes 262144 --max-secret-lines 400 \
  --json ./config/.env
```

---

## 🛠️ Contribuir / Contributing

**ES:** Issues y PRs bienvenidos. Mantén el estilo: *safe-by-default*, tests, UX clara. Añade nuevos comandos como secciones independientes en este README.
**EN:** Issues and PRs welcome. Keep the style: *safe-by-default*, tests, clear UX. Add new commands as separate sections in this README.

---

## 📜 Licencia / License

MIT

Repo: [https://github.com/Sabbat-cloud/sabbat-tools](https://github.com/Sabbat-cloud/sabbat-tools)

---

> **ES:** Si decides añadir un “pre-aviso” temprano de logs grandes (pre-scan) en `sabbat-loganalyce`, documenta la bandera que expongas (p. ej., `--large-threshold`). Mientras no exista en el código, no lo publiques para evitar confusiones.
> **EN:** If you add an early “large log” pre-scan in `sabbat-loganalyce`, document the flag you expose (e.g., `--large-threshold`). Until it exists in code, avoid publishing it to prevent confusion.

