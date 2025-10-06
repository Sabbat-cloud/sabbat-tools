-----

# 🧰 sabbat-tools — CLI toolbox

**EN:** A collection of system and security command-line tools designed for automation and safety.  
**ES:** Una colección de utilidades de sistema y seguridad diseñadas para la automatización y la seguridad.

| ✅ Bilingüe (auto/en/es) | ✅ Seguro por defecto | ✅ Listo para producción | ✅ Pensado para automatización (JSON) |
| :--- | :--- | :--- | :--- |
| ✅ Bilingual (auto/en/es) | ✅ Safe-by-default | ✅ Production-ready | ✅ Designed for automation (JSON) |

-----

## 📑 Table of Contents / Índice

  * [🚀 Installation / Instalación](https://www.google.com/search?q=%23-installation--instalaci%C3%B3n)
  * [🧱 Requirements / Requisitos](https://www.google.com/search?q=%23-requirements--requisitos)
  * [🧭 Commands / Comandos](https://www.google.com/search?q=%23-commands--comandos)
      * [📊 sabbat-loganalyce — Advanced Log Analyzer](https://www.google.com/search?q=%23-sabbat-loganalyce--advanced-log-analyzer)
      * [🕵️ sabbat-fileinspect — File Inspector](https://www.google.com/search?q=%23-sabbat-fileinspect--file-inspector)
  * [✅ Best Practices / Buenas Prácticas](https://www.google.com/search?q=%23-best-practices--buenas-pr%C3%A1cticas)
  * [🧪 Quick Tests / Pruebas Rápidas](https://www.google.com/search?q=%23-quick-tests--pruebas-r%C3%A1pidas)
  * [🛠️ Contributing / Contribuir](https://www.google.com/search?q=%23%EF%B8%8F-contributing--contribuir)
  * [📜 License / Licencia](https://www.google.com/search?q=%23-license--licencia)

-----

## 🚀 Installation / Instalación

```bash
# EN: Clone the repository
# ES: Clona el repositorio
git clone https://github.com/Sabbat-cloud/sabbat-tools
cd sabbat-tools

# EN: Editable install (recommended for development)
# ES: Instalación editable (recomendada para desarrollo)
pip install -e .

# EN: Optional extras for extended functionality
# ES: Extras opcionales para funcionalidad extendida
pip install -e ".[geoip,images,detect,hardened]"
```

**EN:** After installation, the `sabbat-loganalyce` and `sabbat-fileinspect` commands will be available in your PATH.  
**ES:** Tras la instalación, los comandos `sabbat-loganalyce` y `sabbat-fileinspect` estarán disponibles en tu PATH.

-----

## 🧱 Requirements / Requisitos

  * **EN:** Python 3.8+.  
    **ES:** Python 3.8+.
  * **EN:** Optional dependencies for full functionality:
      * `geoip2`: For IP geolocation in `loganalyce`.
      * `Pillow`: For image analysis in `fileinspect`.
      * `python-magic` & `chardet`: For robust MIME type and encoding detection.
      * `regex`: For the hardened regular expression engine to mitigate ReDoS in `loganalyce`.
  * **ES:** Dependencias opcionales para una funcionalidad completa:
      * `geoip2`: Para geolocalización de IPs en `loganalyce`.
      * `Pillow`: Para el análisis de imágenes en `fileinspect`.
      * `python-magic` y `chardet`: Para una detección robusta de tipos MIME y codificación.
      * `regex`: Para el motor de expresiones regulares endurecido que mitiga ReDoS en `loganalyce`.

-----

## 🧭 Commands / Comandos

### 📊 sabbat-loganalyce — Advanced Log Analyzer

**EN:** A production-ready log analyzer that reads plain or `.gz` files, supports `stdin`, and outputs rich statistics and security signals in multiple formats.  
**ES:** Un analizador de logs listo para producción que lee ficheros estándar o `.gz`, soporta `stdin` y muestra estadísticas detalladas y alertas de seguridad en múltiples formatos.

#### ✨ Highlights / Características Destacadas

  * **EN:**
      * **Security-First**: Confines output to the current directory by default (`--unsafe-output` to override), sanitizes ANSI escape codes, and offers a hardened regex engine (`--hardened-regex`) to reduce ReDoS risk.
      * **High Performance**: Utilizes multithreading for statistics generation (`--threads`) and a bounded futures queue for stable memory usage, even with large files.
      * **Flexible Output**: Choose between a human-readable column view (default), a detailed list view (`--list-view`), or a comprehensive JSON format (`--json`) perfect for automation.
      * **Early Warning System**: A fast pre-scan warns you if a log file is very large before full analysis begins, using the `--large-threshold` parameter.
  * **ES:**
      * **Seguridad Primero**: Confinamiento de la salida al directorio actual por defecto (`--unsafe-output` para anular), sanitización de códigos de escape ANSI y un motor de regex endurecido (`--hardened-regex`) para mitigar riesgos de ReDoS.
      * **Alto Rendimiento**: Usa multihilo para generar estadísticas (`--threads`) y una cola de futuros acotada para un uso de memoria estable, incluso con ficheros grandes.
      * **Salida Flexible**: Elige entre una vista de columnas fácil de leer (por defecto), una vista de lista detallada (`--list-view`), o un formato JSON completo (`--json`) ideal para la automatización.
      * **Sistema de Alerta Temprana**: Un pre-escaneo rápido te avisa si un fichero de log es muy grande antes de comenzar el análisis completo, a través del parámetro `--large-threshold`.

#### 📦 Examples / Ejemplos

```bash
# EN: Full analysis with the default column view
# ES: Análisis completo con la vista de columnas por defecto
sabbat-loganalyce access.log

# EN: Analyze a log file using the list view
# ES: Analizar un fichero de log usando la vista de lista
sabbat-loganalyce access.log --list-view

# EN: Search for the first 50 lines matching a pattern (ordered, single-thread)
# ES: Buscar las primeras 50 líneas que coincidan con un patrón (ordenado, monohilo)
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50

# EN: Get detailed statistics in JSON format
# ES: Obtener estadísticas detalladas en formato JSON
sabbat-loganalyce app.log --json

# EN: Filter logs within a specific UTC time range
# ES: Filtrar logs en un rango de tiempo UTC específico
sabbat-loganalyce access.log --since "2024-01-01" --until "2024-01-31 23:59:59"

# EN: Analyze compressed logs from stdin
# ES: Analizar logs comprimidos desde stdin
zcat access.log.gz | sabbat-loganalyce - --json
```

#### ⚙️ Key Options / Opciones Clave

| Option / Opción | Description (EN) | Descripción (ES) |
|---|---|---|
| `file` or `-` | Log file to analyze, or `-` for stdin. | Fichero de log a analizar, o `-` para stdin. |
| `--lang {auto,en,es}` | Sets the interface language. | Establece el idioma de la interfaz. |
| `-p, --pattern REGEX` | Searches for a specific regex pattern. | Busca un patrón (regex) específico. |
| `--json` | Outputs results in JSON format. | Muestra la salida en formato JSON. |
| `--output PATH` | Saves the results to a file (safely). | Guarda los resultados en un fichero (de forma segura). |
| `--since/--until` | Filters logs by a UTC date/time range. | Filtra los logs por un rango de fecha/hora UTC. |
| `--threads N` | Number of worker threads for analysis. | Número de hilos de trabajo para el análisis. |
| `--hardened-regex` | Uses the hardened regex engine. | Utiliza el motor de regex endurecido. |

-----

### 🕵️ sabbat-fileinspect — File Inspector

**EN:** A security-focused and portable file inspector that provides detailed metadata, security alerts, and integrity checks.  
**ES:** Un inspector de ficheros portátil y centrado en la seguridad que proporciona metadatos detallados, alertas de seguridad y comprobaciones de integridad.

#### ✨ Features / Características

  * **EN:**
      * **Robust MIME Detection**: Uses a smart chain of detection: `python-magic` -\> `file(1)` command (with timeout) -\> `mimetypes` fallback.
      * **Advanced Secret Scanning**: Detects common patterns (passwords, API keys, private keys) and high-entropy Base64/Hex strings that might be secrets. Scan limits are configurable (`--max-secret-bytes`, `--max-secret-lines`).
      * **Configurable Hashes**: Computes file hashes using multiple algorithms (`--hash sha256,sha1,md5`). Hashing can be disabled with `--no-hash`.
      * **Context-Aware Details**: Provides specific metadata for images (via Pillow), executables (ELF/PE/Mach-O headers), and text files (encoding).
  * **ES:**
      * **Detección MIME Robusta**: Utiliza una cadena de detección inteligente: `python-magic` -\> comando `file(1)` (con timeout) -\> `mimetypes` como alternativa.
      * **Escaneo de Secretos Avanzado**: Detecta patrones comunes (contraseñas, claves de API, claves privadas) y cadenas Base64/Hex de alta entropía que podrían ser secretos. Los límites del escaneo son configurables (`--max-secret-bytes`, `--max-secret-lines`).
      * **Hashes Configurables**: Calcula hashes de ficheros usando múltiples algoritmos (`--hash sha256,sha1,md5`). El cálculo de hashes se puede desactivar con `--no-hash`.
      * **Detalles Contextuales**: Proporciona metadatos específicos para imágenes (a través de Pillow), ejecutables (cabeceras ELF/PE/Mach-O) y ficheros de texto (codificación).

#### 📦 Examples / Ejemplos

```bash
# EN: Basic inspection of a file
# ES: Inspección básica de un fichero
sabbat-fileinspect /etc/passwd

# EN: Inspect a file with Spanish output, UTC timestamps, and multiple hashes in JSON format
# ES: Inspeccionar un fichero con salida en español, fechas en UTC y múltiples hashes en formato JSON
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts

# EN: Inspect a symbolic link without following it and disable hashing
# ES: Inspeccionar un enlace simbólico sin seguirlo y desactivar el cálculo de hashes
sabbat-fileinspect --nofollow --no-hash /path/to/symlink

# EN: Set custom limits for the secret scanning engine
# ES: Establecer límites personalizados para el motor de escaneo de secretos
sabbat-fileinspect --max-secret-bytes 262144 --max-secret-lines 300 config.env
```

-----

## ✅ Best Practices / Buenas Prácticas

  * **EN:** For huge logs, use `--max-bytes` with `sabbat-loganalyce` to limit the amount of data processed and enable `--hardened-regex` for safer pattern matching.  
    **ES:** Para logs muy grandes, usa `--max-bytes` con `sabbat-loganalyce` para limitar la cantidad de datos procesados y activa `--hardened-regex` para un análisis de patrones más seguro.
  * **EN:** For accurate IP geolocation, install `geoip2` and download the free GeoLite2-Country database from MaxMind.  
    **ES:** Para una geolocalización de IPs precisa, instala `geoip2` y descarga la base de datos gratuita GeoLite2-Country de MaxMind.
  * **EN:** When automating, always use the `--json` flag for stable, machine-readable output.  
    **ES:** Al automatizar, utiliza siempre la bandera `--json` para obtener una salida estable y legible por máquina.

-----

## 🧪 Quick Tests / Pruebas Rápidas

**EN:** Run these commands to quickly test the core functionalities of the tools.  
**ES:** Ejecuta estos comandos para probar rápidamente las funcionalidades principales de las herramientas.

```bash
# Test sabbat-loganalyce with multithreading and safety limits
sabbat-loganalyce access.log \
  --threads 4 --hardened-regex \
  --max-line-chars 8192 --max-bytes 500000000 \
  --top-urls 10 --top-ips 25

# Test sabbat-fileinspect with JSON output and multi-hash
sabbat-fileinspect --utc \
  --hash sha256,sha1 \
  --json ./pyproject.toml
```

-----

## 🛠️ Contributing / Contribuir

**EN:** Issues and Pull Requests are welcome. Please maintain the project's style: safe-by-default, clear UX, and robust testing.  
**ES:** Los issues y Pull Requests son bienvenidos. Por favor, mantén el estilo del proyecto: seguro por defecto, una UX clara y pruebas robustas.

-----

## 📜 License / Licencia

MIT License.

Repo: [https://github.com/Sabbat-cloud/sabbat-tools](https://github.com/Sabbat-cloud/sabbat-tools)
