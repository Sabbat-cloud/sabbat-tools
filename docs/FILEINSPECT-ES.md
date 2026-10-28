```markdown
# sabbat-fileinspect — Inspector de Archivos (Manual Completo)

Inspector con foco en seguridad para texto/imágenes/binarios con salida JSON estable, análisis de contenido profundo y extensibilidad.

---
## Sinopsis
```bash
sabbat-fileinspect [OPCIONES] <ruta...>
````

## Opciones Principales

  - `--lang {auto,en,es}`: Idioma de la interfaz.
  - `--json`: Salida JSON (estable para automatización).
  - `--jsonl`: Salida JSON Lines (un objeto JSON por línea, ideal con `-r`).
  - `-o, --output <FICHERO>`: Guarda la salida JSON/JSONL o el informe HTML/PDF en la ruta indicada.
  - `--fail-on-alert` (`--strict`): Devuelve código de salida `2` si se detectan alertas de seguridad, coincidencias YARA o diferencias de hash.
  - `-r, --recursive`: Analiza directorios recursivamente.
  - `--hash ALGO,ALGO`: Hashes a calcular (ej. `sha256,sha1,md5`).
  - `--no-hash`: Desactiva el cálculo de hashes (más rápido).
  - `--nofollow`: No sigue enlaces simbólicos (symlinks).
  - `--utc`: Muestra fechas y horas en formato UTC (ISO 8601).
  - `--export {html,pdf}`: Exporta un informe en HTML o PDF.
  - `--compare <OTRO_ARCHIVO>`: Compara los hashes del archivo A con el B.

## Opciones Avanzadas (Seguridad y Análisis)

  - **Análisis Forense Integrado (Automático)**:
    - Identificación nativa por *magic bytes* (`ELF`, `PE`, `Mach-O`, `PDF`, `ZIP/OOXML`, imágenes, comprimidos y texto plano).
    - Detección de *spoofing* de extensión (discrepancia extensión/contenido) y dobles extensiones sospechosas (`factura.pdf.exe`).
    - Entropía de Shannon por fichero (`entropia`, `0.0–8.0` bits/byte) y alerta de binarios empaquetados/cifrados ($\ge 7.2$).
    - Inspección nativa de cabeceras **PE** (`x86`/`x86_64`/`ARM64`, `EXE`/`DLL`, fecha de compilación UTC, secciones `UPX`/empaquetadores) y **ELF**.
    - Escaneo de etiquetas activas peligrosas en PDF (`/JavaScript`, `/JS`, `/OpenAction`, `/Launch`, `/EmbeddedFiles`) y macros VBA en Office (`vbaProject.bin`).
  - `--malware-heuristics`: Activa heurísticas de malware para scripts (busca `eval`, `base64`, `subprocess`, *cradles* de PowerShell, *reverse shells* `/dev/tcp/`, `nc -e`, etc.).
  - `--yara-rules <RUTA_O_DIR>`: Escanea el archivo con reglas YARA.
  - `--vt-api-key <CLAVE>`: Comprueba el hash SHA256 con VirusTotal (o usa la variable `VT_API_KEY`).
  - `--archives {off,list,deep}`: Controla el análisis de archivos comprimidos (zip/tar), incluyendo detección de **Zip Slip** (*path traversal*) y **Zip Bombs**.
  - `--max-secret-bytes N`: Límite de bytes para el escaneo de secretos (default: 1MB). Detecta contraseñas, API keys, JWT, Slack, GCP, Stripe, claves AWS, URIs de bases de datos con credenciales y tarjetas (Luhn).
  - `--max-secret-lines N`: Límite de líneas para el escaneo de secretos (default: 800).
  - `--plugins-dir <DIR>`: Carga plugins personalizados desde un directorio.

## Opciones de Filtrado (Recursivo)

  - `--include-pattern "*.py,*.json"`: Incluye solo archivos que coincidan.
  - `--exclude-dir ".git,.venv"`: Excluye directorios (por defecto: `.git`, `.venv`, `node_modules`, `__pycache__`).
  - `--exclude-pattern "*.log,*.tmp"`: Excluye archivos que coincidan.
  - `--max-depth N`: Profundidad máxima de recursión.

-----

## Instalación

```bash
# Recomendado: instalar con extras para 'detect' (MIME) e 'images' (EXIF)
pip install -e ".[detect,images]"

# Para YARA (opcional)
pip install yara-python
# Para PDF/Office/Media (opcional)
pip install ".[full]"
```

-----

## Casos Prácticos y Ejemplos Detallados

### 1\. Análisis Básico (Humano y JSON)

Obtén metadatos, permisos y hashes de un archivo crítico.

```bash
# Vista legible para humanos
sabbat-fileinspect /etc/passwd
```

```
File:      /etc/passwd
MIME type: text/plain
Size:      2.35 KiB
----------------------------------------
Permissions: 0644 (rw-r--r--) (Inodo: 12345)
Owner:     root:root
Alertas de seguridad:
  - 🔍 Nombre potencialmente sensible
----------------------------------------
Modified:   2025-10-01 12:00:00
Accessed:   2025-10-07 09:30:00
Metadata changed:   2025-10-01 12:00:00
----------------------------------------
Integridad:
  SHA256: e3b0c44298fc1c149afbf4c8...
```

```bash
# Salida JSON para scripts (con hashes específicos)
sabbat-fileinspect --json --hash sha256,sha1 /etc/hosts
```

```json
{
  "lang": "es",
  "nombre": "/etc/hosts",
  "realpath": "/etc/hosts",
  "tipo_mime": "text/plain",
  "tamaño_bytes": 150,
  "permisos": "0644",
  "propietario": "root:root",
  "fecha_mod": "...",
  "fecha_acc": "...",
  "fecha_cre": "...",
  "inodo": 12346,
  "es_symlink": false,
  "destino_symlink": null,
  "detalles_contextuales": [
    "Encoding: ascii (100.0% conf.)",
    "8 líneas"
  ],
  "detalles_avanzados": [],
  "alertas_seguridad": [],
  "tamaño_formateado": "150 B",
  "hashes": {
    "sha256": "...",
    "sha1": "..."
  }
}
```

### 2\. Escaneo de Secretos (con Límites)

Busca claves, contraseñas y tokens en archivos de configuración o código fuente.

```bash
sabbat-fileinspect .env.production --max-secret-bytes 50000 --json
```

```json
{
  "nombre": ".env.production",
  "tipo_mime": "text/plain",
  ...
  "alertas_seguridad": [
    "🔍 Nombre potencialmente sensible",
    "🔑 Contraseña en texto claro",
    "🔑 Clave de API",
    "🔑 Cadena base64 de alta entropía (posible secreto)"
  ],
  ...
}
```

### 3\. Escaneo Recursivo de Código Fuente

Busca todos los archivos `.py` en un proyecto, excluyendo el entorno virtual, y busca secretos o heurísticas de malware.

```bash
sabbat-fileinspect -r . \
    --include-pattern "*.py,*.sh" \
    --exclude-dir ".venv,node_modules" \
    --malware-heuristics \
    --jsonl > scan_report.jsonl
```

*(Salida --jsonl: un objeto JSON por cada archivo encontrado)*

### 4\. Búsqueda con YARA

Escanea un directorio de descargas o `tmp` buscando coincidencias con tus reglas YARA.

```bash
# Escanea un directorio con un conjunto de reglas
sabbat-fileinspect -r /tmp \
    --yara-rules /opt/yara-rules/crypto_miners.yar \
    --json | jq '. | select(.yara_matches | length > 0)'
```

```json
{
  "nombre": "/tmp/xm.bin",
  ...
  "detalles_contextuales": [
    "Fichero ejecutable (ELF)"
  ],
  "yara_matches": [
    "CryptoMiner_XMRig"
  ],
  ...
}
```

### 5\. Análisis de Archivos Comprimidos (`--archives`)

Inspecciona el contenido de un archivo `.zip` o `.tar.gz` buscando archivos sospechosos en su interior.

```bash
sabbat-fileinspect backup.zip --archives deep --malware-heuristics --json
```

```json
{
  "nombre": "backup.zip",
  "tipo_mime": "application/zip",
  ...
  "archive": {
    "type": "zip",
    "entries": [
      { "name": "config.ini", "size": 120, "type": "file", "alerts": ["🔑 Clave de API"] },
      { "name": "run.sh", "size": 80, "type": "file", "alerts": ["malware heuristics"] },
      { "name": "data/", "size": 0, "type": "dir", "alerts": [] }
    ]
  },
  ...
}
```

### 6\. Comprobación de Dependencias

Analiza `requirements.txt` o `package.json` en busca de vulnerabilidades conocidas (usando `safety` o `npm audit` si están instalados).

```bash
sabbat-fileinspect /opt/mi-app/requirements.txt --json
```

```json
{
  "nombre": "/opt/mi-app/requirements.txt",
  ...
  "alertas_seguridad": [
    "⚠️ Vulnerabilidades detectadas en dependencias"
  ]
}
```

### 7\. Verificación con VirusTotal

Comprueba el hash de un archivo sospechoso contra la base de datos de VirusTotal.

```bash
# Puedes pasar la clave o definir VT_API_KEY en tu entorno
sabbat-fileinspect /tmp/download.exe --vt-api-key "TU_CLAVE_VT" --json
```

```json
{
  "nombre": "/tmp/download.exe",
  "tipo_mime": "application/vnd.microsoft.portable-executable",
  ...
  "detalles_contextuales": [
    "Fichero ejecutable (PE)"
  ],
  "detalles_avanzados": [
    "⚠️ VirusTotal: 42 maliciosos, 5 sospechosos (78 motores)"
  ],
  ...
}
```

### 8\. Comparación de Ficheros

Verifica la integridad de un archivo comparando sus hashes con una copia de seguridad conocida.

```bash
sabbat-fileinspect /usr/bin/sshd --compare /root/sshd_backup.bin
```

```
Comparación de hashes
 - SAME: SHA256 identical
```

### 9\. Exportación de Informes

Genera un informe HTML de un análisis recursivo.

```bash
sabbat-fileinspect -r /etc/ssh --export html --output ssh_config_report
```

```
Exported HTML: ssh_config_report.html
```

```
</details>
```
