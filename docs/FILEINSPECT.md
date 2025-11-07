````markdown
# sabbat-fileinspect — File Inspector (Full Manual)

Security-focused inspector for text/images/binaries with stable JSON output, deep content analysis, and extensibility.

---
## Synopsis
```bash
sabbat-fileinspect [OPTIONS] <path...>
````

## Main Options

  - `--lang {auto,en,es}`: Interface language.
  - `--json`: JSON output (stable for automation).
  - `-r, --recursive`: Recursively analyzes directories.
  - `--hash ALGO,ALGO`: Hashes to compute (e.g., `sha256,sha1,md5`).
  - `--no-hash`: Disables hash calculation (faster).
  - `--nofollow`: Does not follow symbolic links (symlinks).
  - `--utc`: Displays dates and times in UTC format (ISO 8601).
  - `--export {html,pdf}`: Exports a report in HTML or PDF.
  - `--compare <OTHER_FILE>`: Compares the hashes of file A with file B.

## Advanced Options (Security and Analysis)

  - `--malware-heuristics`: Activates malware heuristics for scripts (searches for `eval`, `base64`, `subprocess`, etc.).
  - `--yara-rules <PATH_OR_DIR>`: Scans the file with YARA rules.
  - `--vt-api-key <KEY>`: Checks the SHA256 hash with VirusTotal (or uses the `VT_API_KEY` variable).
  - `--archives {off,list,deep}`: Controls the analysis of compressed files (zip/tar).
  - `--max-secret-bytes N`: Byte limit for secret scanning (default: 1MB).
  - `--max-secret-lines N`: Line limit for secret scanning (default: 800).
  - `--plugins-dir <DIR>`: Loads custom plugins from a directory.

## Filtering Options (Recursive)

  - `--include-pattern "*.py,*.json"`: Includes only matching files.
  - `--exclude-dir ".git,.venv"`: Excludes directories (default: `.git`, `.venv`, `node_modules`, `__pycache__`).
  - `--exclude-pattern "*.log,*.tmp"`: Excludes matching files.
  - `--max-depth N`: Maximum recursion depth.

-----

## Installation

```bash
# Recommended: install with extras for 'detect' (MIME) and 'images' (EXIF)
pip install -e ".[detect,images]"

# For YARA (optional)
pip install yara-python
# For PDF/Office/Media (optional)
pip install ".[full]"
```

-----

## Practical Use Cases and Detailed Examples

### 1\. Basic Analysis (Human and JSON)

Get metadata, permissions, and hashes for a critical file.

```bash
# Human-readable view
sabbat-fileinspect /etc/passwd
```

```
File: /etc/passwd
MIME type: text/plain
Size: 2.35 KiB
----------------------------------------
Permissions: 0644 (rw-r--r--) (Inode: 12345)
Owner: root:root
Security Alerts:
- 🔍 Potentially sensitive name
----------------------------------------
Modified: 2025-10-01 12:00:00
Accessed: 2025-10-07 09:30:00
Metadata changed: 2025-10-01 12:00:00
----------------------------------------
Integrity:
SHA256: e3b0c44298fc1c149afbf4c8...
```

```bash
# JSON output for scripts (with specific hashes)
sabbat-fileinspect --json --hash sha256,sha1 /etc/hosts
```

```json
{
  "lang": "en",
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
    "8 lines"
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

### 2\. Secret Scanning (with Limits)

Search for keys, passwords, and tokens in configuration files or source code.

```bash
sabbat-fileinspect .env.production --max-secret-bytes 50000 --json
```

```json
{
  "nombre": ".env.production",
  "tipo_mime": "text/plain",
  ...
  "alertas_seguridad": [
    "🔍 Potentially sensitive name",
    "🔑 Password in plaintext",
    "🔑 API key",
    "🔑 High-entropy base64 string (possible secret)"
  ],
  ...
}
```

### 3\. Recursive Source Code Scanning

Find all `.py` files in a project, excluding the virtual environment, and scan for secrets or malware heuristics.

```bash
sabbat-fileinspect -r . \
    --include-pattern "*.py,*.sh" \
    --exclude-dir ".venv,node_modules" \
    --malware-heuristics \
    --jsonl > scan_report.jsonl
```

*(--jsonl output: one JSON object for each file found)*

### 4\. YARA Scanning

Scan a downloads or `/tmp` directory for matches against your YARA rules.

```bash
# Scan a directory with a ruleset
sabbat-fileinspect -r /tmp \
    --yara-rules /opt/yara-rules/crypto_miners.yar \
    --json | jq '. | select(.yara_matches | length > 0)'
```

```json
{
  "nombre": "/tmp/xm.bin",
  ...
  "detalles_contextuales": [
    "Executable file (ELF)"
  ],
  "yara_matches": [
    "CryptoMiner_XMRig"
  ],
  ...
}
```

### 5\. Compressed File Analysis (`--archives`)

Inspect the contents of a `.zip` or `.tar.gz` file, looking for suspicious files inside.

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
      { "name": "config.ini", "size": 120, "type": "file", "alerts": ["🔑 API key"] },
      { "name": "run.sh", "size": 80, "type": "file", "alerts": ["malware heuristics"] },
      { "name": "data/", "size": 0, "type": "dir", "alerts": [] }
    ]
  },
  ...
}
```

### 6\. Dependency Checking

Analyzes `requirements.txt` or `package.json` for known vulnerabilities (using `safety` or `npm audit` if installed).

```bash
sabbat-fileinspect /opt/my-app/requirements.txt --json
```

```json
{
  "nombre": "/opt/my-app/requirements.txt",
  ...
  "alertas_seguridad": [
    "⚠️ Vulnerabilities detected in dependencies"
  ]
}
```

### 7\. VirusTotal Verification

Check a suspicious file's hash against the VirusTotal database.

```bash
# You can pass the key or define VT_API_KEY in your environment
sabbat-fileinspect /tmp/download.exe --vt-api-key "YOUR_VT_KEY" --json
```

```json
{
  "nombre": "/tmp/download.exe",
  "tipo_mime": "application/vnd.microsoft.portable-executable",
  ...
  "detalles_contextuales": [
    "Executable file (PE)"
  ],
  "detalles_avanzados": [
    "⚠️ VirusTotal: 42 malicious, 5 suspicious (78 engines)"
  ],
  ...
}
```

### 8\. File Comparison

Verify a file's integrity by comparing its hashes against a known good backup.

```bash
sabbat-fileinspect /usr/bin/sshd --compare /root/sshd_backup.bin
```

```
Hash comparison
 - SAME: SHA256 identical
```

### 9\. Report Exporting

Generate an HTML report of a recursive scan.

```bash
sabbat-fileinspect -r /etc/ssh --export html --output ssh_config_report
```

```
Exported HTML: ssh_config_report.html
```

```
```
