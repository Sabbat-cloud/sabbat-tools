# sabbat-loganalyce — Analizador Avanzado de Logs (Manual Completo)

Analizador orientado a seguridad que lee logs planos o `.gz` (o stdin), extrae señales y genera
salidas humanas y JSON para automatización.

---
## Sinopsis
```
sabbat-loganalyce [OPCIONES] <fichero|->
```

Lee logs planos o `.gz` (o stdin), genera señales de seguridad y estadísticas, y soporta JSON.

## Opciones
- `--lang {auto,en,es}`
- `--list-view`
- `--json`
- `-p/--pattern REGEX` y `-c N`
- `--max-bytes`, `--max-line-chars`
- `--threads`, `--batch-size`, `--large-threshold`

## Ejemplos
```bash
sabbat-loganalyce access.log
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50
sabbat-loganalyce app.log --json
zcat access.log.gz | sabbat-loganalyce - --json
```
---

## Descripción
- **Entrada:** ficheros de texto o `-` (stdin). `.gz` soportado vía stdin (`zcat file.gz | sabbat-loganalyce -`).
- **Foco:** señales de seguridad (SQLi/XSS/auth), estadísticas rápidas (URLs, IPs, códigos), y JSON para CI.
- **Diseño:** seguro por defecto, límites acotados, rutas regex resistentes a ReDoS (activa con `--hardened-regex`).

## Instalación
```bash
pip install -e ".[detect,hardened]"
sabbat-loganalyce -h
```

## Inicio rápido
```bash
sabbat-loganalyce access.log
sabbat-loganalyce app.log --json > reports/app.json
zcat access.log.gz | sabbat-loganalyce - --json | jq '.summary'
```

## Opciones clave
- Idioma: `--lang {auto,en,es}`
- Vista lista: `--list-view`
- JSON: `--json` / JSONL: `--jsonl`
- Búsqueda ordenada: `-p/--pattern REGEX` (+ `-c N`)
- Tiempo (UTC): `--since`, `--until`
- Rendimiento/límites: `--threads`, `--batch-size`, `--large-threshold`, `--max-bytes`, `--max-line-chars`
- Endurecer regex: `--hardened-regex` (requiere `regex`)

## Ejemplos prácticos (de básico a avanzado)

### 1) Lectura rápida
```bash
sabbat-loganalyce access.log
```

### 2) Ventana temporal
```bash
sabbat-loganalyce access.log --since "2025-10-06" --until "2025-10-07 23:59:59"
```

### 3) Caza de errores ordenada
```bash
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50
```

### 4) Ficheros enormes
```bash
sabbat-loganalyce big.log --large-threshold 2000000 --max-bytes 200MB
```

### 5) Señales de seguridad → CI
```bash
sabbat-loganalyce access.log --json | jq '[.security_alerts[] | select(.type=="sqli" or .type=="xss")] | length' \
  | awk '{ exit ($1>0?2:0) }'
```

## JSON (resumen)
```jsonc
{
  "schema_version": "1.x",
  "summary": {"file":"access.log","total_lines":12345},
  "security_alerts": [{"type":"auth_fail","count":42}],
  "top_urls": [{"path":"/api","count":100}]
}
```

## Códigos de salida
- `0` ok
- `1` error de uso/ejecución
- `2` alertas de seguridad detectadas

## Consejos
- Usa `--large-threshold` / `--max-bytes` en logs muy grandes.
- Instala `regex` y `--hardened-regex` para evitar backtracking catastrófico.
- `NO_COLOR=1` en CI para salidas limpias.
