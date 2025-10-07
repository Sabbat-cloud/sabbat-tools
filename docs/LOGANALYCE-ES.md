# sabbat-loganalyce — Analizador Avanzado de Logs

Manual breve con ejemplos.

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

## JSON (resumen)
```jsonc
{"schema_version":"...","summary":{"total_lines":12345}}
```

## Códigos de salida
0 ok · 1 error · 2 alertas de seguridad
