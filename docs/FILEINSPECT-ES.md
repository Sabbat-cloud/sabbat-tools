# sabbat-fileinspect — Inspector de Ficheros

Inspector con foco en seguridad (JSON).

## Sinopsis
```
sabbat-fileinspect [OPCIONES] <ruta...>
```

## Opciones
- `--lang {auto,en,es}`
- Hashes: `--hash sha256,sha1,md5` o `--no-hash`
- Enlaces: `--nofollow`
- Secretos: `--max-secret-bytes`, `--max-secret-lines`
- Salida: `--json`, `--utc`

## Ejemplos
```bash
sabbat-fileinspect /etc/passwd
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts
sabbat-fileinspect --no-hash --nofollow /path/to/link
```

