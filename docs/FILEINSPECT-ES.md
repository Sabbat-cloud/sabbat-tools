# sabbat-fileinspect — Inspector de Ficheros (Manual Completo)

Inspector con foco en seguridad para texto/imágenes/binarios con salida JSON estable.

---
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
---

## Descripción
- Detecta **MIME/tipo**, **permisos**, **propietario**, **fechas**.
- Calcula **hashes** (SHA‑256 por defecto; SHA‑1/MD5 opcionales).
- **Escaneo de secretos** opcional (patrones + entropía) con límites seguros.
- Manejo de symlinks con `--nofollow`.

## Instalación
```bash
pip install -e ".[detect,images]"
sabbat-fileinspect -h
```

## Inicio rápido
```bash
sabbat-fileinspect /etc/passwd
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts
sabbat-fileinspect --no-hash --nofollow /ruta/a/enlace
```

## Casos prácticos
```bash
# Inventario + hashes
find ./release -maxdepth 1 -type f -print0 | xargs -0 sabbat-fileinspect --json > release.json

# Secretos con límites
sabbat-fileinspect .env --max-secret-bytes 262144 --max-secret-lines 400 --json

# Metadatos de imagen (si Pillow)
sabbat-fileinspect image.jpg --json
```

## JSON (resumen)
```jsonc
{"file":{"path":"..."},"stat":{"mode":"0644"},"hashes":{"sha256":"..."},"secrets":[]}
```

## Códigos de salida
0 ok · 1 error

## Consejos
- `--nofollow` para symlinks de confianza limitada.
- Ajusta `--max-secret-*` para ficheros grandes.
