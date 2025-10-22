#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
limpiatexto_cli v1.5 — Extrae texto "crudo" de documentos (.docx, .odt, .ods y .txt),
incluyendo tablas, y lo guarda SIN formato en .txt con guardado robusto para Windows.

- Si se ejecuta sin argumentos, pregunta la ruta del archivo a convertir.
- Si se pasan rutas como argumentos, las procesa automáticamente.
- Para .doc (antiguo) muestra aviso de no soportado.

Dependencias:
    pip install python-docx odfpy
"""

from __future__ import annotations
import sys
import os
import re
import glob
import tempfile
from pathlib import Path
from typing import Optional, List

# --- Información del programa ---
__program_name__ = "limpiatexto"
__version__ = "1.5"
__date__ = "2025-10-22"
__author__ = "Oscar Gimenez Blasco"

# --- Dependencias para formatos ---
try:
    import docx
    from docx.text.paragraph import Paragraph as DocxParagraph
    from docx.table import Table as DocxTable
    from docx.oxml.text.paragraph import CT_P as DOCX_CT_P
    from docx.oxml.table import CT_Tbl as DOCX_CT_TBL
except Exception:
    print("ERROR: Falta 'python-docx'. Instala con: pip install python-docx", file=sys.stderr)
    # No abortamos aún: solo fallará si se intenta abrir .docx
    docx = None  # type: ignore
    DOCX_CT_P = DOCX_CT_TBL = DocxParagraph = DocxTable = None  # type: ignore

try:
    from odf.opendocument import load as odf_load
    from odf.text import P as ODF_P
    from odf.teletype import extractText as odf_extract_text
    from odf.table import (
        Table as ODF_Table,
        TableRow as ODF_TableRow,
        TableCell as ODF_TableCell,
        CoveredTableCell as ODF_CoveredTableCell,
    )
except Exception:
    print("ERROR: Falta 'odfpy'. Instala con: pip install odfpy", file=sys.stderr)
    # Igual que arriba: solo fallará si se intenta abrir .odt/.ods
    odf_load = ODF_P = odf_extract_text = None  # type: ignore
    ODF_Table = ODF_TableRow = ODF_TableCell = ODF_CoveredTableCell = None  # type: ignore


# ==============================
#   Utilidades de limpieza
# ==============================

def limpiar_texto_crudo(texto_sucio: str) -> str:
    """
    Normaliza el texto: sustituye tabs/nbsp por espacios, colapsa espacios,
    recorta líneas y descarta vacías.
    """
    texto = texto_sucio.replace("\t", " ").replace("\xa0", " ")
    lineas = texto.splitlines()
    lineas_limpias: List[str] = []
    for linea in lineas:
        s = re.sub(r" +", " ", linea.strip())
        if s:
            lineas_limpias.append(s)
    return "\n".join(lineas_limpias)


# ==============================
#   Lectura de .docx (incluye tablas)
# ==============================

def _docx_iter_block_items(document_or_cell):
    """Itera párrafos y tablas manteniendo orden (documento o celdas)."""
    if document_or_cell is None:
        return
    if hasattr(document_or_cell, "element") and hasattr(document_or_cell.element, "body"):
        parent_elm = document_or_cell.element.body
        parent = document_or_cell
    elif hasattr(document_or_cell, "_tc"):
        parent_elm = document_or_cell._tc
        parent = document_or_cell
    else:
        return
    for child in parent_elm.iterchildren():
        if isinstance(child, DOCX_CT_P):
            yield DocxParagraph(child, parent)
        elif isinstance(child, DOCX_CT_TBL):
            yield DocxTable(child, parent)

def _docx_table_to_lines(tbl: DocxTable) -> list[str]:
    lines: List[str] = []
    for row in tbl.rows:
        cells_text: List[str] = []
        for cell in row.cells:
            cell_lines: List[str] = []
            for block in _docx_iter_block_items(cell):
                if isinstance(block, DocxParagraph):
                    txt = (block.text or "").strip()
                    if txt:
                        cell_lines.append(txt)
                elif isinstance(block, DocxTable):
                    nested = _docx_table_to_lines(block)
                    if nested:
                        cell_lines.append(" ".join(nested))
            joined = " ".join(cell_lines).strip()
            if joined:
                cells_text.append(joined)
        if cells_text:
            lines.append(" ".join(cells_text))
    return lines

def leer_docx(ruta_archivo: str) -> str:
    if docx is None:
        raise RuntimeError("python-docx no está instalado.")
    d = docx.Document(ruta_archivo)
    out_lines: List[str] = []
    for block in _docx_iter_block_items(d):
        if isinstance(block, DocxParagraph):
            txt = (block.text or "").strip()
            if txt:
                out_lines.append(txt)
        elif isinstance(block, DocxTable):
            out_lines.extend(_docx_table_to_lines(block))
    return "\n".join(out_lines)


# ==============================
#   Lectura de .odt
# ==============================

def leer_odt(ruta_archivo: str) -> str:
    if odf_load is None:
        raise RuntimeError("odfpy no está instalado.")
    doc = odf_load(ruta_archivo)
    parrafos = doc.getElementsByType(ODF_P)
    lines: List[str] = []
    for p in parrafos:
        txt = (odf_extract_text(p) or "").strip()
        if txt:
            lines.append(txt)
    return "\n".join(lines)


# ==============================
#   Lectura de .ods (Calc)
# ==============================

def leer_ods(ruta_archivo: str) -> str:
    """
    Extrae texto por filas: cada fila -> línea; celdas unidas por espacio.
    """
    if odf_load is None:
        raise RuntimeError("odfpy no está instalado.")
    doc = odf_load(ruta_archivo)
    lines: List[str] = []
    for table in doc.getElementsByType(ODF_Table):
        for row in table.getElementsByType(ODF_TableRow):
            cell_texts: List[str] = []
            for cell in row.childNodes:
                if not isinstance(cell, (ODF_TableCell, ODF_CoveredTableCell)):
                    continue
                ps = getattr(cell, "getElementsByType", lambda *_: [])(ODF_P)
                pieces = []
                for p in ps:
                    t = (odf_extract_text(p) or "").strip()
                    if t:
                        pieces.append(t)
                if pieces:
                    cell_texts.append(" ".join(pieces))
            if cell_texts:
                lines.append(" ".join(cell_texts))
    return "\n".join(lines)


# ==============================
#   Multiplexor de lectura
# ==============================

def leer_archivo(ruta_archivo: str) -> Optional[str]:
    _, extension = os.path.splitext(ruta_archivo)
    ext = extension.lower()
    try:
        if ext == ".txt":
            try:
                with open(ruta_archivo, "r", encoding="utf-8") as f:
                    return f.read()
            except UnicodeDecodeError:
                with open(ruta_archivo, "r", encoding="latin-1") as f:
                    return f.read()
        elif ext == ".docx":
            return leer_docx(ruta_archivo)
        elif ext == ".odt":
            return leer_odt(ruta_archivo)
        elif ext == ".ods":
            return leer_ods(ruta_archivo)
        elif ext == ".doc":
            return "formato_doc_no_soportado"
        else:
            return None
    except Exception as e:
        return f"error_lectura:{e!r}"


# ==============================
#   Guardado robusto (Windows-friendly)
# ==============================

_ILLEGAL_WIN_CHARS = r'<>:"/\\|?*'

def sanitize_filename(name: str) -> str:
    trans = {ord(c): "_" for c in _ILLEGAL_WIN_CHARS}
    name = name.translate(trans)
    name = re.sub(r"\s+", " ", name).strip()
    name = re.sub(r"[ \.]+$", "", name)
    reserved = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)", re.IGNORECASE)
    if reserved.match(name):
        name = "_" + name
    if len(name) > 240:
        name = re.sub(r"[ \.]+$", "", name[:240])
    return name

def _dir_is_writable(path_dir: Path) -> bool:
    try:
        path_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=str(path_dir), delete=True) as _:
            pass
        return True
    except Exception:
        return False

def _default_fallback_dir() -> Path:
    home = Path.home()
    for d in [home / "Documents", home / "Documentos", Path(tempfile.gettempdir())]:
        if _dir_is_writable(d):
            return d
    return Path.cwd()

def build_output_path(input_path: Path, base_output_name: str) -> Path:
    """
    Intenta guardar junto al archivo original; si no, usa fallback.
    Añade sufijo -1, -2... cuando existe o hay bloqueo.
    """
    safe_base = sanitize_filename(base_output_name)
    candidate_dirs = [input_path.parent]
    if not _dir_is_writable(input_path.parent):
        candidate_dirs = [_default_fallback_dir()]

    for out_dir in candidate_dirs:
        n = 0
        while True:
            suffix = f"-{n}" if n else ""
            out_path = out_dir / f"{safe_base}{suffix}.txt"
            try:
                # Reserva el archivo para evitar carreras/bloqueos
                with open(out_path, "x", encoding="utf-8") as f:
                    f.write("")
                return out_path
            except FileExistsError:
                n += 1
                continue
            except PermissionError:
                if out_dir == input_path.parent:
                    alt = _default_fallback_dir()
                    if alt != out_dir:
                        candidate_dirs = [alt]
                        break
                n += 1
                continue
            except OSError:
                n += 1
                continue
    # Último recurso
    return Path(tempfile.gettempdir()) / f"{safe_base}.txt"


# ==============================
#   Procesamiento CLI
# ==============================

def procesar_archivo_cli(path_str: str) -> bool:
    in_path = Path(path_str).expanduser()
    if not in_path.exists():
        print(f"❌ ERROR: No existe: {path_str}", file=sys.stderr)
        return False

    print(f"📄 Procesando: {in_path.name}")
    contenido_original = leer_archivo(str(in_path))

    if contenido_original == "formato_doc_no_soportado":
        print("   ⚠️  Formato .doc (antiguo) no soportado. Usa .docx.", file=sys.stderr)
        return False
    if contenido_original is None:
        print("   ❌ Formato no reconocido (.docx/.odt/.ods/.txt).", file=sys.stderr)
        return False
    if isinstance(contenido_original, str) and contenido_original.startswith("error_lectura:"):
        print(f"   ❌ Error al leer: {contenido_original}", file=sys.stderr)
        return False

    contenido_limpio = limpiar_texto_crudo(contenido_original)
    base_nombre = f"sin formato-{in_path.stem}"
    out_path = build_output_path(in_path, base_nombre)

    try:
        with open(out_path, "w", encoding="utf-8") as f_out:
            f_out.write(contenido_limpio)
        print(f"   ✅ Guardado: {out_path}")
        return True
    except PermissionError:
        # Intento final en fallback
        fallback_dir = _default_fallback_dir()
        dummy_in = fallback_dir / "dummy.txt"
        out_path2 = build_output_path(dummy_in, base_nombre)
        try:
            with open(out_path2, "w", encoding="utf-8") as f_out:
                f_out.write(contenido_limpio)
            print("   ⚠️  Sin permisos en la carpeta original. Guardado en fallback:")
            print(f"      {out_path2}")
            return True
        except Exception as e2:
            print(f"   ❌ Error de permisos incluso en fallback: {e2!r}", file=sys.stderr)
            return False
    except Exception as e:
        print(f"   ❌ Error inesperado al guardar: {e!r}", file=sys.stderr)
        return False


def _expand_globs(paths: List[str]) -> List[str]:
    """En Windows CMD los * no se expanden: lo hacemos aquí."""
    out: List[str] = []
    for p in paths:
        matches = glob.glob(p)
        out.extend(matches if matches else [p])
    return out


def main(argv: List[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv
    args = argv[1:]

    # Ayuda mínima sin argparse
    if args and args[0] in ("-h", "--help"):
        print(
            "Uso: sabbat-rawtext [ficheros...]\n"
            " - Sin argumentos: pregunta la ruta por consola.\n"
            " - Acepta .docx/.odt/.ods/.txt (avisa si .doc antiguo).\n"
            " - Soporta comodines (globs); en Windows se expanden internamente.\n"
        )
        return 0

    if not args:
        try:
            path = input("Ruta del archivo a convertir (.docx/.odt/.ods/.txt): ").strip('"').strip()
        except EOFError:
            return 1
        if not path:
            print("Nada que hacer.", file=sys.stderr)
            return 1
        targets = [path]
    else:
        targets = _expand_globs(args)

    ok = True
    for target in targets:
        ok &= procesar_archivo_cli(target)

    print("\n🎉 Proceso terminado.")
    return 0 if ok else 1


def cli_main() -> int:
    """Wrapper de compatibilidad para entry points antiguos."""
    return main()


if __name__ == "__main__":
    raise SystemExit(main())
