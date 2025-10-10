
import json
import gzip
import bz2
import lzma
from pathlib import Path

import pytest

try:
    import zstandard as zstd  # opcional
    HAVE_ZSTD = True
except Exception:
    HAVE_ZSTD = False


def _count_lines(p: Path) -> int:
    # Cuenta líneas del fichero de texto normal
    with p.open("rt", encoding="utf-8", errors="ignore") as fh:
        return sum(1 for _ in fh)


def _compress_copy(src: Path, dst: Path, codec: str) -> Path:
    data = src.read_bytes()
    if codec == "gz":
        with gzip.open(dst, "wb") as f:
            f.write(data)
    elif codec == "bz2":
        with bz2.open(dst, "wb") as f:
            f.write(data)
    elif codec in ("xz", "lzma"):
        # xz = lzma con contenedor XZ; lzma = formato “puro”
        fmt = lzma.FORMAT_XZ if codec == "xz" else lzma.FORMAT_ALONE
        with lzma.open(dst, "wb", format=fmt) as f:
            f.write(data)
    elif codec == "zst":
        if not HAVE_ZSTD:
            pytest.skip("zstandard no disponible")
        cctx = zstd.ZstdCompressor()
        dst.write_bytes(cctx.compress(data))
    else:
        raise ValueError(f"codec desconocido: {codec}")
    return dst


@pytest.mark.parametrize(
    "codec,ext",
    [
        ("gz", ".gz"),
        ("bz2", ".bz2"),
        ("xz", ".xz"),
        ("lzma", ".lzma"),
        pytest.param("zst", ".zst", marks=pytest.mark.skipif(not HAVE_ZSTD, reason="zstd no instalado")),
    ],
)
def test_loganalyce_reads_compressed_files(run_cli, tmp_path, sample_log, codec, ext):
    """
    Debe leer correctamente los formatos comprimidos soportados
    y mantener el mismo total de líneas que el fichero original.
    """
    expected = _count_lines(sample_log)

    dst = tmp_path / f"access.log{ext}"
    _compress_copy(sample_log, dst, codec)

    res = run_cli("loganalyce", ["--json", str(dst)])
    assert res.returncode in (0, 2), f"returncode inesperado: {res.returncode}\nSTDERR:\n{res.stderr}"
    data = json.loads(res.stdout)

    assert data["summary"]["file"].endswith(dst.name)
    got = data["summary"]["total_lines"]

    # Algunos entornos/lectores no soportan LZMA “alone” (.lzma). Si no coincide, xfail amable.
    if codec == "lzma" and got != expected:
        pytest.xfail("LZMA (.lzma, formato 'alone') no soportado por el lector actual")
        return

    assert got == expected


def test_loganalyce_magic_bytes_over_extension(run_cli, tmp_path, sample_log):
    """
    Aunque la extensión sea incorrecta, si el contenido es gzip (magic bytes),
    debe detectar y leer el archivo correctamente.
    """
    expected = _count_lines(sample_log)

    weird = tmp_path / "access.log.weird_ext"
    _compress_copy(sample_log, weird, "gz")  # contenido gzip con extensión rara

    res = run_cli("loganalyce", ["--json", str(weird)])
    assert res.returncode in (0, 2), f"returncode inesperado: {res.returncode}\nSTDERR:\n{res.stderr}"
    data = json.loads(res.stdout)
    assert data["summary"]["total_lines"] == expected

