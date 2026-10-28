import json
import os
import struct
import zipfile
from pathlib import Path

import pytest


def test_fileinspect_help(run_cli):
    res = run_cli("fileinspect", ["--help"])
    assert res.returncode == 0
    assert "Usage" in res.stdout or "Uso" in res.stdout
    assert "--json" in res.stdout


def test_fileinspect_basic(run_cli, sample_text):
    res = run_cli("fileinspect", [str(sample_text)])
    assert res.returncode == 0
    # Campos humanos básicos (ES/EN)
    assert "MIME" in res.stdout or "Tipo MIME" in res.stdout
    assert "Size" in res.stdout or "Tamaño" in res.stdout
    assert "Permissions" in res.stdout or "Permisos" in res.stdout


def test_fileinspect_json_and_secrets(run_cli, sample_text):
    res = run_cli("fileinspect", ["--json", "--lang", "en", str(sample_text)])
    assert res.returncode == 0
    data = json.loads(res.stdout)
    # Claves estables para pipelines
    for key in ("nombre", "tipo_mime", "tamaño_bytes", "entropia", "detalles_contextuales", "alertas_seguridad", "hashes"):
        assert key in data
    # Detecta patrones de secretos (al menos password)
    assert any("Password" in a or "Contraseña" in a for a in data["alertas_seguridad"])


def test_fileinspect_nohash_and_specific_hash(run_cli, sample_text):
    # Sin hashes
    res1 = run_cli("fileinspect", ["--json", "--no-hash", str(sample_text)])
    d1 = json.loads(res1.stdout)
    assert isinstance(d1["hashes"], dict) and len(d1["hashes"]) == 0

    # Solo sha1
    res2 = run_cli("fileinspect", ["--json", "--hash", "sha1", str(sample_text)])
    d2 = json.loads(res2.stdout)
    assert list(d2["hashes"].keys()) == ["sha1"]
    assert len(d2["hashes"]["sha1"]) >= 10


def test_fileinspect_symlink_nofollow(run_cli, tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("hello", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target.name)  # relative symlink
    except OSError as e:
        pytest.skip(f"Symlinks not permitted in this environment: {e}")
    res = run_cli("fileinspect", ["--json", "--nofollow", str(link)])
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["es_symlink"] is True
    # En nofollow no nos interesa realpath; se debe reportar destino_symlink
    assert data["destino_symlink"]


def test_fileinspect_extension_spoofing_and_pe_header(run_cli, tmp_path):
    # Crear un ejecutable PE sintético con sección UPX0 y extensión .jpg (spoofing)
    fake_pe = tmp_path / "photo.jpg"
    dos_hdr = bytearray(64)
    dos_hdr[:2] = b"MZ"
    struct.pack_into("<I", dos_hdr, 60, 64)  # e_lfanew = 64
    pe_hdr = struct.pack("<4sHHIIIHH", b"PE\x00\x00", 0x8664, 1, 1700000000, 0, 0, 0, 0x0002)
    sec_hdr = bytearray(40)
    sec_hdr[:4] = b"UPX0"
    fake_pe.write_bytes(bytes(dos_hdr) + pe_hdr + bytes(sec_hdr))

    res = run_cli("fileinspect", ["--json", "--lang", "en", "--fail-on-alert", str(fake_pe)])
    assert res.returncode == 2
    data = json.loads(res.stdout)
    alerts = " ".join(data["alertas_seguridad"])
    adv = " ".join(data["detalles_avanzados"])
    assert "mismatch" in alerts or "spoofing" in alerts.lower()
    assert "UPX0" in alerts
    assert "PE EXE (x86_64)" in adv


def test_fileinspect_double_extension_and_extended_secrets(run_cli, tmp_path):
    f = tmp_path / "invoice.pdf.exe"
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    db_uri = "postgresql://admin:SuperSecret123@db.internal:5432/prod"
    f.write_text(f"TOKEN={jwt}\nDB={db_uri}\n", encoding="utf-8")

    res = run_cli("fileinspect", ["--json", "--lang", "en", str(f)])
    assert res.returncode == 0
    data = json.loads(res.stdout)
    alerts = " ".join(data["alertas_seguridad"])
    assert "double extension" in alerts.lower()
    assert "JWT token" in alerts
    assert "Database connection URI" in alerts


def test_fileinspect_archive_zip_slip(run_cli, tmp_path):
    zpath = tmp_path / "evil.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("../../etc/cron.d/pwn", "* * * * * root id\n")
    res = run_cli("fileinspect", ["--json", "--lang", "en", "--archives", "deep", str(zpath)])
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert any("Zip Slip" in a for a in data["alertas_seguridad"])
    assert data["archive"]["type"] == "zip"


def test_fileinspect_pdf_active_tags(run_cli, tmp_path):
    pdf_file = tmp_path / "malicious.pdf"
    pdf_file.write_bytes(b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\n2 0 obj << /Type /Page >> endobj\n")
    res = run_cli("fileinspect", ["--json", "--lang", "en", str(pdf_file)])
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert any("PDF: 1 pages" in d for d in data["detalles_avanzados"])
    assert any("/JavaScript" in a and "/OpenAction" in a for a in data["alertas_seguridad"])


def test_fileinspect_jsonl_and_output(run_cli, tmp_path):
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "b.txt").write_text("world", encoding="utf-8")
    out_file = tmp_path / "out.jsonl"
    res = run_cli("fileinspect", ["-r", "--include-pattern", "*.txt", "--jsonl", "-o", str(out_file), str(tmp_path)])
    assert res.returncode == 0
    lines = out_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["tipo_mime"].startswith("text/")
