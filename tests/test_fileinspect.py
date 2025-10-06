import json
import os
from pathlib import Path

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
    for key in ("nombre", "tipo_mime", "tamaño_bytes", "detalles_contextuales", "alertas_seguridad", "hashes"):
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
    link.symlink_to(target.name)  # relative symlink
    res = run_cli("fileinspect", ["--json", "--nofollow", str(link)])
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["es_symlink"] is True
    # En nofollow no nos interesa realpath; se debe reportar destino_symlink
    assert data["destino_symlink"]

