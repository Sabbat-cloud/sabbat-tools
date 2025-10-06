# tests/conftest.py
import os
import sys
import subprocess
import textwrap
import pytest

@pytest.fixture(autouse=True)
def _stable_env(monkeypatch):
    # Salida sin colores y locale estable para asserts
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("LANG", "C")
    monkeypatch.setenv("LC_ALL", "C")
    yield

@pytest.fixture
def run_cli():
    """
    Ejecuta `python -m sabbat_tools.<module> ...` y devuelve CompletedProcess.
    Uso:
        res = run_cli("fileinspect", ["--help"])
    """
    def _run(module: str, args: list[str], stdin: str | None = None, timeout: int = 20):
        cmd = [sys.executable, "-m", f"sabbat_tools.{module}", *args]
        return subprocess.run(
            cmd,
            input=stdin,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    return _run

@pytest.fixture
def sample_log(tmp_path):
    p = tmp_path / "access.log"
    content = textwrap.dedent(
        r"""
        2025-10-03T00:23:06Z "GET /index.html HTTP/1.1" 200 "-" "Mozilla/5.0"
        2025-10-03T00:23:07Z "GET /../../etc/passwd HTTP/1.1" 404 "-" "curl/8.6.0"
        2025-10-03T00:23:08Z "POST /search?q=1'+UNION+SELECT+1,2 HTTP/1.1" 500 "-" "Mozilla/5.0"
        2025-10-03T00:23:09Z "GET /app.js HTTP/1.1" 200 "-" "Mozilla/5.0"
        """
    ).strip() + "\n"
    p.write_text(content, encoding="utf-8")
    return p

@pytest.fixture
def sample_text(tmp_path):
    p = tmp_path / "secrets.env"
    p.write_text(
        "USER=demo\npassword = \"s3cr3t\"\nAPI_KEY = 'abcdEFGH1234'\n",
        encoding="utf-8",
    )
    return p

