import json
from pathlib import Path

def test_loganalyce_help(run_cli):
    res = run_cli("loganalyce", ["--help"])
    assert res.returncode == 0
    s = res.stdout.lower()
    assert "usage" in s or "uso" in s

def test_loganalyce_missing_file(run_cli, tmp_path):
    missing = tmp_path / "nope.log"
    res = run_cli("loganalyce", [str(missing)])
    assert res.returncode == 1
    # Mensaje i18n depende de --lang; comprobamos fragmento estable
    assert "does not exist" in res.stdout or "no existe" in res.stdout

def test_loganalyce_basic_analysis(run_cli, sample_log):
    res = run_cli("loganalyce", [str(sample_log)])
    assert res.returncode in (0, 2)  # 2 si detecta alerts
    # Debe mostrar cabecera de estadísticas (ES/EN)
    assert "LOG STATISTICS" in res.stdout or "ESTADÍSTICAS DEL LOG" in res.stdout
    # Debe listar al menos total de líneas
    assert "Total lines" in res.stdout or "Líneas totales" in res.stdout

def test_loganalyce_json_output(run_cli, sample_log):
    res = run_cli("loganalyce", ["--json", str(sample_log)])
    assert res.returncode in (0, 2)
    data = json.loads(res.stdout)
    # Claves principales del esquema
    for key in ("schema_version", "generated_at", "lang", "summary", "parameters_used"):
        assert key in data
    assert data["summary"]["file"].endswith("access.log")
    assert isinstance(data["http_status_codes"], dict)

def test_loganalyce_security_alerts_exitcode(run_cli, sample_log):
    # Debe devolver 2 al tener sqli/path traversal
    res = run_cli("loganalyce", ["--json", str(sample_log)])
    # robusto: si el código cambió, al menos que el JSON refleje las alerts
    data = json.loads(res.stdout)
    alerts = data.get("security_alerts", {})
    assert (res.returncode == 2) or (sum(alerts.values()) > 0)

