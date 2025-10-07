# tests/test_netinspect.py
# -*- coding: utf-8 -*-
import json
from types import SimpleNamespace
from pathlib import Path

import pytest

from sabbat_tools import netinspect


class Conn:
    def __init__(self, laddr=None, raddr=None, status="", pid=None, sock_type=None):
        self.laddr = laddr
        self.raddr = raddr
        self.status = status
        self.pid = pid
        self.type = sock_type


class FakeProcess:
    def __init__(self, pid, name="proc", user="root", cmdline=None):
        self._pid = pid
        self._name = name
        self._user = user
        self._cmdline = cmdline or ["/usr/bin/proc"]

    def name(self):
        return self._name

    def username(self):
        return self._user

    def cmdline(self):
        return self._cmdline


class FakePsutil:
    def __init__(self, conns):
        self._conns = conns
        self._procs = {}

    def net_connections(self, kind="inet"):
        if kind == "inet":
            return [c for c in self._conns if c.type in (1, 2)]
        if kind == "unix":
            return [c for c in self._conns if c.type is None]
        return []

    def Process(self, pid):
        return self._procs[pid]

    def add_proc(self, pid, proc):
        self._procs[pid] = proc


@pytest.fixture
def whitelist_file(tmp_path: Path) -> Path:
    p = tmp_path / "whitelist.conf"
    p.write_text("tcp/22\nudp/53\n", encoding="utf-8")
    return p


@pytest.fixture
def ti_csv(tmp_path: Path) -> Path:
    p = tmp_path / "ti.csv"
    p.write_text("ip,source,confidence\n203.0.113.50,local,90\n", encoding="utf-8")
    return p


def make_args(**kwargs):
    base = dict(
        json=False, jsonl=False, raw=False,
        proto="tcp", state="all", scope="all",
        pid=None, user=None, lport=None, rport=None,
        rdns=False, geoip_db=None, whitelist=None, check_ports=False,
        ti_csv=None, check_threat_intel=False,
        snapshot=False, output=None, diff=None,
        max_conns=None, deadline_sec=5.0, include_unix=False,
        sanitize=True, unsafe_proc_cmdline=False,
    )
    base.update(kwargs)
    return SimpleNamespace(**base)


def test_collect_and_filters(monkeypatch):
    import socket
    c1 = Conn(laddr=("0.0.0.0", 2222), raddr=None, status="LISTEN", pid=1000, sock_type=socket.SOCK_STREAM)
    c2 = Conn(laddr=("10.0.0.5", 55555), raddr=("203.0.113.50", 443), status="ESTABLISHED", pid=2000, sock_type=socket.SOCK_STREAM)
    fps = FakePsutil([c1, c2])
    fps.add_proc(1000, FakeProcess(1000, name="sshd", user="root", cmdline=["/usr/sbin/sshd","-D"]))
    fps.add_proc(2000, FakeProcess(2000, name="curl", user="www-data", cmdline=["/usr/bin/curl","https://example"]))  # noqa

    monkeypatch.setattr(netinspect, "psutil", fps)

    args = make_args()
    report = netinspect.run_inspect(args)
    assert report["summary"]["total"] == 2
    est = [f for f in report["findings"] if f["state"] == "ESTABLISHED"]
    assert est and est[0]["raddr"]["ip"] == "203.0.113.50"
    listen = [f for f in report["findings"] if f["state"] == "LISTEN"][0]
    assert listen["proc"]["name"] == "sshd"


def test_whitelist_and_flags(monkeypatch, whitelist_file: Path):
    import socket
    c1 = Conn(laddr=("0.0.0.0", 2222), raddr=None, status="LISTEN", pid=123, sock_type=socket.SOCK_STREAM)
    fps = FakePsutil([c1])
    fps.add_proc(123, FakeProcess(123, name="sshd", user="root"))
    monkeypatch.setattr(netinspect, "psutil", fps)

    args = make_args(state="listening", whitelist=str(whitelist_file), check_ports=True)
    report = netinspect.run_inspect(args)
    assert report["summary"]["total"] == 1
    f = report["findings"][0]
    assert "not_in_whitelist" in (f["flags"] or [])
    assert "exposed_high_port" in (f["flags"] or [])


def test_threat_intel_local(monkeypatch, ti_csv: Path):
    import socket
    c1 = Conn(laddr=("10.0.0.1", 34567), raddr=("203.0.113.50", 443), status="ESTABLISHED", pid=777, sock_type=socket.SOCK_STREAM)
    fps = FakePsutil([c1])
    fps.add_proc(777, FakeProcess(777, name="curl", user="app", cmdline=["/usr/bin/curl","https://evil"]))
    monkeypatch.setattr(netinspect, "psutil", fps)

    args = make_args(json=True, check_threat_intel=True, ti_csv=str(ti_csv))
    report = netinspect.run_inspect(args)
    f = report["findings"][0]
    assert f["ti"] and f["ti"]["listed"] is True
    assert "ti_blacklisted" in f["flags"]
    assert "TI hit for 203.0.113.50" in (f.get("evidence") or "")


def test_snapshot_and_diff(tmp_path: Path, monkeypatch):
    import socket
    c1 = Conn(laddr=("0.0.0.0", 2222), raddr=None, status="LISTEN", pid=1, sock_type=socket.SOCK_STREAM)
    fps1 = FakePsutil([c1]); fps1.add_proc(1, FakeProcess(1, name="sshd", user="root"))
    monkeypatch.setattr(netinspect, "psutil", fps1)
    args = make_args()
    report1 = netinspect.run_inspect(args)
    snap1 = tmp_path / "snap1.json"
    netinspect.save_snapshot(report1, snap1)

    c2 = Conn(laddr=("0.0.0.0", 8080), raddr=None, status="LISTEN", pid=2, sock_type=socket.SOCK_STREAM)
    fps2 = FakePsutil([c2]); fps2.add_proc(2, FakeProcess(2, name="python", user="root"))
    monkeypatch.setattr(netinspect, "psutil", fps2)
    report2 = netinspect.run_inspect(args)

    diff = netinspect.diff_reports(json.loads(snap1.read_text()), report2)
    assert diff["summary"]["added"] >= 1 or diff["summary"]["removed"] >= 1


def test_output_modes(monkeypatch, capsys):
    import socket
    c1 = Conn(laddr=("127.0.0.1", 9999), raddr=None, status="LISTEN", pid=3, sock_type=socket.SOCK_STREAM)
    fps = FakePsutil([c1]); fps.add_proc(3, FakeProcess(3, name="app", user="user"))
    monkeypatch.setattr(netinspect, "psutil", fps)

    args = make_args(jsonl=True)
    report = netinspect.run_inspect(args)
    netinspect.print_json(report, jsonl=True)
    out = capsys.readouterr().out.strip().splitlines()
    assert out and json.loads(out[0])["proto"] == "tcp"

    netinspect.print_raw(report)
    out2 = capsys.readouterr().out
    assert "proto\tstate\tl_ip" in out2

