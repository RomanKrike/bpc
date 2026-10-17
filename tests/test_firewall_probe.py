from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "firewall_probe.py"
spec = importlib.util.spec_from_file_location("firewall_probe", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def test_scoped_mark_has_unique_exact_cleanup_spec():
    rule = probe.rule("bpcag0", "10.253.0.2", "192.168.88.12", "a" * 32, True)
    assert rule[:6] == ["-i", "bpcag0", "-s", "10.253.0.2/32", "-d", "192.168.88.12/32"]
    assert rule[6:8] == ["-p", "icmp"]
    assert rule[-4:] == ["-j", "MARK", "--set-xmark", "0x425043/0xffffffff"]


@pytest.mark.parametrize("interface,source,destination,token", [
    ("bpcag0; reboot", "10.0.0.1", "10.0.0.2", "a" * 32),
    ("bpcag0", "0.0.0.0/0", "10.0.0.2", "a" * 32),
    ("bpcag0", "10.0.0.1", "0.0.0.0/0", "a" * 32),
    ("bpcag0", "10.0.0.1", "10.0.0.2", "../../bad"),
])
def test_refuses_unbounded_or_injected_rules(interface, source, destination, token):
    with pytest.raises(ValueError):
        probe.rule(interface, source, destination, token, False)


@pytest.mark.parametrize("status", [0, 1, 2])
def test_cleanup_deletes_only_exact_owned_rule(monkeypatch, status):
    commands = []

    def run(argv, **kwargs):
        commands.append(argv)
        return SimpleNamespace(returncode=status)

    monkeypatch.setattr(probe.subprocess, "run", run)
    rule = probe.rule("bpcag0", "10.0.0.1", "10.0.0.2", "a" * 32, False)
    if status == 2:
        with pytest.raises(RuntimeError, match="retain rollback"):
            probe.cleanup(rule)
    else:
        probe.cleanup(rule)
    assert len(commands) == (2 if status == 0 else 1)
    assert commands[0][1:7] == ["-w", "5", "-t", "mangle", "-C", "PREROUTING"]
    if status == 0:
        assert commands[1] == ["iptables", "-w", "5", "-t", "mangle", "-D", "PREROUTING", *rule]


@pytest.mark.skipif(__import__("sys").platform != "linux", reason="requires Linux flock and /proc")
@pytest.mark.parametrize("failure", [
    "arm", "active", "insert", "command", "timeout", "cleanup", None,
])
def test_watchdog_precedes_mutation_and_survives_errors(tmp_path, monkeypatch, failure):
    events = []
    original_open = Path.open
    monkeypatch.setattr(Path, "open", lambda path, *a, **kw:
                        original_open(tmp_path / path.name, *a, **kw))

    def run(argv, **kwargs):
        event = ("arm" if argv[0] == "systemd-run" else
                 "active" if "is-active" in argv else
                 "insert" if argv[0] == "iptables" else "stop")
        events.append(event)
        if event == failure:
            raise RuntimeError(event)
        return SimpleNamespace(returncode=0)

    def cleanup(spec):
        events.append("cleanup")
        if failure == "cleanup":
            raise RuntimeError("cleanup")

    def command(argv, **kwargs):
        events.append("command")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(argv, 1)
        return SimpleNamespace(returncode=7 if failure == "command" else 0)

    monkeypatch.setattr(probe, "run", run)
    monkeypatch.setattr(probe, "cleanup", cleanup)
    monkeypatch.setattr(probe.subprocess, "run", command)
    args = SimpleNamespace(interface="bpcag0", source="10.0.0.1", destination="10.0.0.2",
                           token="a" * 32, icmp=True, cleanup=False, seconds=10, command=["false"])
    if failure in ("arm", "active", "insert", "timeout", "cleanup"):
        with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
            probe.probe(args)
    else:
        assert probe.probe(args) == (7 if failure == "command" else 0)
    if "insert" in events:
        assert events[:3] == ["arm", "active", "insert"]
    if failure in ("command", "timeout", None):
        assert events[-2:] == ["cleanup", "stop"]
    if failure == "cleanup":
        assert "stop" not in events
