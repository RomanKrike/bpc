"""Unit tests must never operate the test runner's real host services."""
from __future__ import annotations

import os
import subprocess

import pytest


@pytest.fixture(autouse=True)
def prohibit_host_service_commands(monkeypatch, request):
    # This dedicated integration test intentionally exercises independent
    # systemd watchdogs on a nonexistent interface and requires explicit opt-in.
    if (request.node.path.name == "test_firewall_probe_systemd.py"
            and os.environ.get("BPC_TEST_SYSTEMD") == "1"):
        return
    original = subprocess.Popen

    def guarded(args, *positional, **kwargs):
        if isinstance(args, (list, tuple)) and args:
            name = os.path.basename(os.fsdecode(args[0]))
            if name in {"systemctl", "systemd-run", "service"}:
                raise AssertionError(f"test attempted real host service command: {name}; mock it")
        return original(args, *positional, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", guarded)
