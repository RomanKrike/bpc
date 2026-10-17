"""Root integration: real timer and real iptables, with a nonmatching probe rule."""
from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
from test_firewall_probe import SCRIPT, probe


@pytest.mark.skipif(os.environ.get("BPC_TEST_SYSTEMD") != "1",
                    reason="requires privileged Linux systemd host")
@pytest.mark.parametrize("failure", ["exit", "kill", "kill_reload"])
def test_real_rollback_after_failed_command_or_killed_caller(failure):
    token = uuid.uuid4().hex
    unit = "bpc-mesh-icmp-rollback-" + token
    rule = probe.rule("bpcprobe0", "192.0.2.1", "192.0.2.2", token, True)

    def present():
        result = subprocess.run(["iptables", "-w", "5", "-t", "mangle", "-C",
                                 "PREROUTING", *rule], capture_output=True, timeout=10)
        assert result.returncode in (0, 1), result.stderr
        return result.returncode == 0

    # Refuse to match any real interface; no live traffic is affected.
    assert not Path("/sys/class/net/bpcprobe0").exists()
    command = [sys.executable, str(SCRIPT), "--interface", "bpcprobe0", "--source",
               "192.0.2.1", "--destination", "192.0.2.2", "--icmp", "--token", token,
               "--seconds", "10", "--", sys.executable, "-c",
               "raise SystemExit(7)" if failure == "exit" else "import time; time.sleep(30)"]
    process = subprocess.Popen(command)
    try:
        if failure == "exit":
            assert process.wait(timeout=15) == 7
        else:
            deadline = time.monotonic() + 5
            while not present():
                assert process.poll() is None
                assert time.monotonic() < deadline
                time.sleep(0.1)
            process.kill()  # No finally/trap can run: independent timer must clean up.
            process.wait(timeout=5)
            deadline = time.monotonic() + 20
            while present():
                assert time.monotonic() < deadline, "watchdog left a temporary rule"
                if failure == "kill_reload":
                    # Node reconciliation reloads the manager repeatedly in production.
                    # A relative OnActive timer can drift indefinitely on these hosts.
                    subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=10)
                time.sleep(0.2)
        assert not present()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        probe.cleanup(rule)
        subprocess.run(["systemctl", "stop", unit + ".timer", unit + ".service"],
                       check=False, timeout=10)
        (Path("/run") / (unit + ".lock")).unlink(missing_ok=True)
