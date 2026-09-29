from pathlib import Path

SCRIPT = Path("scripts/acceptance-public-node-failover.ps1").read_text(encoding="utf-8")


def test_public_node_failover_harness_records_path_and_overlay_state() -> None:
    assert "status-json" in SCRIPT
    assert "ui-transport.json" in SCRIPT
    assert "switch_delay_ms" in SCRIPT
    assert "max_success_gap_ms" in SCRIPT
    assert "overlayUnchanged" in SCRIPT
    assert "MaxSwitchMilliseconds = 1500" in SCRIPT


def test_public_node_failover_harness_can_fault_and_restore_relay_over_ssh() -> None:
    assert '"systemctl", "stop", $serviceName' in SCRIPT
    assert "systemctl start $serviceName" in SCRIPT
    assert "BatchMode=yes" in SCRIPT
    assert "StrictHostKeyChecking=accept-new" in SCRIPT
    assert "ConnectTimeout=5" in SCRIPT
    assert "NoRestore" in SCRIPT
