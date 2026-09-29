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


RESTART_SCRIPT = Path("scripts/acceptance-node-restart-regression.sh").read_text(
    encoding="utf-8"
)


def test_restart_regression_harness_covers_required_stage8_actions() -> None:
    assert "systemctl restart bpc-control.service" in RESTART_SCRIPT
    assert "systemctl restart bpc-agent-relay.service" in RESTART_SCRIPT
    assert 'BPC_UPDATE_COMMAND:-bpc-update' in RESTART_SCRIPT
    assert "prepare-reboot" in RESTART_SCRIPT
    assert "verify-reboot" in RESTART_SCRIPT


def test_restart_regression_harness_checks_multipath_identity_invariants() -> None:
    for field in (
        "node_identity_unchanged",
        "overlay_identity_unchanged",
        "devices_unchanged",
        "access_unchanged",
        "routes_unchanged",
        "peer_set_unchanged",
        "peer_allowed_ips_unchanged",
        "learned_endpoints_not_lost",
    ):
        assert field in RESTART_SCRIPT
    assert 'wg", "show", interface, "dump"' in RESTART_SCRIPT
