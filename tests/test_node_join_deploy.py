from pathlib import Path

ROOT = Path(__file__).parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
BPC = (ROOT / "deploy" / "bpc.sh").read_text(encoding="utf-8")
CONTROL = (ROOT / "deploy" / "bpc-control-server.py").read_text(encoding="utf-8")


def test_no_argument_installer_is_core_only_and_legacy_bootstrap_remains() -> None:
    assert 'ROLE=""' in INSTALL
    assert 'elif [[ "${ROLE}" == "ru-node" ]]' in INSTALL
    assert "BPC core runtime installed. Join this host with: bpc join <TOKEN>" in INSTALL
    assert "Existing RU-node configuration found; keeping credentials and configuration." in INSTALL


def test_installer_preserves_previous_install_profile_on_repeat() -> None:
    assert 'previous_role="$(sed -n' in INSTALL
    assert 'install_role="${previous_role}"' in INSTALL
    assert "BPC_NODE_CONFIG=${BPC_STATE_DIR}/node.yaml" in INSTALL


def test_unified_cli_exposes_stage2_node_commands() -> None:
    assert "bpc join <TOKEN>" in BPC
    assert "bpc status" in BPC
    assert "bpc leave [--force]" in BPC
    assert "bpc node token create" in BPC
    assert "bpc node list" in BPC


def test_controller_exposes_separate_node_enrollment_endpoints() -> None:
    assert 'self.path == "/v1/nodes/join"' in CONTROL
    assert 'self.path == "/v1/nodes/heartbeat"' in CONTROL
    assert 'self.path == "/v1/nodes/leave"' in CONTROL
    assert 'self.path == "/v1/enroll"' in CONTROL
    assert 'self.path == "/v1/heartbeat"' in CONTROL


def test_control_service_runs_server_from_release_tree() -> None:
    enable_control = (ROOT / "deploy" / "bpc-enable-control.sh").read_text(
        encoding="utf-8"
    )
    assert 'control_server="${BPC_ROOT}/current/deploy/bpc-control-server.py"' in enable_control
    assert 'install -m 0700 "${BPC_ROOT}/current/deploy/bpc-control-server.py"' not in enable_control
