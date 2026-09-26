import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
BPC = (ROOT / "deploy" / "bpc.sh").read_text(encoding="utf-8")
CONTROL = (ROOT / "deploy" / "bpc-control-server.py").read_text(encoding="utf-8")
NODE_ENROLLMENT = (ROOT / "deploy" / "bpc_node_enrollment.py").read_text(encoding="utf-8")
MIGRATE = (ROOT / "deploy" / "bpc-migrate.sh").read_text(encoding="utf-8")
HEALTH = (ROOT / "deploy" / "bpc-healthcheck.sh").read_text(encoding="utf-8")


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


def test_control_service_stages_self_contained_runtime_inside_state_dir() -> None:
    enable_control = (ROOT / "deploy" / "bpc-enable-control.sh").read_text(
        encoding="utf-8"
    )
    release_server = 'release_control_server="${BPC_ROOT}/current/deploy/bpc-control-server.py"'
    release_enrollment = (
        'release_node_enrollment="${BPC_ROOT}/current/deploy/bpc_node_enrollment.py"'
    )
    assert release_server in enable_control
    assert release_enrollment in enable_control
    assert 'release_package="${BPC_ROOT}/current/src/bpc_connect"' in enable_control
    assert 'control_server="${CONTROL_DIR}/runtime/bpc-control-server.py"' in enable_control
    assert 'chown -R root:root "${runtime_tmp}"' in enable_control
    assert "journalctl -u bpc-control.service -n 50 -o cat -l --no-pager" in enable_control


def test_staged_control_runtime_imports_without_release_tree(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "src").mkdir(parents=True)
    shutil.copy(ROOT / "deploy" / "bpc-control-server.py", runtime / "bpc-control-server.py")
    shutil.copy(ROOT / "deploy" / "bpc_node_enrollment.py", runtime / "bpc_node_enrollment.py")
    shutil.copy(ROOT / "deploy" / "bpc_identity.py", runtime / "bpc_identity.py")
    shutil.copytree(ROOT / "src" / "bpc_connect", runtime / "src" / "bpc_connect")

    completed = subprocess.run(
        [sys.executable, str(runtime / "bpc-control-server.py"), "--help"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "BPC Agent control plane" in completed.stdout


def test_joined_node_runtime_is_staged_inside_state_dir() -> None:
    assert 'runtime_version = state_dir / f"runtime-{version}"' in NODE_ENROLLMENT
    assert 'runtime_link = state_dir / "runtime"' in NODE_ENROLLMENT
    assert 'runtime / "deploy" / "bpc_node_enrollment.py"' in NODE_ENROLLMENT
    assert "runtime-install" in NODE_ENROLLMENT
    assert 'python3 "${node_enrollment}" --state-dir "${BPC_STATE_DIR}" runtime-install' in MIGRATE
    assert 'runtime_entry="${BPC_STATE_DIR}/runtime/deploy/bpc_node_enrollment.py"' in HEALTH
    assert "bpc-node.service is not active" in HEALTH
