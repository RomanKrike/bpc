from pathlib import Path

import yaml

from bpc_connect.node import load_node_config

ROOT = Path(__file__).parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
MIGRATE = (ROOT / "deploy" / "bpc-migrate.sh").read_text(encoding="utf-8")
UPDATE = (ROOT / "deploy" / "bpc-update.sh").read_text(encoding="utf-8")
NODE_SH = (ROOT / "deploy" / "bpc-node.sh").read_text(encoding="utf-8")
BPC_SH = (ROOT / "deploy" / "bpc.sh").read_text(encoding="utf-8")
STATUS = (ROOT / "deploy" / "bpc-status.sh").read_text(encoding="utf-8")
CONTROL = (ROOT / "deploy" / "bpc-enable-control.sh").read_text(encoding="utf-8")
DATAPLANE = (ROOT / "deploy" / "bpc-enable-agent-dataplane.sh").read_text(
    encoding="utf-8"
)
WGSHIM = (ROOT / "deploy" / "bpc-enable-wgshim.sh").read_text(encoding="utf-8")
NODE_EXAMPLE = ROOT / "config" / "node.example.yaml"


def test_node_example_is_controller_gateway_relay() -> None:
    config = load_node_config(NODE_EXAMPLE)

    assert config.version == 1
    assert config.node.name == "ru-01"
    assert config.node.roles.has("controller")
    assert config.node.roles.has("gateway")
    assert config.node.roles.has("relay")
    assert not config.node.roles.has("site_router")


def test_unified_bpc_cli_routes_node_status_and_info() -> None:
    assert 'exec "${BPC_ROOT}/current/deploy/bpc-node.sh" "$@"' in BPC_SH
    assert "bpc-node status" in NODE_SH
    assert "bpc-node info" in NODE_SH
    assert "node_status" in NODE_SH
    assert "node_info" in NODE_SH


def test_install_and_update_reconcile_bpc_command() -> None:
    assert '"bpc:bpc.sh"' in INSTALL
    assert '"bpc:bpc.sh"' in UPDATE
    assert '"bpc:bpc.sh"' in MIGRATE
    assert "BPC_NODE_CONFIG=" in INSTALL


def test_legacy_role_is_not_runtime_node_type_gate() -> None:
    assert 'legacy_role="${BPC_ROLE:-unknown}"' in STATUS
    assert 'if [[ "${role}" == "ru-node" ]]' not in STATUS
    assert 'if [[ -d "${BPC_STATE_DIR}/ru-node" ]]' in STATUS


def test_capabilities_reconcile_when_services_are_enabled() -> None:
    assert "capability controller enable" in CONTROL
    assert "capability relay enable" in CONTROL
    assert "capability relay enable" in DATAPLANE
    assert "capability relay enable" in WGSHIM


def test_node_config_does_not_embed_transport_credentials() -> None:
    raw = yaml.safe_load(NODE_EXAMPLE.read_text(encoding="utf-8"))
    serialized = yaml.safe_dump(raw).lower()

    assert "private_key" not in serialized
    assert "preshared" not in serialized
    assert "wgshim_psk" not in serialized
    assert "uuid" not in serialized
