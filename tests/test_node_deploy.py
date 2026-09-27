from pathlib import Path

import yaml

from bpc_connect.node import load_node_config

ROOT = Path(__file__).parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
MIGRATE = (ROOT / "deploy" / "bpc-migrate.sh").read_text(encoding="utf-8")
UPDATE = (ROOT / "deploy" / "bpc-update.sh").read_text(encoding="utf-8")
NODE_SH = (ROOT / "deploy" / "bpc-node.sh").read_text(encoding="utf-8")
BPC_SH = (ROOT / "deploy" / "bpc.sh").read_text(encoding="utf-8")
HEALTH = (ROOT / "deploy" / "bpc-healthcheck.sh").read_text(encoding="utf-8")
CONTROL = (ROOT / "deploy" / "bpc-enable-control.sh").read_text(encoding="utf-8")
CLUSTER = (ROOT / "deploy" / "bpc_cluster.py").read_text(encoding="utf-8")
DATAPLANE = (ROOT / "deploy" / "bpc-enable-agent-dataplane.sh").read_text(
    encoding="utf-8"
)
NODE_EXAMPLE = ROOT / "config" / "node.example.yaml"


def test_node_example_is_controller_gateway_relay() -> None:
    config = load_node_config(NODE_EXAMPLE)

    assert config.version == 1
    assert config.node.name == "ru-01"
    assert config.node.roles.has("controller")
    assert config.node.roles.has("gateway")
    assert config.node.roles.has("relay")
    assert not config.node.roles.has("site_router")


def test_unified_cli_exposes_canonical_node_and_cluster_commands() -> None:
    assert "bpc init" in BPC_SH
    assert 'CONTROL_DIR="${BPC_STATE_DIR}/control"' in BPC_SH
    assert 'exec "${BPC_ROOT}/current/deploy/bpc-node.sh" "$@"' in BPC_SH
    assert "bpc-node status" in NODE_SH
    assert "bpc-node info" in NODE_SH


def test_install_and_update_reconcile_bpc_command() -> None:
    assert '"bpc:bpc.sh"' in INSTALL
    assert '"bpc:bpc.sh"' in UPDATE
    assert '"bpc:bpc.sh"' in MIGRATE
    assert '"bpc-enable-cluster:bpc-enable-cluster.sh"' in INSTALL
    assert '"bpc-enable-cluster:bpc-enable-cluster.sh"' in UPDATE
    assert '"bpc-enable-control-replica:bpc-enable-control-replica.sh"' in INSTALL
    assert '"bpc-enable-control-replica:bpc-enable-control-replica.sh"' in UPDATE
    assert '"bpc-enable-cluster:bpc-enable-cluster.sh"' in MIGRATE
    assert '"bpc-enable-control-replica:bpc-enable-control-replica.sh"' in MIGRATE
    assert "BPC_NODE_CONFIG=" in INSTALL


def test_runtime_health_is_not_gated_by_legacy_install_role() -> None:
    assert 'case "${ROLE}" in' not in HEALTH
    assert "node_has_capability" in HEALTH
    assert 'local control_dir="${BPC_STATE_DIR}/control"' in HEALTH


def test_capabilities_reconcile_when_services_are_enabled() -> None:
    assert "capability controller enable" in CONTROL
    assert "capability relay enable" in CONTROL
    assert "capability relay enable" in DATAPLANE


def test_legacy_bp_gateway_write_workflow_is_disabled() -> None:
    assert "Legacy BP Gateway write workflow is deprecated and disabled." in NODE_SH
    assert "create|grant|ungrant|remove" in NODE_SH
    assert "gateway-list" in NODE_SH


def test_agent_dataplane_requires_ownership_before_wireguard_mutation() -> None:
    assert 'ownership_file="${AGENT_DIR}/ownership.json"' in DATAPLANE
    assert "Refusing to modify WireGuard interface" in DATAPLANE
    assert '"owner": "bpc"' in DATAPLANE
    assert '"kind": "wireguard-interface"' in DATAPLANE


def test_node_config_does_not_embed_transport_credentials() -> None:
    raw = yaml.safe_load(NODE_EXAMPLE.read_text(encoding="utf-8"))
    serialized = yaml.safe_dump(raw).lower()

    assert "private_key" not in serialized
    assert "preshared" not in serialized
    assert "wgshim_psk" not in serialized
    assert "uuid" not in serialized


def test_cluster_init_roles_are_parsed_as_role_values() -> None:
    assert 'init.add_argument("--roles", action="append")' in CLUSTER
    assert 'normalize_roles(args.roles or ["controller,gateway,relay"])' in CLUSTER
