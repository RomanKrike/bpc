from pathlib import Path

import pytest

from bpc_connect.compat.legacy import migrate_legacy_node
from bpc_connect.errors import BPCConfigError
from bpc_connect.node import (
    CORE_CAPABILITIES,
    Capabilities,
    load_node_config,
    new_node_config,
    parse_node_config,
    save_node_config,
    set_advertised_routes,
    set_capabilities,
)


def test_capabilities_support_multiple_roles_and_extensions() -> None:
    capabilities = Capabilities.from_mapping(
        {
            "controller": True,
            "gateway": True,
            "relay": True,
            "site_router": False,
            "metrics_exporter": True,
        }
    )

    assert capabilities.has("controller")
    assert capabilities.has("gateway")
    assert capabilities.has("relay")
    assert not capabilities.has("site_router")
    assert capabilities.has("metrics_exporter")
    assert capabilities.enabled() == (
        "controller",
        "gateway",
        "metrics_exporter",
        "relay",
    )


def test_capability_defaults_are_centralized() -> None:
    capabilities = Capabilities.from_mapping({})

    assert set(CORE_CAPABILITIES) == {
        "controller",
        "gateway",
        "relay",
        "site_router",
    }
    assert all(not capabilities.has(name) for name in CORE_CAPABILITIES)
    assert not capabilities.has("future_role")


@pytest.mark.parametrize(
    ("roles", "message"),
    [
        ({"Bad-Role": True}, "Invalid capability name"),
        ({"gateway": "yes"}, "must be boolean"),
    ],
)
def test_invalid_capabilities_are_rejected(roles: dict[str, object], message: str) -> None:
    with pytest.raises(BPCConfigError, match=message):
        Capabilities.from_mapping(roles)


def test_node_config_round_trip_includes_canonical_advertised_routes(tmp_path: Path) -> None:
    path = tmp_path / "node.yaml"
    config = new_node_config(
        name="ru-01",
        roles={
            "controller": True,
            "gateway": True,
            "relay": True,
            "site_router": True,
        },
        advertised_routes=["192.168.88.14/24", "10.20.0.0/16"],
        now=100,
    )
    save_node_config(path, config)

    loaded = load_node_config(path)

    assert loaded.version == 1
    assert loaded.node.id == config.node.id
    assert loaded.node.name == "ru-01"
    assert loaded.node.created_at == 100
    assert loaded.node.last_seen == 0
    assert loaded.node.public_key == ""
    assert loaded.node.has_capability("controller")
    assert loaded.node.has_capability("gateway")
    assert loaded.node.has_capability("relay")
    assert loaded.node.has_capability("site_router")
    assert loaded.advertised_routes == ("10.20.0.0/16", "192.168.88.0/24")


def test_legacy_state_migrates_only_through_compatibility_adapter(tmp_path: Path) -> None:
    legacy = tmp_path / "ru-node"
    (legacy / "control").mkdir(parents=True)
    (legacy / "agent").mkdir(parents=True)
    (legacy / "config.json").write_text("{}", encoding="utf-8")
    (legacy / "control" / "enabled").touch()
    (legacy / "agent" / "enabled").touch()

    first, changed = migrate_legacy_node(tmp_path, name="ru-01", now=200)
    second, changed_again = migrate_legacy_node(tmp_path, now=300)

    assert changed is True
    assert changed_again is False
    assert second.node.id == first.node.id
    assert second.node.name == "ru-01"
    assert second.node.roles.has("controller")
    assert second.node.roles.has("gateway")
    assert second.node.roles.has("relay")
    assert not second.node.roles.has("site_router")


def test_legacy_install_profile_is_compatibility_input_only(tmp_path: Path) -> None:
    (tmp_path / "install.env").write_text("BPC_ROLE=ru-node\n", encoding="utf-8")

    config, _ = migrate_legacy_node(tmp_path, name="legacy-ru", now=400)

    assert config.node.roles.has("gateway")
    assert not config.node.roles.has("controller")
    assert not config.node.roles.has("relay")


def test_compatibility_reconcile_never_drops_canonical_capabilities(tmp_path: Path) -> None:
    config = new_node_config(
        name="mixed-node",
        roles={"site_router": True, "future_role": True},
        advertised_routes=["192.168.88.0/24"],
        now=500,
    )
    save_node_config(tmp_path / "node.yaml", config)
    (tmp_path / "ru-node" / "control").mkdir(parents=True)
    (tmp_path / "ru-node" / "control" / "enabled").touch()

    reconciled, changed = migrate_legacy_node(tmp_path, now=600)

    assert changed is True
    assert reconciled.node.roles.has("controller")
    assert reconciled.node.roles.has("site_router")
    assert reconciled.node.roles.has("future_role")
    assert reconciled.advertised_routes == ("192.168.88.0/24",)


def test_set_capabilities_updates_one_role_without_type_switch(tmp_path: Path) -> None:
    path = tmp_path / "node.yaml"
    save_node_config(path, new_node_config(name="node-01", now=700))

    updated = set_capabilities(path, {"controller": True, "relay": True})

    assert updated.node.roles.has("controller")
    assert updated.node.roles.has("relay")
    assert not updated.node.roles.has("gateway")


def test_set_advertised_routes_is_node_owned_state(tmp_path: Path) -> None:
    path = tmp_path / "node.yaml"
    save_node_config(
        path,
        new_node_config(name="site-01", roles={"site_router": True}, now=800),
    )

    updated = set_advertised_routes(path, ["192.168.88.0/24"])

    assert updated.node.roles.has("site_router")
    assert updated.advertised_routes == ("192.168.88.0/24",)


def test_unknown_node_config_version_is_rejected() -> None:
    raw = {
        "version": 99,
        "node": {
            "id": "abc",
            "name": "node",
            "public_key": "",
            "created_at": 1,
            "last_seen": 0,
        },
        "roles": {},
    }
    with pytest.raises(BPCConfigError, match="Unsupported node config version"):
        parse_node_config(raw)
