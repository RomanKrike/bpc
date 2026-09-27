from __future__ import annotations

from pathlib import Path

import pytest

from bpc_connect.identity import NodeIdentityError, ensure_node_identity
from bpc_connect.node import load_node_config, new_node_config, save_node_config, set_node_identity


def seed_empty_node(root: Path) -> None:
    config = new_node_config(
        name="legacy-controller",
        roles={"controller": True, "gateway": True, "relay": True},
        now=1_000,
    )
    save_node_config(root / "node.yaml", config)


def test_missing_legacy_identity_is_created_and_linked_idempotently(tmp_path: Path) -> None:
    seed_empty_node(tmp_path)

    first = ensure_node_identity(tmp_path)

    assert first.private_key_created is True
    assert first.public_key_file_updated is True
    assert first.node_config_updated is True
    assert first.changed is True
    assert (tmp_path / "identity" / "node.key").is_file()
    assert (tmp_path / "identity" / "node.pub").read_text(encoding="utf-8").strip() == (
        first.public_key
    )
    assert load_node_config(tmp_path / "node.yaml").node.public_key == first.public_key
    assert oct((tmp_path / "identity").stat().st_mode & 0o777) == "0o700"
    assert oct((tmp_path / "identity" / "node.key").stat().st_mode & 0o777) == "0o600"

    private_before = (tmp_path / "identity" / "node.key").read_bytes()
    second = ensure_node_identity(tmp_path)

    assert second.public_key == first.public_key
    assert second.changed is False
    assert (tmp_path / "identity" / "node.key").read_bytes() == private_before


def test_configured_identity_without_private_key_refuses_rotation(tmp_path: Path) -> None:
    seed_empty_node(tmp_path)
    set_node_identity(tmp_path / "node.yaml", "configured-public-key")

    with pytest.raises(NodeIdentityError, match="private key is missing"):
        ensure_node_identity(tmp_path)

    assert not (tmp_path / "identity" / "node.key").exists()
    assert load_node_config(tmp_path / "node.yaml").node.public_key == "configured-public-key"


def test_private_key_mismatch_refuses_public_key_overwrite(tmp_path: Path) -> None:
    seed_empty_node(tmp_path)
    first = ensure_node_identity(tmp_path)
    set_node_identity(tmp_path / "node.yaml", "different-public-key")

    with pytest.raises(NodeIdentityError, match="does not match"):
        ensure_node_identity(tmp_path)

    assert (tmp_path / "identity" / "node.key").is_file()
    assert (tmp_path / "identity" / "node.pub").read_text(encoding="utf-8").strip() == (
        first.public_key
    )
    assert load_node_config(tmp_path / "node.yaml").node.public_key == "different-public-key"


def test_orphaned_public_key_file_refuses_rotation(tmp_path: Path) -> None:
    seed_empty_node(tmp_path)
    identity = tmp_path / "identity"
    identity.mkdir()
    (identity / "node.pub").write_text("orphaned-public-key\n", encoding="utf-8")

    with pytest.raises(NodeIdentityError, match="node.pub exists"):
        ensure_node_identity(tmp_path)

    assert not (identity / "node.key").exists()
    assert (identity / "node.pub").read_text(encoding="utf-8").strip() == "orphaned-public-key"
