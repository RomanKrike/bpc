from __future__ import annotations

import base64
import json
import os
import shlex
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "deploy"))
import bpc_node_enrollment as enrollment  # noqa: E402


@pytest.mark.parametrize("preset,name,options,roles", [
    ("public-node", "ru-02", ["--host", "ru-02.blinpi.ru"],
     {"controller": True, "gateway": True, "relay": True}),
    ("site-router", "home-01", ["--route", "192.168.88.0/24"], {"site_router": True}),
])
def test_preset_creates_scoped_invitation(tmp_path, monkeypatch, capsys,
                                         preset, name, options, roles):
    control = tmp_path / "control"
    monkeypatch.setattr(enrollment.bpc_control_state, "cluster_enabled", lambda _: True)
    monkeypatch.setattr(enrollment.bpc_control_state, "strong_read", lambda _: {})

    def mutation(root, kind, operations, **kwargs):
        for op in operations:
            path = Path(op["path"])
            path.parent.mkdir(parents=True, exist_ok=True)
            if op["op"] == "delete":
                path.unlink()
            else:
                path.write_bytes(op["data"])
        return {"ok": True}

    monkeypatch.setattr(enrollment.bpc_control_state, "mutation", mutation)
    args = enrollment.build_parser().parse_args([
        "--state-dir", str(tmp_path), "--control-dir", str(control), "node-create",
        "--name", name, "--preset", preset,
        "--controller-url", "https://ru-01.blinpi.ru:8444", *options,
    ])
    assert enrollment.cmd_node_create(args) == 0
    command = capsys.readouterr().out.splitlines()[-1]
    assert "| bash -s -- join " in command
    token = shlex.split(command)[-1]
    metadata = enrollment.join_token_metadata(control, token)
    assert set(metadata["roles"]) == set(roles)
    assert metadata["name"] == name
    joined = enrollment.enroll_node(
        control, token=token, public_key=base64.b64encode(os.urandom(32)).decode(),
        presented_name="machine-hostname",
    )
    assert joined["roles"] == roles
    config = joined["config"]
    if preset == "site-router":
        assert config["endpoints"] == []
        assert config["advertised_routes"] == ["192.168.88.0/24"]
    else:
        assert config["endpoints"][0]["host"] == "ru-02.blinpi.ru"
    record = json.loads((control / "nodes" / f'{joined["node_id"]}.json').read_text())
    assert record["endpoints"] == config["endpoints"]


@pytest.mark.parametrize("options", [[], ["--host", "127.0.0.1"], ["--host", "localhost"]])
def test_public_preset_rejects_missing_or_nonpublic_hostname(tmp_path, options):
    args = enrollment.build_parser().parse_args([
        "--state-dir", str(tmp_path), "--control-dir", str(tmp_path / "control"),
        "node-create", "--name", "ru-02", "--preset", "public-node", *options,
    ])
    with pytest.raises(enrollment.EnrollmentError, match="hostname"):
        enrollment.cmd_node_create(args)
    assert not (tmp_path / "control").exists()


def test_route_scope_is_validated_before_invitation_write(tmp_path):
    with pytest.raises(enrollment.EnrollmentError, match="site_router"):
        enrollment.create_join_token(
            tmp_path / "control", controller_url="https://ru-01.blinpi.ru:8444",
            roles=["controller"], advertised_routes=["192.168.88.0/24"],
        )
    assert not (tmp_path / "control").exists()


def test_join_applies_invited_routes_without_endpoint(tmp_path):
    from bpc_connect.node import new_node_config, save_node_config

    # The installer creates a provisional Node before enrollment assigns its ID.
    save_node_config(tmp_path / "node.yaml", new_node_config(name="fresh-machine"))
    enrollment.apply_remote_node_config(
        tmp_path, node_id="a" * 32, name="home-01", public_key="key",
        roles={"site_router": True}, created_at=1, last_seen=1, endpoints=[],
        initial_routes=["192.168.88.0/24"],
    )
    config = enrollment.load_node_config(tmp_path / "node.yaml")
    assert config.node.endpoints == ()
    assert config.advertised_routes == ("192.168.88.0/24",)
