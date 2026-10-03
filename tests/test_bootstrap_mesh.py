from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from bpc_connect.node import new_node_config, save_node_config, set_node_identity

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import bpc_node_enrollment as enrollment  # noqa: E402


@pytest.fixture
def bootstrap(tmp_path, monkeypatch):
    control = tmp_path / "control"
    control.mkdir()
    config = new_node_config(name="ru-original", roles={
        "controller": True, "gateway": True, "relay": True,
    })
    save_node_config(tmp_path / "node.yaml", config)
    key = enrollment.generate_node_identity(tmp_path)
    config = set_node_identity(tmp_path / "node.yaml", key)
    cluster = tmp_path / "cluster"
    cluster.mkdir()
    (cluster / "cluster.json").write_text(json.dumps({
        "cluster_id": "c" * 32, "controller_node_id": config.node.id,
    }))
    (cluster / "controllers").mkdir()
    marker = {"node_id": config.node.id, "raft_address": "original.example:9445",
              "cluster_api_address": "original.example:9447",
              "local_api_address": "127.0.0.1:9446"}
    for field in ("certificate_file", "key_file", "ca_file", "local_api_token_file"):
        path = cluster / field
        path.write_text("protected " + field)
        marker[field] = str(path)
    (cluster / "controller.json").write_text(json.dumps(marker))
    (cluster / "controllers" / f"{config.node.id}.json").write_text(json.dumps({
        "node_id": config.node.id, "state": "voter", "raft_address": marker["raft_address"],
        "public_url": "https://original.example:8444",
    }))
    (control / "runtime.env").write_text("CONTROL_MODE=primary\nCONTROL_PORT=8444\n")
    (control / "config.json").write_text('{"wireguard_interface":"bpcag0"}')
    (control / "update-signing-key.pem").write_text("original signing key")
    wg = tmp_path / "wireguard"
    wg.mkdir()
    (wg / "wg0.conf").write_text("original transport key")
    monkeypatch.setattr(enrollment.os, "geteuid", lambda: 0)
    monkeypatch.setattr(enrollment, "strong_read", lambda _: None)
    calls = []

    def commit(root, kind, ops):
        assert kind == "RegisterBootstrapMeshNode"
        assert all(op["if_absent"] and not op["path"].exists() for op in ops)
        calls.append(ops)
        for op in ops:
            op["path"].parent.mkdir(parents=True, exist_ok=True)
            op["path"].write_bytes(op["data"])

    monkeypatch.setattr(enrollment.bpc_control_state, "mutation", commit)
    monkeypatch.setattr(enrollment, "install_runtime_service", lambda _: None)
    monkeypatch.setattr(enrollment, "send_heartbeat", lambda *args: {})
    args = enrollment.build_parser().parse_args([
        "--state-dir", str(tmp_path), "--control-dir", str(control), "mesh-enable",
        "--host", "original.example", "--preserve-compat",
    ])
    return args, config.node.id, calls


def protected_bytes(state):
    return {p.relative_to(state): p.read_bytes() for directory in
            ("identity", "cluster", "wireguard", "control")
            for p in (state / directory).rglob("*") if p.is_file()}


def test_existing_identity_pki_api_and_transports_preserved_and_retry(bootstrap):
    args, node_id, calls = bootstrap
    before = protected_bytes(args.state_dir)
    assert enrollment.cmd_mesh_enable(args) == 0
    local = enrollment.enrolled_state(args.state_dir)
    assert local["node_id"] == node_id and local["runtime_mode"] == "primary"
    record = enrollment.read_json(args.control_dir / "nodes" / f"{node_id}.json")
    assert record["role_config"]["gateway"] == {"mode": "routed"}
    assert record["advertised_routes"] == []
    assert record["created_at"] == local["created_at"]
    assert len(calls) == 1 and len(calls[0]) == 3
    assert enrollment.cmd_mesh_enable(args) == 0
    assert enrollment.enrolled_state(args.state_dir)["credential"] == local["credential"]
    assert len(calls) == 1
    after = protected_bytes(args.state_dir)
    assert all(after[p] == data for p, data in before.items())
    journal = args.state_dir / "runtime" / "bootstrap-mesh-registration.json"
    assert journal.stat().st_mode & 0o777 == 0o600


def test_lost_commit_response_recovers_same_credential(bootstrap, monkeypatch):
    args, _, calls = bootstrap
    real = enrollment.bpc_control_state.mutation

    def interrupted(*a, **k):
        real(*a, **k)
        raise enrollment.bpc_control_state.ControlStateError("lost response")

    monkeypatch.setattr(enrollment.bpc_control_state, "mutation", interrupted)
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.cmd_mesh_enable(args)
    assert enrollment.enrolled_state(args.state_dir) is None
    saved = enrollment.read_json(args.state_dir / "runtime" / "bootstrap-mesh-registration.json")
    monkeypatch.setattr(enrollment.bpc_control_state, "mutation", real)
    assert enrollment.cmd_mesh_enable(args) == 0
    assert len(calls) == 1
    assert enrollment.enrolled_state(args.state_dir)["credential"] == saved["credential"]


@pytest.mark.parametrize("failure", ["replica", "identity", "membership", "host"])
def test_validation_refuses_before_registration(bootstrap, failure):
    args, node_id, calls = bootstrap
    if failure == "replica":
        (args.control_dir / "runtime.env").write_text("CONTROL_MODE=replica\n")
    elif failure == "identity":
        (args.state_dir / "identity" / "node.pub").write_text("wrong key")
    elif failure == "membership":
        path = args.state_dir / "cluster" / "controllers" / f"{node_id}.json"
        record = enrollment.read_json(path)
        record["state"] = "revoked"
        path.write_text(json.dumps(record))
    else:
        args.host = ["other.example"]
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.cmd_mesh_enable(args)
    assert not calls and enrollment.enrolled_state(args.state_dir) is None
    assert not (args.state_dir / "runtime" / "bootstrap-mesh-registration.json").exists()


def test_revoked_registration_is_never_reactivated(bootstrap):
    args, node_id, calls = bootstrap
    enrollment.cmd_mesh_enable(args)
    path = args.control_dir / "nodes" / f"{node_id}.json"
    record = enrollment.read_json(path)
    record["revoked"] = True
    path.write_text(json.dumps(record))
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.cmd_mesh_enable(args)
    assert len(calls) == 1 and enrollment.read_json(path)["revoked"]


def test_primary_updates_never_convert_api_and_keep_compat_watcher(bootstrap, monkeypatch):
    args, _, _ = bootstrap
    enrollment.cmd_mesh_enable(args)
    commands = []
    monkeypatch.setattr(enrollment.subprocess, "run", lambda command, **kw:
                        commands.append(command) or SimpleNamespace(returncode=0))
    before = protected_bytes(args.state_dir)
    enrollment.reconcile_controller_runtime(args.state_dir)
    assert len(commands) == 1 and "--bootstrap" not in commands[0]
    assert commands[0][0].endswith("bpc-enable-cluster.sh")
    assert protected_bytes(args.state_dir) == before
    gateway = []
    monkeypatch.setattr(enrollment, "reconcile_local_gateway_state", lambda _: gateway.append(True))
    assert enrollment.cmd_local_reconcile(args) == 0
    assert enrollment.reconcile_startup_gateway_state(args.state_dir, {"gateway": True})
    assert gateway == [True, True]


def test_credential_index_contains_only_hash_not_secret(bootstrap):
    args, _, _ = bootstrap
    enrollment.cmd_mesh_enable(args)
    local = enrollment.enrolled_state(args.state_dir)
    files = list((args.control_dir / "node-credentials").glob("*.json"))
    assert len(files) == 1
    assert files[0].stem == hashlib.sha256(local["credential"].encode()).hexdigest()
    assert local["credential"] not in files[0].read_text()


def test_primary_mode_loss_refuses_update_before_services(bootstrap, monkeypatch):
    args, _, _ = bootstrap
    enrollment.cmd_mesh_enable(args)
    (args.control_dir / "runtime.env").write_text("CONTROL_MODE=replica\n")
    monkeypatch.setattr(enrollment.subprocess, "run",
                        lambda *a, **k: pytest.fail("service command"))
    with pytest.raises(enrollment.EnrollmentError, match="primary API"):
        enrollment.reconcile_controller_runtime(args.state_dir)


def test_registration_adds_second_private_uplink_and_public_mesh(bootstrap):
    import bpc_topology as topology

    args, bootstrap_id, _ = bootstrap
    nodes = args.control_dir / "nodes"
    nodes.mkdir()
    for node_id, roles in [("b" * 32, {"gateway": True, "relay": True}),
                           ("d" * 32, {"site_router": True})]:
        (nodes / f"{node_id}.json").write_text(json.dumps({"node_id": node_id, "roles": roles}))
    assert topology.desired_topology_pairs(args.control_dir) == {("b" * 32, "d" * 32)}
    enrollment.cmd_mesh_enable(args)
    expected = {tuple(sorted(pair)) for pair in [
        (bootstrap_id, "b" * 32), (bootstrap_id, "d" * 32), ("b" * 32, "d" * 32),
    ]}
    assert topology.desired_topology_pairs(args.control_dir) == expected
