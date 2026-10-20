from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from bpc_connect.compat import runtime
from bpc_connect.node import new_node_config, save_node_config

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import bpc_node_enrollment as enrollment  # noqa: E402
import bpc_topology as topology  # noqa: E402
from bpc_control_runtime import prepare_control_runtime  # noqa: E402


def test_routed_roles_preserve_existing_transports(tmp_path, monkeypatch):
    # Existing legacy state must not trigger bootstrap, Agent setup, or Xray start.
    legacy = tmp_path / "ru-node"
    legacy.mkdir()
    for name in ("config.json", "client.env"):
        (legacy / name).write_text("existing credentials")
    before = {p: p.read_bytes() for p in legacy.iterdir()}
    monkeypatch.setattr(runtime.subprocess, "run", lambda *a, **k: pytest.fail("legacy command"))
    config = runtime.default_role_config(tmp_path, ["gateway", "relay"], dataplane="routed")
    assert runtime.reconcile_transport_roles(
        tmp_path, {"gateway": True, "relay": True}, config, deploy_dir=ROOT / "deploy",
    ) == {"gateway": "configured", "relay": "configured"}
    assert {p: p.read_bytes() for p in legacy.iterdir()} == before


@pytest.mark.parametrize("config", [
    {"gateway": {"mode": "routed"}, "relay": {"mode": "agent"}},
    {"gateway": {}, "relay": {"mode": "routed"}},
    {"gateway": {"mode": "unknown"}},
])
def test_invalid_modes_rejected_before_any_service_command(tmp_path, monkeypatch, config):
    monkeypatch.setattr(runtime.subprocess, "run", lambda *a, **k: pytest.fail("service command"))
    with pytest.raises(runtime.RuntimeCompatibilityError):
        runtime.reconcile_transport_roles(
            tmp_path, {"gateway": True, "relay": True}, config, deploy_dir=ROOT / "deploy",
        )


def test_routed_gateway_does_not_apply_global_wireguard_config(tmp_path, monkeypatch):
    (tmp_path / "control").mkdir()
    (tmp_path / "control" / "config.json").write_text('{"wireguard_interface":"bpcag0"}')
    record = {
        "roles": {"gateway": True, "relay": True},
        "config": {"role_config": {"gateway": {"mode": "routed"}}},
    }
    enrollment.write_local_enrollment(tmp_path, record)
    monkeypatch.setattr(enrollment, "reconcile_local_gateway_state",
                        lambda *a, **k: pytest.fail("legacy Gateway reconciliation"))
    assert not enrollment.reconcile_startup_gateway_state(tmp_path, record["roles"])
    assert enrollment.cmd_local_reconcile(SimpleNamespace(state_dir=tmp_path)) == 0


def test_routed_promotion_keeps_identity_credentials_and_controller_membership(
    tmp_path, monkeypatch,
):
    control = tmp_path / "control"
    node_id = "a" * 32
    path = control / "nodes" / f"{node_id}.json"
    path.parent.mkdir(parents=True)
    node = {"node_id": node_id, "name": "ru-01", "public_key": "original-key",
            "created_at": 123, "roles": {"controller": True}, "revoked": False}
    path.write_text(json.dumps(node))
    credentials = control / "node-credentials" / "credential.json"
    credentials.parent.mkdir()
    credentials.write_text("unchanged credentials")
    calls = []
    monkeypatch.setattr(enrollment.bpc_control_state, "cluster_enabled", lambda _: True)
    monkeypatch.setattr(enrollment, "strong_read", lambda _: None)

    def mutation(root, kind, ops):
        assert root == control and kind == "ConfigurePublicNode"
        assert len(ops) == 1 and ops[0]["path"] == path
        assert ops[0]["expected_sha256"] == enrollment.node_record_digest(path, node)
        calls.append(json.loads(ops[0]["data"]))
        path.write_bytes(ops[0]["data"])

    monkeypatch.setattr(enrollment.bpc_control_state, "mutation", mutation)
    args = enrollment.build_parser().parse_args([
        "--state-dir", str(tmp_path), "--control-dir", str(control), "node-configure",
        node_id, "--preset", "public-node", "--host", "ru-01.blinpi.ru",
        "--dataplane", "routed",
    ])
    assert enrollment.cmd_node_configure(args) == 0
    updated = calls[0]
    for key in ("node_id", "public_key", "created_at", "name"):
        assert updated[key] == node[key]
    assert updated["roles"] == {"controller": True, "gateway": True, "relay": True}
    assert updated["role_config"]["gateway"] == {"mode": "routed"}
    assert updated["endpoints"][0]["host"] == "ru-01.blinpi.ru"
    assert credentials.read_text() == "unchanged credentials"


@pytest.mark.parametrize("roles,revoked", [
    ({"controller": True, "gateway": True}, False),
    ({"site_router": True}, False),
    ({"controller": True}, True),
])
def test_promotion_rejects_revoked_unenrolled_and_compat_nodes(
    tmp_path, monkeypatch, roles, revoked,
):
    control = tmp_path / "control"
    path = control / "nodes" / f'{"a" * 32}.json'
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"node_id": "a" * 32, "roles": roles, "revoked": revoked}))
    monkeypatch.setattr(enrollment.bpc_control_state, "cluster_enabled", lambda _: True)
    monkeypatch.setattr(enrollment, "strong_read", lambda _: None)
    monkeypatch.setattr(enrollment.bpc_control_state, "mutation",
                        lambda *a, **k: pytest.fail("canonical mutation"))
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.cmd_node_configure(SimpleNamespace(
            node_id="a" * 32, host=["ru-01.blinpi.ru"], control_dir=control, state_dir=tmp_path,
        ))


@pytest.mark.parametrize("script_name", ["bpc-enable-control.sh", "bpc-enable-control-replica.sh"])
def test_actual_api_staging_imports_without_release_tree(tmp_path, script_name):
    # Execute staging commands from each real installer: no hand-maintained
    # dependency list in the test can conceal an omitted module.
    script = (ROOT / "deploy" / script_name).read_text()
    dependencies = script.split('release_control_server="', 1)[1]
    boundary = (
        "release_version=" if script_name == "bpc-enable-control.sh" else "export DEBIAN_FRONTEND"
    )
    dependencies = 'release_control_server="' + dependencies.split(boundary, 1)[0]
    # Primary has an early control_server alias immediately before staging.
    staging = script.split('runtime_version_dir="', 1)[1]
    staging = 'runtime_version_dir="' + staging.split(
        'cat > "${CONTROL_DIR}/runtime.env"', 1,
    )[0]
    if script_name == "bpc-enable-control.sh":
        # Primary performs dataplane/config mutations after staging; exclude them.
        staging = staging.split('control_server="', 1)[0]
    fake_root = tmp_path / "root"
    fake_root.mkdir()
    (fake_root / "current").symlink_to(ROOT)
    control = tmp_path / "control"
    control.mkdir()
    tools = tmp_path / "tools"
    tools.mkdir()
    # CI runs as an unprivileged user; ownership is unrelated to import staging.
    (tools / "chown").write_text("#!/bin/sh\nexit 0\n")
    (tools / "chown").chmod(0o755)
    program = 'set -euo pipefail\nrelease_version=test\n' + dependencies + staging
    result = subprocess.run(["bash", "-c", program], env={
        **os.environ, "BPC_ROOT": str(fake_root), "CONTROL_DIR": str(control),
        "PATH": str(tools) + os.pathsep + os.environ["PATH"],
    }, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    result = subprocess.run([
        sys.executable, str(control / "runtime" / "bpc-control-server.py"), "--help",
    ], cwd=tmp_path, env={**os.environ, "PYTHONPATH": ""},
        capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_controller_update_preserves_ports_and_does_not_bootstrap(tmp_path, monkeypatch):
    config = new_node_config(name="ru-01", roles={"controller": True})
    save_node_config(tmp_path / "node.yaml", config)
    marker = {"node_id": config.node.id, "raft_address": "ru-01.example:9555",
              "cluster_api_address": "ru-01.example:9557", "local_api_address": "127.0.0.1:9556"}
    for key, relative in [
        ("certificate_file", "cluster/pki/controller.crt"),
        ("key_file", "cluster/pki/controller.key"),
        ("ca_file", "cluster/pki/cluster-ca.crt"),
        ("local_api_token_file", "cluster/local-api.token"),
    ]:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"original protected bytes")
        marker[key] = str(path)
    for name in ("node.key", "node.pub"):
        path = tmp_path / "identity" / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b"original identity")
    (tmp_path / "cluster" / "controller.json").write_text(json.dumps(marker))
    calls = []
    monkeypatch.setattr(enrollment.subprocess, "run", lambda command, **kwargs:
                        calls.append(command) or SimpleNamespace(returncode=0))
    enrollment.reconcile_controller_runtime(tmp_path)
    command = calls[0]
    assert len(calls) == 1 and "--bootstrap" not in command
    assert command[command.index("--raft-port") + 1] == "9555"
    assert command[command.index("--cluster-api-port") + 1] == "9557"
    assert command[command.index("--local-api-port") + 1] == "9556"


def test_heartbeat_promotion_installs_security_without_touching_wireguard(tmp_path, monkeypatch):
    enrollment.generate_node_identity(tmp_path)
    (tmp_path / "control").mkdir()
    (tmp_path / "control" / "config.json").write_text('{"wireguard_interface":"bpcag0"}')
    node = {
        "node_id": "a" * 32, "name": "ru-01", "created_at": 123,
        "controller_url": "https://controller.example:8444", "credential": "test",
        "roles": {"controller": True}, "config": {},
    }
    response = {
        "server_time": 500, "roles": {"controller": True, "gateway": True, "relay": True},
        "config": {"role_config": {"gateway": {"mode": "routed"},
                                  "relay": {"mode": "routed"}}},
        "security_snapshot": {"revision": 10, "expires_at": 800},
        "security_snapshot_verification_key": "test-verification-key",
    }
    installed = []
    monkeypatch.setattr(enrollment, "fanout_node_telemetry", lambda *a, **k: None)
    monkeypatch.setattr(enrollment, "request_json", lambda *a, **k: response)
    monkeypatch.setattr(enrollment, "service_state", lambda _: "active")
    monkeypatch.setattr(enrollment, "install_security_snapshot", lambda state, snapshot, key:
                        installed.append((snapshot, key)) or snapshot)
    monkeypatch.setattr(enrollment, "reconcile_local_gateway_state",
                        lambda *a: pytest.fail("WireGuard reconciliation"))
    monkeypatch.setattr(enrollment, "reconcile_routed_runtime", lambda *a: None)
    enrollment.send_heartbeat(tmp_path, node)
    assert installed == [(response["security_snapshot"], "test-verification-key")]
    assert enrollment.enrolled_state(tmp_path)["security_revision"] == 10
    assert enrollment.load_node_config(tmp_path / "node.yaml").node.roles.has("gateway")


def test_expired_mesh_snapshot_stops_only_mesh_service(tmp_path, monkeypatch):
    record = {"roles": {"gateway": True, "relay": True},
              "config": {"role_config": {"gateway": {"mode": "routed"}}}}
    enrollment.write_local_enrollment(tmp_path, record)
    calls = []
    monkeypatch.setattr(enrollment, "reconcile_roles", lambda *a: None)

    def offline(*args, **kwargs):
        raise enrollment.EnrollmentError("Controller unavailable")

    def expired(*args, **kwargs):
        raise enrollment.GatewaySnapshotError("expired")

    class EndIteration(Exception):
        pass

    def stop(*args):
        raise EndIteration

    monkeypatch.setattr(enrollment, "send_heartbeat", offline)
    monkeypatch.setattr(enrollment, "load_valid_security_snapshot", expired)
    monkeypatch.setattr(enrollment.time, "sleep", stop)
    monkeypatch.setattr(enrollment.subprocess, "run", lambda command, **kwargs:
                        calls.append(command) or SimpleNamespace(returncode=0))
    with pytest.raises(EndIteration):
        enrollment.cmd_daemon(SimpleNamespace(state_dir=tmp_path))
    assert calls == [["systemctl", "stop", "bpc-routed-node.service"]]


def test_mesh_status_does_not_claim_connected_without_links(tmp_path, monkeypatch, capsys):
    enrollment.write_local_enrollment(tmp_path, {
        "name": "ru-01", "roles": {"gateway": True},
        "config": {"role_config": {"gateway": {"mode": "routed"}}},
    })
    monkeypatch.setattr(enrollment, "service_state", lambda _: "active")
    assert enrollment.cmd_status(SimpleNamespace(state_dir=tmp_path)) == 1
    assert "awaits topology links" in capsys.readouterr().out


def test_telemetry_survives_node_runtime_replacement(tmp_path):
    prepare_control_runtime(tmp_path, Path("/opt/bpc"), systemd_dir=tmp_path / "units")
    control = tmp_path / "control"
    control.mkdir()
    topology.write_node_telemetry(
        control, "a" * 32, payload={"status": "online"}, compatibility="compatible", now=123,
    )
    before = topology.node_telemetry_path(control, "a" * 32).read_bytes()
    enrollment.stage_node_runtime(tmp_path)
    enrollment.stage_node_runtime(tmp_path)
    assert topology.node_telemetry_path(control, "a" * 32).read_bytes() == before
    assert topology.telemetry_root(control) == tmp_path / "runtime-topology"


def test_runtime_preparation_removes_only_exact_temporary_repairs(tmp_path):
    units = tmp_path / "units"
    dropins = units / "bpc-control.service.d"
    dropins.mkdir(parents=True)
    legacy = dropins / "30-topology-runtime.conf"
    legacy.write_text(f"[Service]\nReadWritePaths={tmp_path}/runtime/topology\n")
    modified = dropins / "40-topology-module.conf"
    modified.write_text("user-maintained configuration\n")
    other = dropins / "50-user.conf"
    other.write_text("[Service]\nEnvironment=USER_SETTING=1\n")
    prepare_control_runtime(tmp_path, Path("/opt/bpc"), systemd_dir=units)
    assert not legacy.exists()
    assert modified.read_text() == "user-maintained configuration\n"
    assert other.read_text() == "[Service]\nEnvironment=USER_SETTING=1\n"
    assert (tmp_path / "runtime-topology").stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("mode,keys,expected", [
    ("primary", False, 1), ("primary", True, 0), ("replica", False, 0),
])
def test_replica_health_does_not_require_primary_update_signing_keys(
    tmp_path, mode, keys, expected,
):
    control = tmp_path / "control"
    control.mkdir()
    for name in ("enabled", "config.json", "certificate.pem", "key.pem"):
        (control / name).write_text("test")
    if keys:
        for name in ("update-signing-key.pem", "update-signing-public.pem"):
            (control / name).write_text("test update key")
    (control / "runtime.env").write_text(
        f"CONTROL_MODE={mode}\nCONTROL_CERT={control}/certificate.pem\n"
        f"CONTROL_KEY={control}/key.pem\nCONTROL_PORT=8444\n"
    )
    script = (ROOT / "deploy" / "bpc-healthcheck.sh").read_text()
    check = "check_control() {" + script.split("check_control() {", 1)[1].split(
        '\ngateway_config="', 1,
    )[0]
    program = (
        "set -euo pipefail\n"
        "fail_health() { return 1; }\n"
        "systemctl() { return 0; }\n"
        "ss() { echo LISTEN; }\n" + check + "\ncheck_control\n"
    )
    result = subprocess.run(["bash", "-c", program], check=False,
                            env={**os.environ, "BPC_STATE_DIR": str(tmp_path)},
                            capture_output=True, text=True)
    assert result.returncode == expected, result.stderr
