from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "deploy"))

import bpc_node_enrollment as enrollment  # noqa: E402


def test_join_token_is_one_time_and_secret_is_not_stored(tmp_path: Path) -> None:
    control = tmp_path / "control"
    token = enrollment.create_join_token(
        control,
        controller_url="https://controller.example:8444",
        roles=["gateway", "relay"],
        name="ge-02",
        expires_in=900,
        role_config={
            "gateway": {"reality_server_name": "www.bing.com", "xray_port": 443},
            "relay": {"mode": "agent"},
        },
        now=100,
    )
    _, secret = enrollment.parse_join_token(token)

    stored = list((control / "node-join").glob("*.json"))
    assert len(stored) == 1
    assert secret not in stored[0].read_text(encoding="utf-8")
    assert oct(stored[0].stat().st_mode & 0o777) == "0o600"

    public_key = base64.b64encode(b"node-public-key-material-32bytes!!").decode("ascii")
    joined = enrollment.enroll_node(
        control,
        token=token,
        public_key=public_key,
        presented_name="ignored-hostname",
        now=110,
    )

    assert joined["name"] == "ge-02"
    assert joined["roles"] == {"gateway": True, "relay": True}
    assert len(joined["credential"]) == 64
    assert not (control / "node-join" / f"{enrollment.token_index(secret)}.json").exists()

    with pytest.raises(enrollment.EnrollmentError, match="already been used") as replay:
        enrollment.enroll_node(
            control,
            token=token,
            public_key=public_key,
            presented_name="ge-02",
            now=111,
        )
    assert replay.value.status == 409


def test_enrollment_end_to_end_join_heartbeat_list_leave(tmp_path: Path) -> None:
    control = tmp_path / "control"
    token = enrollment.create_join_token(
        control,
        controller_url="https://controller.example:8444",
        roles=["gateway", "relay"],
        name="ge-02",
        expires_in=900,
        now=1_000,
    )
    public_key = base64.b64encode(os.urandom(44)).decode("ascii")

    joined = enrollment.enroll_node(
        control,
        token=token,
        public_key=public_key,
        presented_name="fresh-vps",
        now=1_010,
    )
    heartbeat = enrollment.node_heartbeat(
        control,
        credential=str(joined["credential"]),
        payload={
            "status": "online",
            "version": "0.15.0",
            "protocol_version": 1,
            "state_schema_version": 1,
            "services": {"gateway": "active", "relay": "active"},
            "transport": {
                "udp_ports": [24444, 24445, 24444, 80],
                "tcp_port": 24444,
                "overlay_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            },
        },
        now=1_020,
    )

    assert heartbeat["ok"] is True
    assert heartbeat["node_id"] == joined["node_id"]
    assert heartbeat["roles"] == {"gateway": True, "relay": True}

    nodes = enrollment.list_nodes(control, now=1_040)
    assert len(nodes) == 1
    assert nodes[0]["online"] is True
    assert nodes[0]["last_seen"] == 1_020
    assert nodes[0]["services"] == {"gateway": "active", "relay": "active"}
    assert nodes[0]["transport"] == {
        "udp_ports": [24444, 24445],
        "tcp_port": 24444,
        "overlay_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    }
    assert nodes[0]["compatibility"] == "compatible"

    left = enrollment.leave_node(
        control,
        credential=str(joined["credential"]),
        now=1_050,
    )
    assert left == {"ok": True, "node_id": joined["node_id"]}

    nodes = enrollment.list_nodes(control, now=1_051)
    assert nodes[0]["revoked"] is True
    assert nodes[0]["online"] is False

    with pytest.raises(enrollment.EnrollmentError) as unauthorized:
        enrollment.node_heartbeat(
            control,
            credential=str(joined["credential"]),
            payload={"status": "online"},
            now=1_060,
        )
    assert unauthorized.value.status == 401


def test_expired_token_is_rejected_and_tombstoned(tmp_path: Path) -> None:
    control = tmp_path / "control"
    token = enrollment.create_join_token(
        control,
        controller_url="https://controller.example:8444",
        roles=["relay"],
        expires_in=10,
        now=2_000,
    )
    _, secret = enrollment.parse_join_token(token)

    with pytest.raises(enrollment.EnrollmentError, match="expired") as expired:
        enrollment.enroll_node(
            control,
            token=token,
            public_key=base64.b64encode(os.urandom(44)).decode("ascii"),
            presented_name="relay-01",
            now=2_011,
        )

    assert expired.value.status == 401
    assert (control / "node-join-used" / f"{enrollment.token_index(secret)}.json").is_file()


def test_duplicate_active_node_identity_is_rejected(tmp_path: Path) -> None:
    control = tmp_path / "control"
    public_key = base64.b64encode(os.urandom(44)).decode("ascii")
    first = enrollment.create_join_token(
        control,
        controller_url="https://controller.example:8444",
        roles=["gateway"],
        expires_in=900,
        now=3_000,
    )
    enrollment.enroll_node(
        control,
        token=first,
        public_key=public_key,
        presented_name="node-a",
        now=3_001,
    )

    second = enrollment.create_join_token(
        control,
        controller_url="https://controller.example:8444",
        roles=["relay"],
        expires_in=900,
        now=3_002,
    )
    with pytest.raises(enrollment.EnrollmentError, match="duplicate node identity") as duplicate:
        enrollment.enroll_node(
            control,
            token=second,
            public_key=public_key,
            presented_name="node-b",
            now=3_003,
        )
    assert duplicate.value.status == 409


def test_apply_remote_node_config_uses_controller_id_and_roles(tmp_path: Path) -> None:
    public_key = base64.b64encode(os.urandom(44)).decode("ascii")
    enrollment.apply_remote_node_config(
        tmp_path,
        node_id="controller-assigned-id",
        name="ge-02",
        public_key=public_key,
        roles={"gateway": True, "relay": True},
        created_at=4_000,
        last_seen=4_010,
    )

    from bpc_connect.node import load_node_config

    config = load_node_config(tmp_path / "node.yaml")
    assert config.node.id == "controller-assigned-id"
    assert config.node.public_key == public_key
    assert config.node.roles.has("gateway")
    assert config.node.roles.has("relay")
    assert not config.node.roles.has("controller")
    assert oct((tmp_path / "node.yaml").stat().st_mode & 0o777) == "0o600"


def test_node_identity_is_idempotent_and_private(tmp_path: Path) -> None:
    first_public = enrollment.generate_node_identity(tmp_path)
    private_path = tmp_path / "identity" / "node.key"
    first_private = private_path.read_bytes()

    second_public = enrollment.generate_node_identity(tmp_path)

    assert second_public == first_public
    assert private_path.read_bytes() == first_private
    assert oct((tmp_path / "identity").stat().st_mode & 0o777) == "0o700"
    assert oct(private_path.stat().st_mode & 0o777) == "0o600"


def test_repeated_join_is_safe_noop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    existing = {
        "version": 1,
        "controller_url": "https://controller.example:8444",
        "node_id": "existing-node-id",
        "name": "ge-02",
        "credential": "a" * 64,
        "roles": {"gateway": True, "relay": True},
        "config": {},
    }
    enrollment.write_local_enrollment(tmp_path, existing)
    before = (tmp_path / "enrollment.json").read_bytes()
    monkeypatch.setattr(enrollment.os, "geteuid", lambda: 0)
    reconciled: list[dict[str, object]] = []
    monkeypatch.setattr(
        enrollment,
        "reconcile_roles",
        lambda _state, roles, _config: (
            reconciled.append(dict(roles)) or dict.fromkeys(roles, "active")
        ),
    )
    monkeypatch.setattr(enrollment, "install_runtime_service", lambda _state: None)
    monkeypatch.setattr(
        enrollment,
        "send_heartbeat",
        lambda _state, _existing: {"ok": True},
    )

    args = enrollment.argparse.Namespace(
        state_dir=tmp_path,
        token=enrollment.make_join_token(
            "https://another-controller.example:8444",
            "b" * 64,
        ),
    )
    assert enrollment.cmd_join(args) == 0

    assert (tmp_path / "enrollment.json").read_bytes() == before
    assert reconciled == [{"gateway": True, "relay": True}]


def test_staged_node_runtime_is_self_contained(tmp_path: Path) -> None:
    runtime = enrollment.stage_node_runtime(tmp_path)

    assert runtime.is_symlink()
    assert (runtime / "VERSION").is_file()
    assert (runtime / "deploy" / "bpc_node_enrollment.py").is_file()
    assert (runtime / "src" / "bpc_connect" / "node.py").is_file()

    import subprocess

    completed = subprocess.run(
        [
            sys.executable,
            str(runtime / "deploy" / "bpc_node_enrollment.py"),
            "--help",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "BPC Node enrollment" in completed.stdout


def test_cluster_join_token_contains_multiple_controller_endpoints(tmp_path: Path) -> None:
    state = tmp_path
    control = state / "control"
    (state / "cluster" / "controllers").mkdir(parents=True)
    for index, host in enumerate(("a.example", "b.example"), start=1):
        (state / "cluster" / "controllers" / f"{index:032x}.json").write_text(
            json.dumps(
                {
                    "node_id": f"{index:032x}",
                    "state": "voter",
                    "public_url": f"https://{host}:8444",
                }
            ),
            encoding="utf-8",
        )

    token = enrollment.create_join_token(
        control,
        controller_url="https://a.example:8444",
        roles=["relay"],
        now=5_000,
    )
    controllers, _ = enrollment.parse_join_token_endpoints(token)
    assert controllers == [
        "https://a.example:8444",
        "https://b.example:8444",
    ]


def test_site_router_heartbeat_owns_canonical_routes(tmp_path: Path) -> None:
    control = tmp_path / "control"
    token = enrollment.create_join_token(
        control,
        controller_url="https://controller.example:8444",
        roles=["site_router"],
        advertised_routes=["192.168.88.0/24", "10.10.0.0/16"],
        now=6_000,
    )
    joined = enrollment.enroll_node(
        control,
        token=token,
        public_key=base64.b64encode(os.urandom(44)).decode("ascii"),
        presented_name="site-01",
        now=6_001,
    )

    response = enrollment.node_heartbeat(
        control,
        credential=str(joined["credential"]),
        payload={
            "status": "online",
            "version": "0.18.0",
            "protocol_version": 1,
            "state_schema_version": 1,
            "advertised_routes": ["192.168.88.0/24"],
        },
        now=6_010,
    )
    assert response["compatibility"] == "compatible"
    routes = list((control / "routes").glob("*.json"))
    assert len(routes) == 1
    record = json.loads(routes[0].read_text(encoding="utf-8"))
    assert record["cidr"] == "192.168.88.0/24"
    assert record["node_id"] == joined["node_id"]
    assert record["owner_node_id"] == joined["node_id"]

    enrollment.node_heartbeat(
        control,
        credential=str(joined["credential"]),
        payload={
            "status": "online",
            "version": "0.18.0",
            "protocol_version": 1,
            "state_schema_version": 1,
            "advertised_routes": ["10.10.0.0/16"],
        },
        now=6_020,
    )
    records = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (control / "routes").glob("*.json")
    ]
    assert [item["cidr"] for item in records] == ["10.10.0.0/16"]


def test_node_heartbeat_marks_incompatible_protocol(tmp_path: Path) -> None:
    control = tmp_path / "control"
    token = enrollment.create_join_token(
        control,
        controller_url="https://controller.example:8444",
        roles=["relay"],
        now=7_000,
    )
    joined = enrollment.enroll_node(
        control,
        token=token,
        public_key=base64.b64encode(os.urandom(44)).decode("ascii"),
        presented_name="relay-01",
        now=7_001,
    )
    response = enrollment.node_heartbeat(
        control,
        credential=str(joined["credential"]),
        payload={
            "status": "online",
            "version": "99.0.0",
            "protocol_version": 99,
            "state_schema_version": 99,
        },
        now=7_010,
    )
    assert response["compatibility"] == "incompatible"
    node = enrollment.list_nodes(control, now=7_011)[0]
    assert node["protocol_version"] == 99
    assert node["state_schema_version"] == 99
    assert node["compatibility"] == "incompatible"


def test_public_nodes_have_independent_canonical_endpoints(tmp_path):
    control = tmp_path / "control"
    for name in ("ru-01", "ru-02", "home-01"):
        endpoints = [] if name == "home-01" else [{"host": f"{name}.blinpi.ru"}]
        token = enrollment.create_join_token(
            control, controller_url="https://ru-01.blinpi.ru:8444",
            roles=["site_router"], name=name, endpoints=endpoints,
        )
        joined = enrollment.enroll_node(
            control, token=token, public_key=base64.b64encode(os.urandom(32)).decode(),
            presented_name="ignored",
        )
        expected = (
            [{"host": f"{name}.blinpi.ru", "public": True, "enabled": True}] if endpoints else []
        )
        assert joined["config"]["endpoints"] == expected
        record = enrollment.read_json(control / "nodes" / f'{joined["node_id"]}.json')
        assert record["endpoints"] == expected
        response = enrollment.node_heartbeat(
            control, credential=joined["credential"],
            payload={"endpoints": [{"host": "attacker.invalid"}]},
        )
        assert response["config"]["endpoints"] == expected
    assert len(enrollment.list_nodes(control)) == 3


def test_local_gateway_reconcile_applies_replicated_state_without_heartbeat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enrollment.write_local_enrollment(
        tmp_path,
        {
            "version": 1,
            "controller_url": "https://controller.example:8444",
            "node_id": "gateway-node",
            "name": "ru-02",
            "credential": "a" * 64,
            "roles": {"gateway": True, "relay": True},
            "config": {},
        },
    )
    control = tmp_path / "control"
    control.mkdir(parents=True)
    (control / "config.json").write_text("{}", encoding="utf-8")
    calls: list[str] = []
    monkeypatch.setattr(
        enrollment,
        "reconcile_gateway_dataplane",
        lambda state: calls.append(f"dataplane:{state}"),
    )
    monkeypatch.setattr(
        enrollment,
        "sync_access_firewall",
        lambda state: calls.append(f"access:{state}"),
    )

    args = enrollment.argparse.Namespace(state_dir=tmp_path)
    assert enrollment.cmd_local_reconcile(args) == 0
    assert calls == [
        f"dataplane:{tmp_path}",
        f"access:{control}",
    ]
    lock_path = tmp_path / "gateway-reconcile.lock"
    assert lock_path.is_file()
    assert oct(lock_path.stat().st_mode & 0o777) == "0o600"


def test_local_reconcile_is_noop_for_non_gateway_node(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enrollment.write_local_enrollment(
        tmp_path,
        {
            "version": 1,
            "controller_url": "https://controller.example:8444",
            "node_id": "relay-node",
            "name": "relay-01",
            "credential": "a" * 64,
            "roles": {"relay": True},
            "config": {},
        },
    )
    monkeypatch.setattr(
        enrollment,
        "reconcile_gateway_dataplane",
        lambda _state: pytest.fail("non-gateway reconciled dataplane"),
    )
    monkeypatch.setattr(
        enrollment,
        "sync_access_firewall",
        lambda _state: pytest.fail("non-gateway reconciled Access"),
    )

    args = enrollment.argparse.Namespace(state_dir=tmp_path)
    assert enrollment.cmd_local_reconcile(args) == 0


def test_gateway_startup_reconciles_replicated_state_before_heartbeat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = tmp_path / "control"
    control.mkdir()
    (control / "config.json").write_text("{}", encoding="utf-8")
    calls: list[Path] = []
    monkeypatch.setattr(
        enrollment,
        "reconcile_local_gateway_state",
        lambda state: calls.append(state),
    )

    assert enrollment.reconcile_startup_gateway_state(
        tmp_path,
        {"controller": True, "gateway": True, "relay": True},
    )
    assert calls == [tmp_path]


def test_gateway_startup_reconcile_is_noop_without_gateway_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        enrollment,
        "reconcile_local_gateway_state",
        lambda _state: pytest.fail("unexpected startup gateway reconcile"),
    )
    assert not enrollment.reconcile_startup_gateway_state(
        tmp_path,
        {"controller": True, "relay": True},
    )
    assert not enrollment.reconcile_startup_gateway_state(
        tmp_path,
        {"gateway": True, "relay": True},
    )


def test_gateway_startup_reconcile_failure_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = tmp_path / "control"
    control.mkdir()
    (control / "config.json").write_text("{}", encoding="utf-8")

    def fail(_state: Path) -> None:
        raise enrollment.GatewayDataplaneError("wg interface not ready")

    monkeypatch.setattr(enrollment, "reconcile_local_gateway_state", fail)
    with pytest.raises(enrollment.EnrollmentError, match="startup dataplane"):
        enrollment.reconcile_startup_gateway_state(
            tmp_path,
            {"gateway": True, "relay": True},
        )


def test_site_router_cannot_expand_invitation_route_policy(tmp_path: Path) -> None:
    control = tmp_path / "control"
    token = enrollment.create_join_token(
        control, controller_url="https://controller.example:8444",
        roles=["site_router"], advertised_routes=["192.168.88.0/24"], now=100,
    )
    joined = enrollment.enroll_node(
        control, token=token, public_key=base64.b64encode(os.urandom(44)).decode(),
        presented_name="home-01", now=101,
    )
    with pytest.raises(enrollment.EnrollmentError, match="route policy") as error:
        enrollment.node_heartbeat(
            control, credential=joined["credential"], now=102,
            payload={"advertised_routes": ["10.0.0.0/8"], "authorized_routes": ["10.0.0.0/8"]},
        )
    assert error.value.status == 403
    assert not list((control / "routes").glob("*.json"))


def test_legacy_site_route_policy_freezes_and_admin_can_extend(tmp_path: Path) -> None:
    control = tmp_path / "control"
    token = enrollment.create_join_token(
        control, controller_url="https://controller.example:8444",
        roles=["site_router"], advertised_routes=["192.168.88.0/24"], now=100,
    )
    joined = enrollment.enroll_node(
        control, token=token, public_key=base64.b64encode(os.urandom(44)).decode(),
        presented_name="home-01", now=101,
    )
    path = control / "nodes" / f"{joined['node_id']}.json"
    node = enrollment.read_json(path)
    node.pop("authorized_routes")
    enrollment.atomic_json(path, node)
    # Withdrawal does not erase the upgrade-time grant or allow its expansion.
    enrollment.node_heartbeat(control, credential=joined["credential"], payload={}, now=102)
    assert enrollment.read_json(path)["authorized_routes"] == ["192.168.88.0/24"]
    enrollment.node_heartbeat(control, credential=joined["credential"],
                              payload={"advertised_routes": ["192.168.88.128/25"]}, now=103)
    with pytest.raises(enrollment.EnrollmentError, match="route policy"):
        enrollment.node_heartbeat(control, credential=joined["credential"],
                                  payload={"advertised_routes": ["10.10.0.0/16"]}, now=104)
    enrollment.authorize_site_routes(control, joined["node_id"], ["10.10.0.0/16"])
    enrollment.node_heartbeat(control, credential=joined["credential"],
                              payload={"advertised_routes": ["10.10.0.0/16"]}, now=105)
    assert enrollment.read_json(path)["node_id"] == joined["node_id"]
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.authorize_site_routes(control, joined["node_id"], ["0.0.0.0/0"])


def test_status_does_not_report_connected_after_policy_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    import argparse

    monkeypatch.setattr(enrollment, "enrolled_state", lambda _: {
        "roles": {"site_router": True},
        "config": {"routing": {"links": [{"id": "uplink"}], "policy_expires_at": 100}},
    })
    monkeypatch.setattr(enrollment, "service_state", lambda _: "active")
    assert enrollment.cmd_status(argparse.Namespace(state_dir=tmp_path)) == 1
    assert "Not connected (routed policy expired" in capsys.readouterr().out


@pytest.mark.parametrize("changed", [False, True])
def test_routed_update_restarts_only_changed_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: bool,
) -> None:
    running = tmp_path / "running"
    target = tmp_path / "target"
    running.write_bytes(b"old executable")
    target.write_bytes(b"new executable" if changed else b"old executable")
    monkeypatch.setattr(enrollment, "running_routed_executable", lambda: running)
    monkeypatch.setattr(enrollment, "_routed_binary", lambda: target)
    commands = []
    monkeypatch.setattr(enrollment.subprocess, "run", lambda cmd, **kw: commands.append(cmd))
    assert enrollment.restart_changed_routed_runtime() is changed
    assert commands == ([["systemctl", "restart", "bpc-routed-node.service"]] if changed else [])


def test_runtime_install_writes_valid_sysctl_and_keeps_enrollment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    joined = {"node_id": "existing", "roles": {"site_router": True},
              "config": {"routing": {"links": [{"id": "existing-uplink"}]}}}
    enrollment.atomic_json(state / "enrollment.json", joined)
    before = (state / "enrollment.json").read_bytes()
    monkeypatch.setattr(enrollment, "stage_node_runtime", lambda _: state / "runtime")
    monkeypatch.setattr(enrollment, "_routed_binary", lambda: tmp_path / "binary")
    # Redirect privileged files and subprocesses; run the actual install flow.
    def redirect(path: object) -> Path:
        value = str(path)
        result = tmp_path / value.lstrip("/") if value.startswith("/etc/") else Path(value)
        result.parent.mkdir(parents=True, exist_ok=True)
        return result

    monkeypatch.setattr(enrollment, "Path", redirect)
    commands = []
    monkeypatch.setattr(enrollment.subprocess, "run", lambda cmd, **kw: commands.append(cmd))
    inspected = []
    monkeypatch.setattr(
        enrollment, "restart_changed_routed_runtime", lambda: inspected.append(True),
    )
    enrollment.install_runtime_service(state)
    assert (tmp_path / "etc/sysctl.d/93-bpc-routed.conf").read_bytes() == b"net.ipv4.ip_forward=1\n"
    assert ["sysctl", "-q", "-p", str(tmp_path / "etc/sysctl.d/93-bpc-routed.conf")] in commands
    assert inspected == [True]
    assert (state / "enrollment.json").read_bytes() == before
