from __future__ import annotations

import base64
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
            "services": {"gateway": "active", "relay": "active"},
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
        lambda _state, roles, _config: reconciled.append(dict(roles)) or {},
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
