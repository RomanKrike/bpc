from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "deploy"))

from bpc_gateway_snapshot import (  # noqa: E402
    GatewaySnapshotError,
    build_security_snapshot,
    install_security_snapshot,
    snapshot_allows_device,
    snapshot_contains_sensitive_auth_db,
    verify_security_snapshot,
)


def seed_cluster(state_root: Path) -> None:
    cluster = state_root / "cluster"
    pki = cluster / "pki"
    pki.mkdir(parents=True)
    key = Ed25519PrivateKey.generate()
    now = datetime.now(tz=UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "BPC snapshot test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, algorithm=None)
    )
    (pki / "cluster-ca.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(pki / "cluster-ca.key", 0o600)
    (pki / "cluster-ca.crt").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )
    (cluster / "cluster.json").write_text(
        json.dumps({"version": 1, "cluster_id": "cluster-test"}),
        encoding="utf-8",
    )
    members = cluster / "controllers"
    members.mkdir()
    (members / f"{'a' * 32}.json").write_text(
        json.dumps(
            {
                "node_id": "a" * 32,
                "state": "voter",
                "public_url": "https://controller-a.example:8444",
            }
        ),
        encoding="utf-8",
    )


def write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def seed_security_state(control: Path) -> None:
    write_json(
        control / "devices" / "d1.json",
        {
            "id": "d1",
            "user_id": "u1",
            "name": "pc004",
            "public_key": "device-public",
            "wireguard_public_key": "wg-public",
            "wireguard_address": "10.253.0.2/32",
            "wgshim_psk": "transport-secret-required-by-gateway",
            "enabled": True,
            "revoked": False,
            "revoked_at": None,
        },
    )
    write_json(
        control / "devices" / "d2.json",
        {
            "id": "d2",
            "user_id": "u1",
            "name": "old-pc",
            "public_key": "old-public",
            "enabled": False,
            "revoked": True,
            "revoked_at": 990,
        },
    )
    write_json(
        control / "access" / "device-d1.json",
        {
            "version": 1,
            "subject_type": "device",
            "subject_id": "d1",
            "allow": ["192.168.88.0/24"],
            "deny": [],
        },
    )
    write_json(
        control / "routes" / "r1.json",
        {
            "version": 1,
            "cidr": "192.168.88.0/24",
            "node_id": "site-1",
        },
    )
    write_json(
        control / "revocations" / "device-d2.json",
        {
            "version": 1,
            "kind": "device",
            "subject_id": "d2",
            "revoked_at": 990,
        },
    )
    write_json(
        control / "nodes" / "site-1.json",
        {
            "node_id": "site-1",
            "public_key": "node-public",
            "roles": {"site_router": True},
            "revoked": False,
        },
    )

    # Controller-only sensitive state deliberately exists next to the source
    # state. The Gateway snapshot builder must never traverse it.
    write_json(
        control / "identity" / "users" / "u1.json",
        {
            "id": "u1",
            "username": "roman",
            "password_hash": "$argon2id$DO-NOT-LEAK",
        },
    )
    write_json(
        control / "identity" / "refresh" / "secret.json",
        {
            "user_id": "u1",
            "refresh_token": "DO-NOT-LEAK",
        },
    )


def test_signed_gateway_snapshot_excludes_sensitive_auth_db(tmp_path: Path) -> None:
    seed_cluster(tmp_path)
    control = tmp_path / "control"
    seed_security_state(control)

    snapshot, verification_key = build_security_snapshot(
        control,
        revision=7,
        now=1_000,
        valid_for=300,
    )

    assert snapshot["revision"] == 7
    assert snapshot["cluster_id"] == "cluster-test"
    assert snapshot_contains_sensitive_auth_db(snapshot) is False
    encoded = json.dumps(snapshot, sort_keys=True)
    assert "DO-NOT-LEAK" not in encoded
    assert "password_hash" not in encoded
    assert "refresh_token" not in encoded

    verify_security_snapshot(
        snapshot,
        verification_key,
        expected_cluster_id="cluster-test",
        min_revision=7,
        now=1_100,
    )
    assert snapshot_allows_device(snapshot, "d1", now=1_100) is True
    assert snapshot_allows_device(snapshot, "d2", now=1_100) is False
    assert snapshot_allows_device(snapshot, "unknown", now=1_100) is False

    tampered = json.loads(json.dumps(snapshot))
    tampered["access"][0]["allow"] = ["0.0.0.0/0"]
    with pytest.raises(GatewaySnapshotError, match="signature"):
        verify_security_snapshot(tampered, verification_key, now=1_100)

    with pytest.raises(GatewaySnapshotError, match="expired"):
        verify_security_snapshot(snapshot, verification_key, now=1_301)


def test_gateway_snapshot_install_rejects_revision_rollback(tmp_path: Path) -> None:
    controller = tmp_path / "controller"
    seed_cluster(controller)
    control = controller / "control"
    seed_security_state(control)

    current, verification_key = build_security_snapshot(
        control,
        revision=10,
        now=2_000,
        valid_for=300,
    )
    older, _ = build_security_snapshot(
        control,
        revision=9,
        now=2_001,
        valid_for=300,
    )

    gateway = tmp_path / "gateway"
    install_security_snapshot(gateway, current, verification_key, now=2_010)
    with pytest.raises(GatewaySnapshotError, match="rollback"):
        install_security_snapshot(gateway, older, verification_key, now=2_020)
