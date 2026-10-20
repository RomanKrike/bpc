"""Synthetic P2P state shared by unit and real Controller process acceptance."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def seed_p2p(root: Path, *, ca_key=None, ca_cert=None, cluster_id="p2p-test") -> dict:
    control = root / "control"
    cluster = root / "cluster"
    cluster.mkdir(parents=True, exist_ok=True)
    write_json(cluster / "cluster.json", {"version": 1, "cluster_id": cluster_id})
    write_json(cluster / "controller.json", {})
    if ca_key is None:
        ca_key = Ed25519PrivateKey.generate()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "P2P ephemeral test")])
        now = datetime.now(UTC)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, None)
        )
    pki = cluster / "pki"
    pki.mkdir(exist_ok=True)
    (pki / "cluster-ca.key").write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (pki / "cluster-ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    write_json(control / "config.json", {"p2p_enabled": True})
    owner = "c" * 32
    write_json(
        control / "identity" / "users" / f"{owner}.json",
        {
            "id": owner,
            "enabled": True,
            "password_hash": "synthetic-not-a-real-password-hash",
        },
    )
    devices, keys, tokens = [], [], []
    for index, device_id in enumerate(("a" * 32, "b" * 32)):
        private = Ed25519PrivateKey.generate()
        public = base64.b64encode(
            private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        ).decode()
        device = {
            "id": device_id,
            "user_id": owner,
            "enabled": True,
            "revoked": False,
            "revoked_at": None,
            "public_key": public,
            "wireguard_public_key": base64.b64encode(secrets.token_bytes(32)).decode(),
            "wireguard_address": f"10.253.0.{index + 2}/32",
        }
        write_json(control / "devices" / f"{device_id}.json", device)
        write_json(
            control / "access" / f"device-{device_id}.json",
            {
                "version": 1,
                "subject_type": "device",
                "subject_id": device_id,
                "allow": ["10.253.0.3/32"] if index == 0 else [],
                "deny": [],
                "p2p_enabled": True,
            },
        )
        token = secrets.token_hex(32)
        write_json(
            control / "identity" / "access" / f"{hashlib.sha256(token.encode()).hexdigest()}.json",
            {
                "version": 1,
                "scope": "device",
                "device_id": device_id,
                "user_id": owner,
                "created_at": int(time.time()),
                "expires_at": int(time.time()) + 600,
            },
        )
        devices.append(device)
        keys.append(private)
        tokens.append(token)
    return {
        "control": control,
        "owner": owner,
        "devices": devices,
        "keys": keys,
        "tokens": tokens,
        "ca_key": ca_key,
    }
