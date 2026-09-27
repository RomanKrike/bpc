from __future__ import annotations

import base64
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SNAPSHOT_VERSION = 1
DEFAULT_VALID_FOR = 300
MIN_VALID_FOR = 30
MAX_VALID_FOR = 3600
DOMAIN = b"bpc-gateway-security-snapshot-v1\n"

_SENSITIVE_KEYS = {
    "password",
    "password_hash",
    "password_hashes",
    "refresh_token",
    "refresh_tokens",
    "refresh_credential",
    "refresh_credentials",
    "two_factor_secret",
    "2fa_secret",
    "controller_private_key",
    "private_key",
    "join_token",
    "join_token_secret",
}


class GatewaySnapshotError(RuntimeError):
    pass


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise GatewaySnapshotError(f"{path} does not contain a JSON object")
    return value


def _atomic_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _safe_records(directory: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not directory.is_dir():
        return records
    for path in sorted(directory.glob("*.json")):
        try:
            records.append(_read_json(path))
        except (OSError, ValueError, json.JSONDecodeError, GatewaySnapshotError):
            continue
    return records


def _device_view(device: dict[str, Any]) -> dict[str, Any]:
    device_id = str(device.get("id", device.get("device_id", ""))).strip()
    if not device_id:
        raise GatewaySnapshotError("Device record is missing id")
    return {
        "id": device_id,
        "user_id": str(device.get("user_id", "")),
        "name": str(device.get("name", device.get("device", "")))[:64],
        "public_key": str(device.get("public_key", "")),
        "wireguard_public_key": str(device.get("wireguard_public_key", "")),
        "wireguard_address": str(device.get("wireguard_address", "")),
        "wgshim_psk": str(device.get("wgshim_psk", "")),
        "enabled": bool(device.get("enabled", True)),
        "revoked": bool(device.get("revoked", False)),
        "revoked_at": device.get("revoked_at"),
    }


def _node_view(node: dict[str, Any]) -> dict[str, Any]:
    roles = node.get("roles", {})
    if not isinstance(roles, dict):
        roles = {}
    return {
        "node_id": str(node.get("node_id", node.get("id", ""))),
        "public_key": str(node.get("public_key", "")),
        "roles": {
            str(role): bool(enabled)
            for role, enabled in roles.items()
            if bool(enabled)
        },
        "revoked": bool(node.get("revoked", False)),
    }


def _assert_no_sensitive_state(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).casefold()
            if normalized in _SENSITIVE_KEYS:
                raise GatewaySnapshotError(
                    f"sensitive Controller-only state leaked into Gateway snapshot: "
                    f"{path}.{key}"
                )
            _assert_no_sensitive_state(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_no_sensitive_state(nested, f"{path}[{index}]")


def _signing_bytes(snapshot: dict[str, Any]) -> bytes:
    unsigned = dict(snapshot)
    unsigned.pop("signature", None)
    return DOMAIN + json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _cluster_signing_identity(
    state_root: Path,
) -> tuple[Ed25519PrivateKey, str, str]:
    pki = state_root / "cluster" / "pki"
    try:
        private = serialization.load_pem_private_key(
            (pki / "cluster-ca.key").read_bytes(),
            password=None,
        )
        certificate = x509.load_pem_x509_certificate(
            (pki / "cluster-ca.crt").read_bytes()
        )
    except OSError as exc:
        raise GatewaySnapshotError("cluster signing identity is unavailable") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise GatewaySnapshotError("cluster signing key is not Ed25519")
    public = certificate.public_key()
    if not isinstance(public, Ed25519PublicKey):
        raise GatewaySnapshotError("cluster signing certificate is not Ed25519")
    private_public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    cert_public = public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if private_public != cert_public:
        raise GatewaySnapshotError("cluster signing certificate/key mismatch")

    digest = hashes.Hash(hashes.SHA256())
    digest.update(certificate.public_bytes(serialization.Encoding.DER))
    key_id = digest.finalize().hex()
    return private, base64.b64encode(cert_public).decode("ascii"), key_id


def controller_public_urls(state_root: Path) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for record in _safe_records(state_root / "cluster" / "controllers"):
        if str(record.get("state", "")) == "revoked":
            continue
        value = str(record.get("public_url", "")).strip().rstrip("/")
        if not value.startswith("https://") or value in seen:
            continue
        seen.add(value)
        urls.append(value)
    return sorted(urls)


def build_security_snapshot(
    control_dir: Path,
    *,
    revision: int,
    now: int | None = None,
    valid_for: int = DEFAULT_VALID_FOR,
) -> tuple[dict[str, Any], str]:
    if revision < 0:
        raise GatewaySnapshotError("snapshot revision cannot be negative")
    if not MIN_VALID_FOR <= valid_for <= MAX_VALID_FOR:
        raise GatewaySnapshotError("invalid Gateway snapshot validity window")

    state_root = control_dir.parent
    cluster = _read_json(state_root / "cluster" / "cluster.json")
    cluster_id = str(cluster.get("cluster_id", "")).strip()
    if not cluster_id:
        raise GatewaySnapshotError("cluster_id is missing")

    timestamp = int(time.time()) if now is None else int(now)
    devices: list[dict[str, Any]] = []
    for record in _safe_records(control_dir / "devices"):
        try:
            devices.append(_device_view(record))
        except GatewaySnapshotError:
            continue

    snapshot: dict[str, Any] = {
        "snapshot_version": SNAPSHOT_VERSION,
        "state_schema_version": 1,
        "cluster_id": cluster_id,
        "revision": int(revision),
        "created_at": timestamp,
        "expires_at": timestamp + int(valid_for),
        "devices": devices,
        "access": _safe_records(control_dir / "access"),
        "routes": _safe_records(control_dir / "routes"),
        "revocations": _safe_records(control_dir / "revocations"),
        "node_trust": [
            _node_view(item)
            for item in _safe_records(control_dir / "nodes")
            if str(item.get("node_id", item.get("id", ""))).strip()
        ],
        "controllers": controller_public_urls(state_root),
        "token_verification_keys": [],
    }
    _assert_no_sensitive_state(snapshot)

    private_key, public_key, key_id = _cluster_signing_identity(state_root)
    snapshot["signing_key_id"] = key_id
    signature = private_key.sign(_signing_bytes(snapshot))
    snapshot["signature"] = base64.b64encode(signature).decode("ascii")
    return snapshot, public_key


def verify_security_snapshot(
    snapshot: dict[str, Any],
    verification_key: str,
    *,
    expected_cluster_id: str | None = None,
    min_revision: int = 0,
    now: int | None = None,
) -> dict[str, Any]:
    if int(snapshot.get("snapshot_version", 0)) != SNAPSHOT_VERSION:
        raise GatewaySnapshotError("unsupported Gateway snapshot version")
    if int(snapshot.get("state_schema_version", 0)) != 1:
        raise GatewaySnapshotError("incompatible Gateway state schema")
    cluster_id = str(snapshot.get("cluster_id", "")).strip()
    if not cluster_id:
        raise GatewaySnapshotError("Gateway snapshot cluster_id is missing")
    if expected_cluster_id and cluster_id != expected_cluster_id:
        raise GatewaySnapshotError("Gateway snapshot cluster identity mismatch")

    revision = int(snapshot.get("revision", -1))
    if revision < min_revision:
        raise GatewaySnapshotError("Gateway snapshot revision rollback detected")
    timestamp = int(time.time()) if now is None else int(now)
    created_at = int(snapshot.get("created_at", 0))
    expires_at = int(snapshot.get("expires_at", 0))
    if created_at <= 0 or expires_at <= created_at:
        raise GatewaySnapshotError("Gateway snapshot validity is malformed")
    if created_at > timestamp + 300:
        raise GatewaySnapshotError("Gateway snapshot is from the future")
    if expires_at < timestamp:
        raise GatewaySnapshotError("Gateway snapshot has expired")

    _assert_no_sensitive_state(snapshot)
    signature_raw = str(snapshot.get("signature", "")).strip()
    try:
        public_raw = base64.b64decode(verification_key, validate=True)
        signature = base64.b64decode(signature_raw, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise GatewaySnapshotError("invalid Gateway snapshot signature encoding") from exc
    if len(public_raw) != 32:
        raise GatewaySnapshotError("invalid Gateway snapshot verification key")
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature,
            _signing_bytes(snapshot),
        )
    except InvalidSignature as exc:
        raise GatewaySnapshotError("Gateway snapshot signature verification failed") from exc
    return snapshot


def install_security_snapshot(
    state_dir: Path,
    snapshot: dict[str, Any],
    verification_key: str,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    runtime = state_dir / "runtime"
    current_path = runtime / "security-snapshot.json"
    current_revision = 0
    expected_cluster: str | None = None
    if current_path.is_file():
        try:
            current = _read_json(current_path)
            current_revision = int(current.get("revision", 0))
            expected_cluster = str(current.get("cluster_id", "")).strip() or None
        except (OSError, ValueError, json.JSONDecodeError, GatewaySnapshotError):
            raise GatewaySnapshotError("existing Gateway snapshot is invalid") from None
    verified = verify_security_snapshot(
        snapshot,
        verification_key,
        expected_cluster_id=expected_cluster,
        min_revision=current_revision,
        now=now,
    )
    _atomic_json(current_path, verified)
    trust = {
        "version": 1,
        "cluster_id": str(verified["cluster_id"]),
        "verification_key": verification_key,
        "signing_key_id": str(verified.get("signing_key_id", "")),
    }
    _atomic_json(runtime / "security-trust.json", trust)
    return verified


def load_valid_security_snapshot(
    state_dir: Path,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    runtime = state_dir / "runtime"
    snapshot = _read_json(runtime / "security-snapshot.json")
    trust = _read_json(runtime / "security-trust.json")
    return verify_security_snapshot(
        snapshot,
        str(trust.get("verification_key", "")),
        expected_cluster_id=str(trust.get("cluster_id", "")) or None,
        min_revision=int(snapshot.get("revision", 0)),
        now=now,
    )


def snapshot_allows_device(
    snapshot: dict[str, Any],
    device_id: str,
    *,
    now: int | None = None,
) -> bool:
    timestamp = int(time.time()) if now is None else int(now)
    if int(snapshot.get("expires_at", 0)) < timestamp:
        return False
    target = device_id.strip()
    if not target:
        return False
    for device in snapshot.get("devices", []):
        if not isinstance(device, dict) or str(device.get("id", "")) != target:
            continue
        if not bool(device.get("enabled", True)):
            return False
        if bool(device.get("revoked", False)):
            return False
        if device.get("revoked_at") not in (None, "", 0):
            return False
        return True
    return False


def snapshot_contains_sensitive_auth_db(snapshot: dict[str, Any]) -> bool:
    try:
        _assert_no_sensitive_state(snapshot)
    except GatewaySnapshotError:
        return True
    return False
