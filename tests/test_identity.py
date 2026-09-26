from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "deploy"))

import bpc_identity as identity  # noqa: E402


def _device(root: Path, user_id: str, private_key: Ed25519PrivateKey) -> dict[str, object]:
    public_raw = private_key.public_key().public_bytes_raw()
    public_key = base64.b64encode(public_raw).decode("ascii")
    device_id = "a" * 32
    device = {
        "id": device_id,
        "device_id": device_id,
        "user_id": user_id,
        "name": "pc004",
        "device": "pc004",
        "public_key": public_key,
        "created_at": 100,
        "last_seen": 100,
        "enabled": True,
        "revoked_at": None,
        "revoked": False,
    }
    identity.atomic_json(root / "devices" / f"{device_id}.json", device)
    return device


def _sign(private_key: Ed25519PrivateKey, message: bytes) -> str:
    return base64.b64encode(private_key.sign(message)).decode("ascii")


def test_user_password_is_argon2id_and_plaintext_is_never_stored(tmp_path: Path) -> None:
    user = identity.create_user(tmp_path, "roman", "correct horse battery staple", now=100)
    raw = (tmp_path / "identity" / "users" / f"{user['id']}.json").read_text(
        encoding="utf-8"
    )

    assert "correct horse battery staple" not in raw
    stored = json.loads(raw)
    assert stored["password_hash"].startswith("$argon2id$")
    assert stored["username"] == "roman"
    assert stored["enabled"] is True
    assert stored["created_at"] == 100

    authenticated = identity.authenticate_local_user(
        tmp_path, "RoMaN", "correct horse battery staple"
    )
    assert authenticated["id"] == user["id"]

    with pytest.raises(identity.IdentityError, match="invalid username or password"):
        identity.authenticate_local_user(tmp_path, "roman", "wrong password")


def test_access_credential_is_short_lived_and_only_hash_is_stored(tmp_path: Path) -> None:
    user = identity.create_user(tmp_path, "roman", "correct horse battery staple", now=100)
    token, expires = identity.issue_access_credential(
        tmp_path,
        user_id=str(user["id"]),
        device_id=None,
        scope="login",
        now=110,
    )

    assert expires == 110 + identity.ACCESS_TTL
    access_files = list((tmp_path / "identity" / "access").glob("*.json"))
    assert len(access_files) == 1
    assert token not in access_files[0].read_text(encoding="utf-8")

    authorized, device, record = identity.authorize_access_credential(
        tmp_path,
        token,
        required_scope="login",
        now=111,
    )
    assert authorized["id"] == user["id"]
    assert device is None
    assert record["scope"] == "login"

    with pytest.raises(identity.IdentityError, match="expired"):
        identity.authorize_access_credential(
            tmp_path,
            token,
            required_scope="login",
            now=expires,
        )


def test_refresh_is_device_bound_rotating_and_replay_revokes_family(tmp_path: Path) -> None:
    user = identity.create_user(tmp_path, "roman", "correct horse battery staple", now=100)
    private_key = Ed25519PrivateKey.generate()
    device = _device(tmp_path, str(user["id"]), private_key)

    session = identity.issue_device_session(
        tmp_path,
        user_id=str(user["id"]),
        device_id=str(device["id"]),
        now=120,
    )
    refresh = str(session["refresh_token"])
    proof = _sign(private_key, identity.refresh_message(refresh))

    rotated = identity.refresh_device_session(tmp_path, refresh, proof, now=130)
    assert rotated["refresh_token"] != refresh
    assert rotated["access_token"] != session["access_token"]

    new_refresh = str(rotated["refresh_token"])
    new_proof = _sign(private_key, identity.refresh_message(new_refresh))
    second = identity.refresh_device_session(tmp_path, new_refresh, new_proof, now=140)
    assert second["refresh_token"] != new_refresh

    with pytest.raises(identity.IdentityError, match="replay"):
        identity.refresh_device_session(tmp_path, refresh, proof, now=150)

    newest = str(second["refresh_token"])
    newest_proof = _sign(private_key, identity.refresh_message(newest))
    with pytest.raises(identity.IdentityError, match="replay"):
        identity.refresh_device_session(tmp_path, newest, newest_proof, now=151)


def test_invalid_device_private_key_proof_cannot_refresh(tmp_path: Path) -> None:
    user = identity.create_user(tmp_path, "roman", "correct horse battery staple", now=100)
    private_key = Ed25519PrivateKey.generate()
    attacker_key = Ed25519PrivateKey.generate()
    device = _device(tmp_path, str(user["id"]), private_key)
    session = identity.issue_device_session(
        tmp_path,
        user_id=str(user["id"]),
        device_id=str(device["id"]),
        now=120,
    )
    refresh = str(session["refresh_token"])
    proof = _sign(attacker_key, identity.refresh_message(refresh))

    with pytest.raises(identity.IdentityError, match="invalid device proof"):
        identity.refresh_device_session(tmp_path, refresh, proof, now=130)


def test_device_revoke_invalidates_access_and_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = identity.create_user(tmp_path, "roman", "correct horse battery staple", now=100)
    private_key = Ed25519PrivateKey.generate()
    device = _device(tmp_path, str(user["id"]), private_key)
    session = identity.issue_device_session(
        tmp_path,
        user_id=str(user["id"]),
        device_id=str(device["id"]),
        now=120,
    )
    monkeypatch.setattr(identity.subprocess, "run", lambda *args, **kwargs: None)

    revoked = identity.deactivate_device(
        tmp_path,
        str(device["id"]),
        revoked=True,
        now=130,
    )
    assert revoked["enabled"] is False
    assert revoked["revoked_at"] == 130

    with pytest.raises(identity.IdentityError):
        identity.authorize_access_credential(
            tmp_path,
            str(session["access_token"]),
            require_device=True,
            now=131,
        )

    refresh = str(session["refresh_token"])
    proof = _sign(private_key, identity.refresh_message(refresh))
    with pytest.raises(identity.IdentityError):
        identity.refresh_device_session(tmp_path, refresh, proof, now=131)


def test_disabling_user_disables_owned_devices_and_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = identity.create_user(tmp_path, "roman", "correct horse battery staple", now=100)
    private_key = Ed25519PrivateKey.generate()
    device = _device(tmp_path, str(user["id"]), private_key)
    session = identity.issue_device_session(
        tmp_path,
        user_id=str(user["id"]),
        device_id=str(device["id"]),
        now=120,
    )
    monkeypatch.setattr(identity.subprocess, "run", lambda *args, **kwargs: None)

    disabled = identity.disable_user(tmp_path, "roman", now=130)
    assert disabled["enabled"] is False
    stored_device = identity.load_device(tmp_path, str(device["id"]))
    assert stored_device["enabled"] is False

    with pytest.raises(identity.IdentityError):
        identity.authorize_access_credential(
            tmp_path,
            str(session["access_token"]),
            require_device=True,
            now=131,
        )
