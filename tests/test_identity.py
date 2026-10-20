from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "deploy"))

import bpc_identity as identity  # noqa: E402


def _device(root: Path, user_id: str, private_key: Ed25519PrivateKey) -> dict[str, object]:
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
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


@pytest.mark.parametrize("disabled", [False, True])
def test_password_change_preserves_identity_sessions_and_status(tmp_path, disabled):
    user = identity.create_user(tmp_path, "account", "old synthetic password")
    private = Ed25519PrivateKey.generate()
    _device(tmp_path, user["id"], private)
    path = tmp_path / "identity/users" / f"{user['id']}.json"
    if disabled:
        user["enabled"] = False
        identity.atomic_json(path, user)
    token, _ = identity.issue_access_credential(tmp_path, user_id=user["id"],
                                               device_id=None, scope="login")
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    changed = identity.change_user_password(tmp_path, "AcCoUnT", "new synthetic password")
    assert {k: v for k, v in changed.items() if k != "password_hash"} == {
        k: v for k, v in user.items() if k != "password_hash"}
    assert identity.PASSWORD_HASHER.verify(changed["password_hash"], "new synthetic password")
    assert "new synthetic password" not in path.read_text()
    for other, data in before.items():
        if other != path:
            assert other.read_bytes() == data
    with pytest.raises(identity.IdentityError):
        identity.authenticate_local_user(tmp_path, "account", "old synthetic password")
    if disabled:
        with pytest.raises(identity.IdentityError):
            identity.authenticate_local_user(tmp_path, "account", "new synthetic password")
    else:
        authenticated = identity.authenticate_local_user(
            tmp_path, "account", "new synthetic password")
        assert authenticated["id"] == user["id"]
        assert identity.authorize_access_credential(tmp_path, token)[0]["id"] == user["id"]


@pytest.mark.parametrize("password", ["short", "x" * 1025])
def test_password_change_invalid_length_does_not_write(tmp_path, password):
    user = identity.create_user(tmp_path, "account", "old synthetic password")
    path = tmp_path / "identity/users" / f"{user['id']}.json"
    before = path.read_bytes()
    with pytest.raises(identity.IdentityError, match="password must"):
        identity.change_user_password(tmp_path, "account", password)
    assert path.read_bytes() == before


def test_password_change_missing_user_does_not_create(tmp_path):
    with pytest.raises(identity.IdentityError, match="user not found"):
        identity.change_user_password(tmp_path, "missing", "new synthetic password")
    assert not list(tmp_path.rglob("*.json"))


@pytest.mark.parametrize("failure", [None, "conflict", "quorum"])
def test_password_change_consensus_precondition_and_no_local_fallback(
    tmp_path, monkeypatch, failure,
):
    import hashlib

    user = identity.create_user(tmp_path, "account", "old synthetic password")
    path = tmp_path / "identity/users" / f"{user['id']}.json"
    before = path.read_bytes()
    monkeypatch.setattr(identity.bpc_control_state, "cluster_enabled", lambda root: True)
    monkeypatch.setattr(identity.bpc_control_state, "strong_read", lambda root: {})

    def commit(root, kind, operations):
        assert kind == "ChangeUserPassword" and len(operations) == 1
        op = operations[0]
        assert op["path"] == path
        assert op["expected_sha256"] == hashlib.sha256(before).hexdigest()
        if failure == "conflict":
            concurrent = {**user, "enabled": False}
            path.write_text(json.dumps(concurrent))
            raise identity.bpc_control_state.ControlStateError("conflict", 409)
        if failure == "quorum":
            raise identity.bpc_control_state.ControlStateError("quorum unavailable", 503)
        path.write_bytes(op["data"])
        return {}

    monkeypatch.setattr(identity.bpc_control_state, "mutation", commit)
    if failure:
        with pytest.raises(identity.IdentityError, match="conflict|quorum"):
            identity.change_user_password(tmp_path, "account", "new synthetic password")
        stored = json.loads(path.read_bytes())
        assert stored["password_hash"] == user["password_hash"]
        assert stored["enabled"] == (failure != "conflict")
    else:
        identity.change_user_password(tmp_path, "account", "new synthetic password")
        authenticated = identity.authenticate_local_user(
            tmp_path, "account", "new synthetic password")
        assert authenticated["id"] == user["id"]


def test_password_command_stdin_output_and_prompt_validation(tmp_path, monkeypatch, capsys):
    import io

    identity.create_user(tmp_path, "account", "old synthetic password")
    monkeypatch.setattr(identity.sys, "stdin", io.StringIO("new synthetic password\n"))
    args = identity.parser().parse_args(["--state-dir", str(tmp_path), "user-passwd",
                                        "account", "--password-stdin"])
    assert args.func(args) == 0
    output = capsys.readouterr().out
    assert "Password changed for account" in output and "new synthetic password" not in output
    answers = iter(["пароль-тестовый", "пароль-тестовый"])
    monkeypatch.setattr(identity.getpass, "getpass", lambda *a: next(answers))
    assert identity._read_password(False) == "пароль-тестовый"
    answers = iter(["first", "different"])
    with pytest.raises(identity.IdentityError, match="do not match"):
        identity._read_password(False)
    monkeypatch.setattr(identity.sys, "stdin", io.StringIO(""))
    with pytest.raises(identity.IdentityError, match="empty"):
        identity._read_password(True)


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
