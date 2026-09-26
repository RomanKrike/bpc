#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import contextlib
import getpass
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DEFAULT_CONTROL_DIR = Path("/etc/bpc-connect/ru-node/control")
ACCESS_TTL = 10 * 60
REFRESH_TTL = 30 * 24 * 60 * 60
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DEVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=2$SqqHn3CWlOztsv14UGaiTw$"
    "YKur3kzmEgIzL3TtGFpHEN9Tn+V1Z2eVGH9PCMoTgms"
)


class IdentityError(RuntimeError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def atomic_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    tmp.write_text(payload, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return value


def credential_index(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _validate_opaque_token(value: str, label: str) -> str:
    token = value.strip()
    if len(token) != 64:
        raise IdentityError(f"invalid {label}", 401)
    try:
        int(token, 16)
    except ValueError as exc:
        raise IdentityError(f"invalid {label}", 401) from exc
    return token


def normalize_username(value: str) -> str:
    username = value.strip()
    if not USERNAME_RE.fullmatch(username):
        raise IdentityError(
            "username must start with an alphanumeric character and contain only "
            "letters, digits, '.', '_' or '-'"
        )
    return username.casefold()


def normalize_device_name(value: str) -> str:
    name = value.strip()
    if not DEVICE_NAME_RE.fullmatch(name):
        raise IdentityError(
            "device name must start with an alphanumeric character and contain only "
            "letters, digits, '.', '_' or '-'"
        )
    return name


def username_index(username: str) -> str:
    return hashlib.sha256(normalize_username(username).encode("utf-8")).hexdigest()


def _users(root: Path) -> Path:
    return root / "identity" / "users"


def _usernames(root: Path) -> Path:
    return root / "identity" / "usernames"


def _access(root: Path) -> Path:
    return root / "identity" / "access"


def _refresh(root: Path) -> Path:
    return root / "identity" / "refresh"


def ensure_identity_dirs(root: Path) -> None:
    paths = (_users(root), _usernames(root), _access(root), _refresh(root), root / "devices")
    for path in paths:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            os.chmod(path, 0o700)


def create_user(root: Path, username: str, password: str, now: int | None = None) -> dict[str, Any]:
    ensure_identity_dirs(root)
    normalized = normalize_username(username)
    if not 8 <= len(password) <= 1024:
        raise IdentityError("password must contain between 8 and 1024 characters")
    index_path = _usernames(root) / f"{username_index(normalized)}.json"
    if index_path.is_file():
        raise IdentityError("username already exists", 409)
    timestamp = int(time.time()) if now is None else int(now)
    user_id = uuid.uuid4().hex
    user = {
        "id": user_id,
        "username": username.strip(),
        "username_normalized": normalized,
        "password_hash": PASSWORD_HASHER.hash(password),
        "enabled": True,
        "created_at": timestamp,
    }
    atomic_json(_users(root) / f"{user_id}.json", user)
    atomic_json(index_path, {"user_id": user_id})
    return user


def load_user(root: Path, user_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{32}", user_id):
        raise IdentityError("invalid user", 401)
    path = _users(root) / f"{user_id}.json"
    if not path.is_file():
        raise IdentityError("invalid user", 401)
    try:
        return read_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise IdentityError("invalid user", 401) from exc


def load_user_by_username(root: Path, username: str) -> dict[str, Any] | None:
    try:
        index_path = _usernames(root) / f"{username_index(username)}.json"
    except IdentityError:
        return None
    if not index_path.is_file():
        return None
    try:
        index = read_json(index_path)
        return load_user(root, str(index["user_id"]))
    except (OSError, KeyError, ValueError, json.JSONDecodeError, IdentityError):
        return None


def authenticate_local_user(root: Path, username: str, password: str) -> dict[str, Any]:
    user = load_user_by_username(root, username)
    encoded = str(user.get("password_hash", "")) if user else DUMMY_PASSWORD_HASH
    ok = False
    try:
        ok = PASSWORD_HASHER.verify(encoded, password)
    except (VerificationError, ValueError):
        ok = False
    if not user or not bool(user.get("enabled", False)) or not ok:
        raise IdentityError("invalid username or password", 401)

    if PASSWORD_HASHER.check_needs_rehash(encoded):
        user["password_hash"] = PASSWORD_HASHER.hash(password)
        atomic_json(_users(root) / f"{user['id']}.json", user)
    return user


def _write_credential(directory: Path, token: str, record: dict[str, Any]) -> None:
    atomic_json(directory / f"{credential_index(token)}.json", record)


def issue_access_credential(
    root: Path,
    *,
    user_id: str,
    device_id: str | None,
    scope: str,
    now: int | None = None,
    ttl: int = ACCESS_TTL,
) -> tuple[str, int]:
    ensure_identity_dirs(root)
    timestamp = int(time.time()) if now is None else int(now)
    if ttl <= 0 or ttl > 3600:
        raise IdentityError("invalid access credential TTL")
    token = secrets.token_hex(32)
    expires_at = timestamp + ttl
    _write_credential(
        _access(root),
        token,
        {
            "version": 1,
            "user_id": user_id,
            "device_id": device_id,
            "scope": scope,
            "created_at": timestamp,
            "expires_at": expires_at,
        },
    )
    return token, expires_at


def issue_refresh_credential(
    root: Path,
    *,
    user_id: str,
    device_id: str,
    family_id: str | None = None,
    now: int | None = None,
    ttl: int = REFRESH_TTL,
) -> tuple[str, int]:
    ensure_identity_dirs(root)
    timestamp = int(time.time()) if now is None else int(now)
    if ttl <= 0 or ttl > 90 * 24 * 60 * 60:
        raise IdentityError("invalid refresh credential TTL")
    token = secrets.token_hex(32)
    expires_at = timestamp + ttl
    _write_credential(
        _refresh(root),
        token,
        {
            "version": 1,
            "user_id": user_id,
            "device_id": device_id,
            "family_id": family_id or uuid.uuid4().hex,
            "created_at": timestamp,
            "expires_at": expires_at,
            "revoked_at": None,
        },
    )
    return token, expires_at


def _device_path(root: Path, device_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}", device_id):
        raise IdentityError("invalid device", 401)
    return root / "devices" / f"{device_id}.json"


def load_device(root: Path, device_id: str) -> dict[str, Any]:
    path = _device_path(root, device_id)
    if not path.is_file():
        raise IdentityError("invalid device", 401)
    try:
        return read_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise IdentityError("invalid device", 401) from exc


def device_is_active(device: dict[str, Any]) -> bool:
    enabled = bool(device.get("enabled", True))
    revoked_at = device.get("revoked_at")
    revoked = bool(device.get("revoked", False))
    return enabled and not revoked and revoked_at in (None, "", 0)


def authorize_access_credential(
    root: Path,
    token: str,
    *,
    require_device: bool = False,
    required_scope: str | None = None,
    now: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any]]:
    credential = _validate_opaque_token(token, "access credential")
    path = _access(root) / f"{credential_index(credential)}.json"
    if not path.is_file():
        raise IdentityError("invalid access credential", 401)
    try:
        record = read_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise IdentityError("invalid access credential", 401) from exc
    timestamp = int(time.time()) if now is None else int(now)
    if int(record.get("expires_at", 0)) <= timestamp:
        path.unlink(missing_ok=True)
        raise IdentityError("access credential expired", 401)
    if required_scope and str(record.get("scope", "")) != required_scope:
        raise IdentityError("access credential scope is not permitted", 403)

    user = load_user(root, str(record.get("user_id", "")))
    if not bool(user.get("enabled", False)):
        raise IdentityError("user is disabled", 403)

    device_id = str(record.get("device_id") or "")
    device: dict[str, Any] | None = None
    if device_id:
        device = load_device(root, device_id)
        if str(device.get("user_id", "")) != str(user["id"]) or not device_is_active(device):
            raise IdentityError("device is disabled or revoked", 403)
    elif require_device:
        raise IdentityError("device credential required", 403)
    return user, device, record


def _decode_device_public_key(value: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise IdentityError("invalid device public key") from exc
    if len(raw) != 32:
        raise IdentityError("invalid device public key")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_device_proof(public_key: str, signature: str, message: bytes) -> None:
    key = _decode_device_public_key(public_key)
    try:
        raw_signature = base64.b64decode(signature.strip(), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise IdentityError("invalid device proof", 401) from exc
    try:
        key.verify(raw_signature, message)
    except InvalidSignature as exc:
        raise IdentityError("invalid device proof", 401) from exc


def registration_message(
    access_token: str,
    public_key: str,
    wireguard_public_key: str,
) -> bytes:
    return (
        "bpc-register-v1\n"
        + access_token.strip()
        + "\n"
        + public_key.strip()
        + "\n"
        + wireguard_public_key.strip()
        + "\n"
    ).encode("utf-8")


def refresh_message(refresh_token: str) -> bytes:
    return ("bpc-refresh-v1\n" + refresh_token.strip() + "\n").encode("utf-8")


def issue_device_session(
    root: Path,
    *,
    user_id: str,
    device_id: str,
    now: int | None = None,
) -> dict[str, Any]:
    access_token, access_expires_at = issue_access_credential(
        root,
        user_id=user_id,
        device_id=device_id,
        scope="device",
        now=now,
    )
    refresh_token, refresh_expires_at = issue_refresh_credential(
        root,
        user_id=user_id,
        device_id=device_id,
        now=now,
    )
    return {
        "access_token": access_token,
        "access_expires_at": access_expires_at,
        "refresh_token": refresh_token,
        "refresh_expires_at": refresh_expires_at,
    }


def _revoke_refresh_family(root: Path, family_id: str, now: int) -> None:
    if not family_id:
        return
    for path in _refresh(root).glob("*.json"):
        try:
            record = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if str(record.get("family_id", "")) != family_id:
            continue
        if record.get("revoked_at") in (None, "", 0):
            record["revoked_at"] = now
            atomic_json(path, record)


def refresh_device_session(
    root: Path,
    refresh_token: str,
    proof: str,
    now: int | None = None,
) -> dict[str, Any]:
    credential = _validate_opaque_token(refresh_token, "refresh credential")
    path = _refresh(root) / f"{credential_index(credential)}.json"
    if not path.is_file():
        raise IdentityError("invalid refresh credential", 401)
    try:
        record = read_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise IdentityError("invalid refresh credential", 401) from exc
    timestamp = int(time.time()) if now is None else int(now)
    family_id = str(record.get("family_id", ""))
    if record.get("revoked_at") not in (None, "", 0):
        _revoke_refresh_family(root, family_id, timestamp)
        raise IdentityError("refresh credential replay detected", 401)
    if int(record.get("expires_at", 0)) <= timestamp:
        record["revoked_at"] = timestamp
        atomic_json(path, record)
        raise IdentityError("refresh credential expired", 401)

    user = load_user(root, str(record.get("user_id", "")))
    if not bool(user.get("enabled", False)):
        raise IdentityError("user is disabled", 403)
    device = load_device(root, str(record.get("device_id", "")))
    if str(device.get("user_id", "")) != str(user["id"]) or not device_is_active(device):
        raise IdentityError("device is disabled or revoked", 403)
    verify_device_proof(
        str(device.get("public_key", "")),
        proof,
        refresh_message(credential),
    )

    record["revoked_at"] = timestamp
    record["rotated_at"] = timestamp
    atomic_json(path, record)

    access_token, access_expires_at = issue_access_credential(
        root,
        user_id=str(user["id"]),
        device_id=str(device["id"] if "id" in device else device["device_id"]),
        scope="device",
        now=timestamp,
    )
    new_refresh, refresh_expires_at = issue_refresh_credential(
        root,
        user_id=str(user["id"]),
        device_id=str(device["id"] if "id" in device else device["device_id"]),
        family_id=family_id or uuid.uuid4().hex,
        now=timestamp,
    )
    return {
        "access_token": access_token,
        "access_expires_at": access_expires_at,
        "refresh_token": new_refresh,
        "refresh_expires_at": refresh_expires_at,
        "device_id": str(device.get("id", device.get("device_id", ""))),
    }


def revoke_device_credentials(root: Path, device_id: str, now: int | None = None) -> None:
    timestamp = int(time.time()) if now is None else int(now)
    for path in _access(root).glob("*.json"):
        try:
            record = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if str(record.get("device_id") or "") == device_id:
            path.unlink(missing_ok=True)
    for path in _refresh(root).glob("*.json"):
        try:
            record = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if str(record.get("device_id") or "") != device_id:
            continue
        if record.get("revoked_at") in (None, "", 0):
            record["revoked_at"] = timestamp
            atomic_json(path, record)


def revoke_user_access(root: Path, user_id: str, now: int | None = None) -> None:
    timestamp = int(time.time()) if now is None else int(now)
    for path in _access(root).glob("*.json"):
        try:
            record = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if str(record.get("user_id", "")) == user_id:
            path.unlink(missing_ok=True)
    for path in _refresh(root).glob("*.json"):
        try:
            record = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if str(record.get("user_id", "")) != user_id:
            continue
        if record.get("revoked_at") in (None, "", 0):
            record["revoked_at"] = timestamp
            atomic_json(path, record)


def logout_session(
    root: Path,
    access_token: str,
    refresh_token: str | None = None,
    now: int | None = None,
) -> None:
    timestamp = int(time.time()) if now is None else int(now)
    user, device, _ = authorize_access_credential(
        root,
        access_token,
        require_device=True,
        now=timestamp,
    )
    access_path = _access(root) / f"{credential_index(access_token)}.json"
    access_path.unlink(missing_ok=True)

    if refresh_token:
        credential = _validate_opaque_token(refresh_token, "refresh credential")
        path = _refresh(root) / f"{credential_index(credential)}.json"
        if path.is_file():
            try:
                record = read_json(path)
            except (OSError, ValueError, json.JSONDecodeError):
                record = {}
            same_user = str(record.get("user_id", "")) == str(user["id"])
            same_device = device is not None and str(record.get("device_id", "")) == str(
                device.get("id", device.get("device_id", ""))
            )
            if same_user and same_device:
                _revoke_refresh_family(root, str(record.get("family_id", "")), timestamp)
                return
    if device is not None:
        revoke_device_credentials(
            root,
            str(device.get("id", device.get("device_id", ""))),
            timestamp,
        )


def find_device_by_public_key(root: Path, public_key: str) -> dict[str, Any] | None:
    for path in sorted((root / "devices").glob("*.json")):
        try:
            device = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if secrets.compare_digest(str(device.get("public_key", "")), public_key):
            return device
    return None


def list_devices(root: Path, user_id: str | None = None) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    for path in sorted((root / "devices").glob("*.json")):
        try:
            device = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if user_id is not None and str(device.get("user_id", "")) != user_id:
            continue
        devices.append(device)
    return devices


def resolve_device(root: Path, identifier: str) -> dict[str, Any]:
    raw = identifier.strip()
    direct = root / "devices" / f"{raw}.json"
    if re.fullmatch(r"[0-9a-f]{32}", raw) and direct.is_file():
        return read_json(direct)
    matches = [
        device
        for device in list_devices(root)
        if str(device.get("name", device.get("device", ""))) == raw
        and device.get("revoked_at") in (None, "", 0)
        and not bool(device.get("revoked", False))
    ]
    if not matches:
        raise IdentityError(f"device not found: {raw}", 404)
    if len(matches) > 1:
        raise IdentityError(
            f"multiple active devices are named {raw!r}; use the device ID",
            409,
        )
    return matches[0]


def _remove_device_dataplane(root: Path, device: dict[str, Any]) -> None:
    device_id = str(device.get("id", device.get("device_id", "")))
    if device_id:
        (root.parent / "agent" / "wgshim-keys" / f"{device_id}.key").unlink(missing_ok=True)
    public_key = str(device.get("wireguard_public_key", "")).strip()
    if not public_key:
        return
    try:
        config = read_json(root / "config.json")
        interface = str(config.get("wireguard_interface", "")).strip()
    except (OSError, ValueError, json.JSONDecodeError):
        return
    if not interface:
        return
    subprocess.run(
        ["wg", "set", interface, "peer", public_key, "remove"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def deactivate_device(
    root: Path,
    device_id: str,
    *,
    revoked: bool,
    now: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    device = load_device(root, device_id)
    canonical_id = str(device.get("id", device.get("device_id", device_id)))
    device["enabled"] = False
    if revoked:
        device["revoked"] = True
        device["revoked_at"] = timestamp
    atomic_json(_device_path(root, canonical_id), device)
    revoke_device_credentials(root, canonical_id, timestamp)

    legacy_token = str(device.get("device_token", "")).strip()
    if legacy_token:
        (root / "tokens" / f"{credential_index(legacy_token)}.json").unlink(missing_ok=True)
    _remove_device_dataplane(root, device)
    return device


def disable_user(root: Path, username: str, now: int | None = None) -> dict[str, Any]:
    user = load_user_by_username(root, username)
    if user is None:
        raise IdentityError("user not found", 404)
    timestamp = int(time.time()) if now is None else int(now)
    user["enabled"] = False
    atomic_json(_users(root) / f"{user['id']}.json", user)
    revoke_user_access(root, str(user["id"]), timestamp)
    for device in list_devices(root, str(user["id"])):
        if device_is_active(device):
            deactivate_device(
                root,
                str(device.get("id", device.get("device_id", ""))),
                revoked=False,
                now=timestamp,
            )
    return user


def _read_password(stdin: bool) -> str:
    if stdin:
        value = sys.stdin.readline()
        if value == "":
            raise IdentityError("password stdin is empty")
        return value.rstrip("\r\n")
    first = getpass.getpass("Password: ")
    second = getpass.getpass("Confirm password: ")
    if not secrets.compare_digest(first, second):
        raise IdentityError("passwords do not match")
    return first


def cmd_user_add(args: argparse.Namespace) -> int:
    password = _read_password(bool(args.password_stdin))
    user = create_user(Path(args.state_dir), args.username, password)
    print(f"Created user {user['username']} ({user['id']})")
    return 0


def cmd_user_disable(args: argparse.Namespace) -> int:
    user = disable_user(Path(args.state_dir), args.username)
    print(f"Disabled user {user['username']}")
    return 0


def cmd_device_list(args: argparse.Namespace) -> int:
    root = Path(args.state_dir)
    devices = list_devices(root)
    if not devices:
        print("No devices.")
        return 0
    for device in devices:
        device_id = str(device.get("id", device.get("device_id", "?")))
        name = str(device.get("name", device.get("device", "?")))
        user_id = str(device.get("user_id", "-"))
        state = "active" if device_is_active(device) else "revoked/disabled"
        last_seen = str(device.get("last_seen", "-"))
        print(f"{device_id}  {name}  user={user_id}  {state}  last_seen={last_seen}")
    return 0


def cmd_device_revoke(args: argparse.Namespace) -> int:
    root = Path(args.state_dir)
    device = resolve_device(root, args.device)
    device_id = str(device.get("id", device.get("device_id", "")))
    revoked = deactivate_device(root, device_id, revoked=True)
    print(
        f"Revoked device {revoked.get('name', revoked.get('device', device_id))} "
        f"({device_id})"
    )
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="BPC User and Device identity administration")
    result.add_argument("--state-dir", default=str(DEFAULT_CONTROL_DIR))
    commands = result.add_subparsers(dest="command", required=True)

    add = commands.add_parser("user-add")
    add.add_argument("username")
    add.add_argument("--password-stdin", action="store_true")
    add.set_defaults(func=cmd_user_add)

    disable = commands.add_parser("user-disable")
    disable.add_argument("username")
    disable.set_defaults(func=cmd_user_disable)

    devices = commands.add_parser("device-list")
    devices.set_defaults(func=cmd_device_list)

    revoke = commands.add_parser("device-revoke")
    revoke.add_argument("device")
    revoke.set_defaults(func=cmd_device_revoke)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return int(args.func(args))
    except IdentityError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
