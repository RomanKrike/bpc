from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path
from typing import Any


class LegacyDeviceAuthError(RuntimeError):
    pass


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return value


def _token_index(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def legacy_token_index_path(root: Path, token: str) -> Path:
    return root / "tokens" / f"{_token_index(token)}.json"


def authorize_legacy_static_device(
    root: Path,
    token: str,
) -> tuple[Path, dict[str, Any]] | None:
    index_path = legacy_token_index_path(root, token)
    if not index_path.is_file():
        return None
    try:
        index = _read_json(index_path)
        device_id = str(index["device_id"])
        device_path = root / "devices" / f"{device_id}.json"
        device = _read_json(device_path)
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        raise LegacyDeviceAuthError("invalid legacy Device credential") from exc

    stored = str(device.get("device_token", ""))
    if not stored or not secrets.compare_digest(stored, token):
        raise LegacyDeviceAuthError("invalid legacy Device credential")
    if not bool(device.get("enabled", True)) or bool(device.get("revoked", False)):
        raise LegacyDeviceAuthError("legacy Device is disabled")
    return device_path, device


def compatibility_enrollment_fields(
    *,
    credential: str,
    enrollment: dict[str, Any],
) -> dict[str, object]:
    return {
        "device_token": credential,
        "managed_routes": [],
        "legacy_tunnel": str(enrollment.get("legacy_tunnel", "")),
    }


def compatibility_enrollment_response(credential: str) -> dict[str, str]:
    return {"device_token": credential}
