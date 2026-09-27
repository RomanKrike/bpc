from __future__ import annotations

import base64
import json
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

LOCAL_API = "http://127.0.0.1:9446"
REPLICATED_PREFIXES = (
    "control/identity/users/",
    "control/identity/usernames/",
    "control/identity/access/",
    "control/identity/refresh/",
    "control/devices/",
    "control/access/",
    "control/node-join/",
    "control/node-join-used/",
    "control/nodes/",
    "control/node-public-keys/",
    "control/node-credentials/",
    "control/routes/",
    "control/revocations/",
    "cluster/controllers/",
)
REPLICATED_EXACT = {"cluster/cluster.json"}


class ControlStateError(RuntimeError):
    def __init__(self, message: str, status: int = 503):
        super().__init__(message)
        self.status = status


def state_root(control_root: Path) -> Path:
    root = Path(control_root).resolve()
    return root.parent if root.name == "control" else root


def cluster_enabled(control_root: Path) -> bool:
    return (state_root(control_root) / "cluster" / "controller.json").is_file()


def canonical_relative(control_root: Path, path: Path) -> str:
    root = state_root(control_root)
    try:
        return Path(path).resolve().relative_to(root).as_posix()
    except ValueError as exc:
        raise ControlStateError(f"path escapes BPC state root: {path}", 500) from exc


def is_replicated_path(control_root: Path, path: Path) -> bool:
    relative = canonical_relative(control_root, path)
    return relative in REPLICATED_EXACT or any(
        relative.startswith(prefix) and len(relative) > len(prefix)
        for prefix in REPLICATED_PREFIXES
    )


def _post(path: str, value: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        LOCAL_API + path,
        data=json.dumps(value, separators=(",", ":")).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        try:
            error = json.loads(exc.read()).get("error", str(exc))
        except (json.JSONDecodeError, UnicodeDecodeError):
            error = str(exc)
        raise ControlStateError(str(error), exc.code) from exc
    except OSError as exc:
        raise ControlStateError(f"distributed control plane unavailable: {exc}") from exc
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ControlStateError("invalid distributed control-plane response")
    return result


def mutation(
    control_root: Path,
    kind: str,
    operations: list[dict[str, Any]],
    *,
    issued_at: int | None = None,
) -> dict[str, Any]:
    if not cluster_enabled(control_root):
        raise ControlStateError("distributed control plane is not enabled", 412)
    encoded = []
    for operation in operations:
        item = dict(operation)
        path = Path(item["path"])
        if not is_replicated_path(control_root, path):
            raise ControlStateError(f"path is not replicated canonical state: {path}", 500)
        item["path"] = canonical_relative(control_root, path)
        data = item.get("data")
        if data is not None:
            if not isinstance(data, bytes):
                raise TypeError("mutation data must be bytes")
            item["data"] = base64.b64encode(data).decode("ascii")
        encoded.append(item)
    return _post(
        "/v1/mutate",
        {
            "version": 1,
            "id": secrets.token_hex(16),
            "kind": kind,
            "issued_at": int(time.time()) if issued_at is None else int(issued_at),
            "operations": encoded,
        },
    )


def strong_read(control_root: Path) -> dict[str, Any]:
    if not cluster_enabled(control_root):
        return {"commit_index": 0, "revision": 0, "local_fallback": True}
    return _post("/v1/barrier", {})
