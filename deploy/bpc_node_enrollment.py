#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

MODULE_DIR = Path(__file__).resolve().parent
if (MODULE_DIR / "src" / "bpc_connect").is_dir():
    ROOT = MODULE_DIR
    SOURCE_ROOT = MODULE_DIR / "src"
else:
    ROOT = MODULE_DIR.parent
    SOURCE_ROOT = ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

import bpc_control_state  # noqa: E402
from bpc_access import AccessError, sync_access_firewall  # noqa: E402
from bpc_controller_enrollment import (  # noqa: E402
    ControllerEnrollmentError,
    activate_controller_marker,
    ensure_controller_csr,
    install_controller_enrollment,
)
from bpc_gateway_dataplane import (  # noqa: E402
    GatewayDataplaneError,
    reconcile_gateway_dataplane,
)
from bpc_gateway_snapshot import (  # noqa: E402
    GatewaySnapshotError,
    controller_public_urls,
    install_security_snapshot,
    load_valid_security_snapshot,
    security_runtime_lock,
)
from bpc_topology import (  # noqa: E402
    TopologyError,
    ensure_topology_links,
    merge_node_telemetry,
    routing_config_for_node,
    validate_route_ownership,
    write_node_telemetry,
)

from bpc_connect.compat.runtime import (  # noqa: E402
    RuntimeCompatibilityError,
    reconcile_transport_roles,
    routed_dataplane,
)
from bpc_connect.compat.runtime import (  # noqa: E402
    agent_runtime_env as compatibility_agent_runtime_env,
)
from bpc_connect.compat.runtime import (  # noqa: E402
    default_role_config as compatibility_role_config,
)
from bpc_connect.node import (  # noqa: E402
    NODE_PRESETS,
    Capabilities,
    Node,
    NodeConfig,
    canonical_advertised_routes,
    canonical_endpoints,
    load_node_config,
    save_node_config,
)
from bpc_connect.state import StateLayout  # noqa: E402

DEFAULT_STATE_DIR = Path("/etc/bpc-connect")
DEFAULT_CONTROL_DIR = StateLayout.from_root(DEFAULT_STATE_DIR).control_dir
TOKEN_PREFIX = "BPC-"
HEARTBEAT_INTERVAL = 5
BPC_PROTOCOL_VERSION = 1
STATE_SCHEMA_VERSION = 1
MAX_CLOCK_SKEW = 300
ROLE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class EnrollmentError(RuntimeError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _control_root_for_path(path: Path) -> Path | None:
    for candidate in (path, *path.parents):
        if candidate.name == "control":
            return candidate
    return None


def _raise_control_state(exc: bpc_control_state.ControlStateError) -> None:
    raise EnrollmentError(str(exc), exc.status) from exc


def atomic_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    control_root = _control_root_for_path(path)
    if (
        control_root is not None
        and bpc_control_state.cluster_enabled(control_root)
        and bpc_control_state.is_replicated_path(control_root, path)
    ):
        try:
            bpc_control_state.mutation(
                control_root,
                "PutCanonicalRecord",
                [{"op": "put", "path": path, "data": payload.encode("utf-8")}],
            )
        except bpc_control_state.ControlStateError as exc:
            _raise_control_state(exc)
        return

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def delete_canonical(path: Path, *, kind: str = "DeleteCanonicalRecord") -> None:
    control_root = _control_root_for_path(path)
    if (
        control_root is not None
        and bpc_control_state.cluster_enabled(control_root)
        and bpc_control_state.is_replicated_path(control_root, path)
    ):
        try:
            bpc_control_state.mutation(
                control_root,
                kind,
                [{"op": "delete", "path": path}],
            )
        except bpc_control_state.ControlStateError as exc:
            _raise_control_state(exc)
        return
    path.unlink(missing_ok=True)


def strong_read(control_dir: Path) -> None:
    if not bpc_control_state.cluster_enabled(control_dir):
        return
    try:
        bpc_control_state.strong_read(control_dir)
    except bpc_control_state.ControlStateError as exc:
        _raise_control_state(exc)


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return value


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def token_index(secret: str) -> str:
    return hashlib.sha256(secret.encode("ascii")).hexdigest()


def public_key_fingerprint(public_key: str) -> str:
    try:
        raw = base64.b64decode(public_key, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise EnrollmentError("invalid node public key") from exc
    if not 32 <= len(raw) <= 256:
        raise EnrollmentError("invalid node public key")
    return hashlib.sha256(raw).hexdigest()


def normalize_controller_url(value: str) -> str:
    url = value.strip().rstrip("/")
    if not url.startswith("https://"):
        raise EnrollmentError("controller URL must use https://")
    if len(url) > 512:
        raise EnrollmentError("controller URL is too long")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
        valid = (
            parsed.hostname and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment and not parsed.path
            and (port is None or 1 <= port <= 65535)
            and not any(char.isspace() for char in url)
        )
    except ValueError as exc:
        raise EnrollmentError("invalid controller URL") from exc
    if not valid:
        raise EnrollmentError("invalid controller URL")
    return url


def make_join_token(
    controller_url: str,
    secret: str,
    controller_urls: list[str] | tuple[str, ...] | None = None,
) -> str:
    primary = normalize_controller_url(controller_url)
    pool: list[str] = []
    seen: set[str] = set()
    for raw in [primary, *(controller_urls or [])]:
        url = normalize_controller_url(str(raw))
        if url not in seen:
            seen.add(url)
            pool.append(url)
    if len(pool) > 1:
        envelope = json.dumps(
            {"version": 2, "controllers": pool},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    else:
        envelope = primary.encode("utf-8")
    encoded = b64url_encode(envelope)
    return f"{TOKEN_PREFIX}{encoded}.{secret}"


def parse_join_token_endpoints(token: str) -> tuple[list[str], str]:
    value = token.strip()
    if not value.startswith(TOKEN_PREFIX) or "." not in value:
        raise EnrollmentError("invalid join token", 401)
    encoded, secret = value[len(TOKEN_PREFIX) :].rsplit(".", 1)
    if len(secret) != 64:
        raise EnrollmentError("invalid join token", 401)
    try:
        int(secret, 16)
        decoded = b64url_decode(encoded).decode("utf-8")
    except (ValueError, UnicodeDecodeError, base64.binascii.Error) as exc:
        raise EnrollmentError("invalid join token", 401) from exc

    if decoded.lstrip().startswith("{"):
        try:
            envelope = json.loads(decoded)
        except json.JSONDecodeError as exc:
            raise EnrollmentError("invalid join token", 401) from exc
        if not isinstance(envelope, dict) or int(envelope.get("version", 0)) != 2:
            raise EnrollmentError("invalid join token", 401)
        raw_controllers = envelope.get("controllers", [])
        if not isinstance(raw_controllers, list):
            raise EnrollmentError("invalid join token", 401)
        controllers = _controller_candidates("", [str(item) for item in raw_controllers])
    else:
        controllers = [normalize_controller_url(decoded)]
    return controllers, secret


def parse_join_token(token: str) -> tuple[str, str]:
    controllers, secret = parse_join_token_endpoints(token)
    return controllers[0], secret


def parse_duration(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([smhd])", value.strip().lower())
    if not match:
        raise EnrollmentError("expiration must look like 15m, 2h, or 1d")
    amount = int(match.group(1))
    factor = {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
    seconds = amount * factor
    if seconds > 7 * 86400:
        raise EnrollmentError("join token expiration cannot exceed 7 days")
    return seconds


def normalize_roles(values: list[str] | tuple[str, ...]) -> list[str]:
    roles: list[str] = []
    seen: set[str] = set()
    for raw in values:
        for item in str(raw).split(","):
            role = item.strip()
            if not role:
                continue
            if not ROLE_RE.fullmatch(role):
                raise EnrollmentError(f"invalid role: {role!r}")
            if role not in seen:
                seen.add(role)
                roles.append(role)
    if not roles:
        raise EnrollmentError("at least one role is required")
    return sorted(roles)


def normalize_transport_runtime(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    raw_ports = raw.get("udp_ports", [])
    if not isinstance(raw_ports, list):
        return {}
    ports: list[int] = []
    seen: set[int] = set()
    for raw_port in raw_ports[:16]:
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            continue
        if 1024 <= port <= 65535 and port not in seen:
            seen.add(port)
            ports.append(port)
    try:
        tcp_port = int(raw.get("tcp_port", 0) or 0)
    except (TypeError, ValueError):
        tcp_port = 0
    if not 1024 <= tcp_port <= 65535:
        tcp_port = 0
    overlay_public_key = str(raw.get("overlay_public_key", "")).strip()
    if overlay_public_key:
        try:
            decoded = base64.b64decode(overlay_public_key, validate=True)
        except (ValueError, base64.binascii.Error):
            overlay_public_key = ""
        else:
            if len(decoded) != 32:
                overlay_public_key = ""
    result: dict[str, Any] = {}
    if ports:
        result["udp_ports"] = ports
    if tcp_port:
        result["tcp_port"] = tcp_port
    if overlay_public_key:
        result["overlay_public_key"] = overlay_public_key
    return result


def normalize_node_name(value: str | None, fallback: str = "bpc-node") -> str:
    name = (value or "").strip() or fallback
    if not NODE_NAME_RE.fullmatch(name):
        raise EnrollmentError(
            "node name must start with an alphanumeric character and contain only "
            "letters, digits, '.', '_' or '-'"
        )
    return name


def read_env_value(path: Path, key: str) -> str:
    if not path.is_file():
        return ""
    prefix = f"{key}="
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    return ""


def discover_controller_url(control_dir: Path) -> str:
    runtime = control_dir / "runtime.env"
    host = read_env_value(runtime, "CONTROL_HOST")
    port = read_env_value(runtime, "CONTROL_PORT") or "8444"
    if not host:
        raise EnrollmentError(
            f"controller runtime metadata is missing in {runtime}; "
            "pass --controller-url explicitly"
        )
    return normalize_controller_url(f"https://{host}:{port}")


def default_role_config(
    state_dir: Path, roles: list[str], *, dataplane: str = "compat",
) -> dict[str, Any]:
    return compatibility_role_config(state_dir, roles, dataplane=dataplane)


def enrollment_uses_routed_dataplane(enrollment: dict[str, Any]) -> bool:
    config = enrollment.get("config", {})
    role_config = config.get("role_config", {}) if isinstance(config, dict) else {}
    return isinstance(role_config, dict) and routed_dataplane(role_config)


def create_join_token(
    control_dir: Path,
    *,
    controller_url: str,
    roles: list[str],
    name: str | None = None,
    expires_in: int = 900,
    role_config: dict[str, Any] | None = None,
    endpoints: list[dict[str, Any]] | None = None,
    advertised_routes: list[str] | None = None,
    now: int | None = None,
) -> str:
    timestamp = int(time.time()) if now is None else int(now)
    if expires_in <= 0 or expires_in > 7 * 86400:
        raise EnrollmentError("invalid join token expiration")
    normalized_roles = normalize_roles(roles)
    normalized_name = normalize_node_name(name) if name else None
    routes = canonical_advertised_routes(advertised_routes)
    if routes and "site_router" not in normalized_roles:
        raise EnrollmentError("advertised routes require site_router capability")
    secret = secrets.token_hex(32)
    controllers = controller_public_urls(control_dir.parent)
    token = make_join_token(controller_url, secret, controllers)
    index = token_index(secret)
    metadata = {
        "version": 1,
        "created_at": timestamp,
        "expires_at": timestamp + expires_in,
        "roles": normalized_roles,
        "name": normalized_name,
        "controller_url": normalize_controller_url(controller_url),
        "controllers": _controller_candidates(controller_url, controllers),
        "role_config": role_config or {},
        "endpoints": [item.to_mapping() for item in canonical_endpoints(endpoints)],
        "advertised_routes": list(routes),
    }
    atomic_json(control_dir / "node-join" / f"{index}.json", metadata)
    return token


def _join_record(control_dir: Path, token: str) -> tuple[Path, dict[str, Any], str]:
    strong_read(control_dir)
    controller_url, secret = parse_join_token(token)
    index = token_index(secret)
    path = control_dir / "node-join" / f"{index}.json"
    used = control_dir / "node-join-used" / f"{index}.json"
    if used.is_file():
        raise EnrollmentError("join token has already been used", 409)
    if not path.is_file():
        raise EnrollmentError("invalid join token", 401)
    record = read_json(path)
    if not secrets.compare_digest(
        normalize_controller_url(str(record.get("controller_url", ""))),
        controller_url,
    ):
        raise EnrollmentError("join token controller mismatch", 401)
    return path, record, index


def join_token_metadata(control_dir: Path, token: str) -> dict[str, Any]:
    _, record, _ = _join_record(control_dir, token)
    return dict(record)


def enroll_node(
    control_dir: Path,
    *,
    token: str,
    public_key: str,
    presented_name: str,
    assigned_node_id: str | None = None,
    extra_operations: list[dict[str, Any]] | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    token_path, record, index = _join_record(control_dir, token)
    expires_at = int(record.get("expires_at", 0))
    if expires_at <= timestamp:
        used_path = control_dir / "node-join-used" / f"{index}.json"
        if bpc_control_state.cluster_enabled(control_dir):
            try:
                bpc_control_state.mutation(
                    control_dir,
                    "ExpireNodeJoinToken",
                    [
                        {
                            "op": "delete",
                            "path": token_path,
                            "require_present": True,
                            "expected_sha256": hashlib.sha256(
                                token_path.read_bytes()
                            ).hexdigest(),
                        },
                        {
                            "op": "put",
                            "path": used_path,
                            "data": json.dumps(
                                {"reason": "expired", "used_at": timestamp},
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8"),
                            "if_absent": True,
                        },
                    ],
                    issued_at=timestamp,
                )
            except bpc_control_state.ControlStateError as exc:
                _raise_control_state(exc)
        else:
            token_path.unlink(missing_ok=True)
            atomic_json(used_path, {"reason": "expired", "used_at": timestamp})
        raise EnrollmentError("join token has expired", 401)

    roles = normalize_roles([str(item) for item in record.get("roles", [])])
    fingerprint = public_key_fingerprint(public_key)
    public_index = control_dir / "node-public-keys" / f"{fingerprint}.json"
    if public_index.is_file():
        raise EnrollmentError("duplicate node identity", 409)

    token_name = record.get("name")
    name = normalize_node_name(
        str(token_name) if token_name else presented_name,
        fallback="bpc-node",
    )
    node_id = assigned_node_id or uuid.uuid4().hex
    if not re.fullmatch(r"[0-9a-f]{32}", node_id):
        raise EnrollmentError("assigned Node ID is invalid")
    credential = secrets.token_hex(32)
    credential_index = token_index(credential)
    role_map = {role: True for role in roles}
    role_config = record.get("role_config", {})
    if not isinstance(role_config, dict):
        role_config = {}
    node = {
        "version": 1,
        "node_id": node_id,
        "name": name,
        "public_key": public_key,
        "public_key_fingerprint": fingerprint,
        "roles": role_map,
        "role_config": role_config,
        "endpoints": [item.to_mapping() for item in canonical_endpoints(record.get("endpoints"))],
        "advertised_routes": list(canonical_advertised_routes(record.get("advertised_routes"))),
        "authorized_routes": list(canonical_advertised_routes(record.get("advertised_routes"))),
        "created_at": timestamp,
        "last_seen": timestamp,
        "revoked": False,
        "last_status": "joined",
        "last_version": "",
        "services": {},
    }

    node_path = control_dir / "nodes" / f"{node_id}.json"
    credential_path = control_dir / "node-credentials" / f"{credential_index}.json"
    used_path = control_dir / "node-join-used" / f"{index}.json"
    if bpc_control_state.cluster_enabled(control_dir):
        try:
            token_hash = hashlib.sha256(token_path.read_bytes()).hexdigest()
            operations: list[dict[str, Any]] = [
                {
                    "op": "put",
                    "path": node_path,
                    "data": json.dumps(
                        node, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8"),
                    "if_absent": True,
                },
                {
                    "op": "put",
                    "path": public_index,
                    "data": json.dumps(
                        {"node_id": node_id},
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8"),
                    "if_absent": True,
                },
                {
                    "op": "put",
                    "path": credential_path,
                    "data": json.dumps(
                        {"node_id": node_id},
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8"),
                    "if_absent": True,
                },
                {
                    "op": "put",
                    "path": used_path,
                    "data": json.dumps(
                        {
                            "reason": "used",
                            "used_at": timestamp,
                            "node_id": node_id,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8"),
                    "if_absent": True,
                },
                {
                    "op": "delete",
                    "path": token_path,
                    "require_present": True,
                    "expected_sha256": token_hash,
                },
            ]
            if extra_operations:
                operations.extend(extra_operations)
            bpc_control_state.mutation(
                control_dir,
                "EnrollNode",
                operations,
                issued_at=timestamp,
            )
        except bpc_control_state.ControlStateError as exc:
            _raise_control_state(exc)
    else:
        if extra_operations:
            raise EnrollmentError(
                "Controller enrollment requires distributed control plane",
                412,
            )
        try:
            atomic_json(node_path, node)
            atomic_json(public_index, {"node_id": node_id})
            atomic_json(credential_path, {"node_id": node_id})
            atomic_json(
                used_path,
                {"reason": "used", "used_at": timestamp, "node_id": node_id},
            )
            token_path.unlink()
        except OSError:
            node_path.unlink(missing_ok=True)
            public_index.unlink(missing_ok=True)
            credential_path.unlink(missing_ok=True)
            raise

    return {
        "node_id": node_id,
        "name": name,
        "credential": credential,
        "created_at": timestamp,
        "roles": role_map,
        "config": {
            "version": 1,
            "heartbeat_interval": HEARTBEAT_INTERVAL,
            "role_config": role_config,
            "endpoints": node["endpoints"],
            "advertised_routes": node["advertised_routes"],
        },
    }


def authorize_node(control_dir: Path, credential: str) -> tuple[Path, dict[str, Any]]:
    strong_read(control_dir)
    value = credential.strip()
    if len(value) != 64:
        raise EnrollmentError("invalid node credential", 401)
    try:
        int(value, 16)
    except ValueError as exc:
        raise EnrollmentError("invalid node credential", 401) from exc
    index = token_index(value)
    credential_path = control_dir / "node-credentials" / f"{index}.json"
    if not credential_path.is_file():
        raise EnrollmentError("invalid node credential", 401)
    mapping = read_json(credential_path)
    node_id = str(mapping.get("node_id", ""))
    node_path = control_dir / "nodes" / f"{node_id}.json"
    if not node_path.is_file():
        raise EnrollmentError("invalid node credential", 401)
    node = read_json(node_path)
    if bool(node.get("revoked", False)):
        raise EnrollmentError("node has left the cluster", 403)
    return node_path, node


def authorize_node_telemetry(
    control_dir: Path,
    credential: str,
) -> tuple[Path, dict[str, Any]]:
    """Authorize only expiring local telemetry, without a Raft barrier."""
    value = credential.strip()
    if len(value) != 64:
        raise EnrollmentError("invalid node credential", 401)
    try:
        int(value, 16)
    except ValueError as exc:
        raise EnrollmentError("invalid node credential", 401) from exc
    index = token_index(value)
    credential_path = control_dir / "node-credentials" / f"{index}.json"
    if not credential_path.is_file():
        raise EnrollmentError("invalid node credential", 401)
    mapping = read_json(credential_path)
    node_id = str(mapping.get("node_id", ""))
    node_path = control_dir / "nodes" / f"{node_id}.json"
    if not node_path.is_file():
        raise EnrollmentError("invalid node credential", 401)
    node = read_json(node_path)
    if bool(node.get("revoked", False)):
        raise EnrollmentError("node has left the cluster", 403)
    return node_path, node


def _runtime_telemetry(
    control_dir: Path,
    node: dict[str, Any],
    payload: dict[str, Any],
    *,
    now: int,
) -> dict[str, Any]:
    roles = node.get("roles", {})
    if not isinstance(roles, dict):
        roles = {}
    try:
        protocol_version = int(payload.get("protocol_version", 0) or 0)
        schema_version = int(payload.get("state_schema_version", 0) or 0)
    except (TypeError, ValueError):
        protocol_version = 0
        schema_version = 0
    compatible = (
        protocol_version == BPC_PROTOCOL_VERSION
        and schema_version == STATE_SCHEMA_VERSION
    )
    transport = (
        normalize_transport_runtime(payload.get("transport", {}))
        if bool(roles.get("relay"))
        else {}
    )
    return write_node_telemetry(
        control_dir,
        str(node["node_id"]),
        payload=payload,
        compatibility="compatible" if compatible else "incompatible",
        transport=transport,
        now=now,
    )


def node_telemetry(
    control_dir: Path,
    *,
    credential: str,
    payload: dict[str, Any],
    now: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    _, node = authorize_node_telemetry(control_dir, credential)
    telemetry = _runtime_telemetry(
        control_dir,
        node,
        payload,
        now=timestamp,
    )
    return {
        "ok": True,
        "server_time": timestamp,
        "node_id": str(node["node_id"]),
        "compatibility": str(telemetry.get("compatibility", "incompatible")),
    }


def normalize_advertised_routes(values: object) -> list[str]:
    if values in (None, ""):
        return []
    if not isinstance(values, list):
        raise EnrollmentError("advertised_routes must be a list", 400)
    routes: list[str] = []
    seen: set[str] = set()
    for raw in values:
        try:
            network = ipaddress.ip_network(str(raw).strip(), strict=False)
        except ValueError as exc:
            raise EnrollmentError(f"invalid advertised route {raw!r}", 400) from exc
        if network.version != 4 or network.prefixlen == 0:
            raise EnrollmentError("advertised routes must be non-default IPv4 CIDRs", 400)
        canonical = str(network)
        if canonical not in seen:
            seen.add(canonical)
            routes.append(canonical)
    return sorted(routes)


def authorized_node_routes(node: dict[str, Any]) -> list[str]:
    # Upgrade old Nodes by freezing their last canonical advertisements. A
    # heartbeat may never use its own payload as the source of authorization.
    return normalize_advertised_routes(
        node.get("authorized_routes", node.get("advertised_routes", []))
    )


def route_is_authorized(cidr: str, grants: list[str]) -> bool:
    prefix = ipaddress.ip_network(cidr)
    return any(prefix.subnet_of(ipaddress.ip_network(grant)) for grant in grants)


def node_record_digest(path: Path, node: dict[str, Any]) -> str:
    raw = path.read_bytes()
    if json.loads(raw) != node:
        raise EnrollmentError("Node changed concurrently; retry the request", 409)
    return hashlib.sha256(raw).hexdigest()


def _route_path(control_dir: Path, node_id: str, cidr: str) -> Path:
    index = hashlib.sha256(f"{node_id}\0{cidr}".encode()).hexdigest()
    return control_dir / "routes" / f"{index}.json"


def _existing_node_routes(control_dir: Path, node_id: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    directory = control_dir / "routes"
    if not directory.is_dir():
        return result
    for path in directory.glob("*.json"):
        try:
            record = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if str(record.get("node_id", "")) != node_id:
            continue
        cidr = str(record.get("cidr", "")).strip()
        if cidr:
            result[cidr] = path
    return result


def node_heartbeat(
    control_dir: Path,
    *,
    credential: str,
    payload: dict[str, Any],
    now: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    node_path, node = authorize_node(control_dir, credential)
    node_digest = node_record_digest(node_path, node)
    node_id = str(node["node_id"])
    roles = node.get("roles", {})
    if not isinstance(roles, dict):
        roles = {}

    telemetry = _runtime_telemetry(
        control_dir,
        node,
        payload,
        now=timestamp,
    )
    advertised = (
        normalize_advertised_routes(payload.get("advertised_routes", []))
        if bool(roles.get("site_router"))
        else []
    )
    grants = authorized_node_routes(node)
    if any(not route_is_authorized(cidr, grants) for cidr in advertised):
        raise EnrollmentError("advertised route is outside Controller route policy", 403)
    try:
        validate_route_ownership(control_dir, node_id, advertised)
    except TopologyError as exc:
        raise EnrollmentError(str(exc), 409) from exc

    # Identity, capabilities, endpoints and route ownership are canonical.
    # Liveness/service/transport/link samples are ephemeral and never enter Raft.
    canonical_node = dict(node)
    for key in (
        "last_seen",
        "last_status",
        "last_version",
        "protocol_version",
        "state_schema_version",
        "compatibility",
        "services",
        "transport",
    ):
        canonical_node.pop(key, None)
    canonical_node["advertised_routes"] = advertised
    canonical_node["authorized_routes"] = grants

    existing_routes = _existing_node_routes(control_dir, node_id)
    wanted = set(advertised)
    operations: list[dict[str, Any]] = []
    if canonical_node != node:
        operations.append(
            {
                "op": "put",
                "path": node_path,
                "expected_sha256": node_digest,
                "data": json.dumps(
                    canonical_node, sort_keys=True, separators=(",", ":")
                ).encode("utf-8"),
            }
        )

    for cidr in advertised:
        path = _route_path(control_dir, node_id, cidr)
        rewrite = cidr not in existing_routes
        if not rewrite:
            try:
                current_route = read_json(existing_routes[cidr])
            except (OSError, ValueError, json.JSONDecodeError):
                rewrite = True
            else:
                rewrite = (
                    str(current_route.get("owner_node_id", "")) != node_id
                    or str(current_route.get("node_id", "")) != node_id
                    or str(current_route.get("cidr", "")) != cidr
                )
        if rewrite:
            route = {
                "version": 2,
                "cidr": cidr,
                "node_id": node_id,
                "owner_node_id": node_id,
                "updated_at": timestamp,
            }
            operations.append(
                {
                    "op": "put",
                    "path": path,
                    "data": json.dumps(
                        route, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8"),
                }
            )
    for cidr, route_path in existing_routes.items():
        if cidr not in wanted:
            operations.append({"op": "delete", "path": route_path})

    if operations and not any(op["path"] == node_path for op in operations):
        operations.insert(0, {
            "op": "put", "path": node_path, "expected_sha256": node_digest,
            "data": json.dumps(canonical_node, sort_keys=True, separators=(",", ":")).encode(),
        })
    if operations and bpc_control_state.cluster_enabled(control_dir):
        try:
            bpc_control_state.mutation(
                control_dir,
                "ReconcileNodeCanonicalState",
                operations,
                issued_at=timestamp,
            )
        except bpc_control_state.ControlStateError as exc:
            _raise_control_state(exc)
    elif operations:
        for operation in operations:
            target = Path(operation["path"])
            if operation["op"] == "delete":
                target.unlink(missing_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(operation["data"])
                os.chmod(target, 0o600)

    try:
        ensure_topology_links(control_dir, now=timestamp)
        routing = routing_config_for_node(
            control_dir,
            node_id,
            now=timestamp,
        )
    except TopologyError as exc:
        raise EnrollmentError(str(exc), 409) from exc

    return {
        "ok": True,
        "server_time": timestamp,
        "node_id": node_id,
        "name": str(canonical_node["name"]),
        "roles": dict(roles),
        "compatibility": str(telemetry.get("compatibility", "incompatible")),
        "config": {
            "version": 1,
            "heartbeat_interval": HEARTBEAT_INTERVAL,
            "protocol_version": BPC_PROTOCOL_VERSION,
            "state_schema_version": STATE_SCHEMA_VERSION,
            "controllers": controller_public_urls(control_dir.parent),
            "role_config": dict(canonical_node.get("role_config", {})),
            "endpoints": canonical_node.get("endpoints", []),
            "routing": routing,
        },
    }

def leave_node(control_dir: Path, *, credential: str, now: int | None = None) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    node_path, node = authorize_node(control_dir, credential)
    node["revoked"] = True
    node["last_seen"] = timestamp
    node["last_status"] = "left"

    credential_path = control_dir / "node-credentials" / f"{token_index(credential)}.json"
    fingerprint = str(node.get("public_key_fingerprint", ""))
    public_path = (
        control_dir / "node-public-keys" / f"{fingerprint}.json"
        if fingerprint
        else None
    )
    if bpc_control_state.cluster_enabled(control_dir):
        revocation_path = control_dir / "revocations" / f"node-{node['node_id']}.json"
        revocation = {
            "version": 1,
            "kind": "node",
            "subject_id": str(node["node_id"]),
            "revoked_at": timestamp,
            "reason": "node_left",
        }
        operations: list[dict[str, Any]] = [
            {
                "op": "put",
                "path": node_path,
                "data": json.dumps(
                    node, sort_keys=True, separators=(",", ":")
                ).encode("utf-8"),
            },
            {
                "op": "put",
                "path": revocation_path,
                "data": json.dumps(
                    revocation, sort_keys=True, separators=(",", ":")
                ).encode("utf-8"),
            },
            {"op": "delete", "path": credential_path},
        ]
        if public_path is not None:
            operations.append({"op": "delete", "path": public_path})
        for _, route_path in _existing_node_routes(
            control_dir, str(node["node_id"])
        ).items():
            operations.append({"op": "delete", "path": route_path})
        try:
            bpc_control_state.mutation(
                control_dir,
                "RevokeNode",
                operations,
                issued_at=timestamp,
            )
        except bpc_control_state.ControlStateError as exc:
            _raise_control_state(exc)
    else:
        atomic_json(node_path, node)
        credential_path.unlink(missing_ok=True)
        if public_path is not None:
            public_path.unlink(missing_ok=True)
        for _, route_path in _existing_node_routes(
            control_dir, str(node["node_id"])
        ).items():
            route_path.unlink(missing_ok=True)
    return {"ok": True, "node_id": str(node["node_id"])}


def list_nodes(control_dir: Path, now: int | None = None) -> list[dict[str, Any]]:
    timestamp = int(time.time()) if now is None else int(now)
    result: list[dict[str, Any]] = []
    for path in sorted((control_dir / "nodes").glob("*.json")):
        try:
            node = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        result.append(merge_node_telemetry(control_dir, node, now=timestamp))
    return result

def generate_node_identity(state_dir: Path) -> str:
    identity_dir = state_dir / "identity"
    identity_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(identity_dir, 0o700)
    private_path = identity_dir / "node.key"
    if not private_path.is_file():
        tmp = identity_dir / f".node.key.{secrets.token_hex(4)}.tmp"
        completed = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(tmp)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            tmp.unlink(missing_ok=True)
            raise EnrollmentError(
                completed.stderr.strip() or "failed to generate Ed25519 node identity"
            )
        os.chmod(tmp, 0o600)
        os.replace(tmp, private_path)
    os.chmod(private_path, 0o600)

    completed = subprocess.run(
        ["openssl", "pkey", "-in", str(private_path), "-pubout", "-outform", "DER"],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0 or not completed.stdout:
        raise EnrollmentError("failed to derive node public key")
    public_key = base64.b64encode(completed.stdout).decode("ascii")
    (identity_dir / "node.pub").write_text(public_key + "\n", encoding="utf-8")
    os.chmod(identity_dir / "node.pub", 0o644)
    return public_key


def _controller_candidates(
    primary: str,
    alternatives: list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for raw in [primary, *(alternatives or [])]:
        try:
            value = normalize_controller_url(str(raw))
        except EnrollmentError:
            continue
        if value not in seen:
            seen.add(value)
            result.append(value)
    if not result:
        raise EnrollmentError("no valid Controller endpoints are available")
    return result


def request_json(
    controller_url: str,
    path: str,
    payload: dict[str, Any],
    *,
    credential: str | None = None,
    timeout: int = 20,
    controller_urls: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if credential:
        headers["Authorization"] = f"Bearer {credential}"
    context = ssl.create_default_context()
    last_error: EnrollmentError | None = None

    for target in _controller_candidates(controller_url, controller_urls):
        request = urllib.request.Request(
            target + path,
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=timeout,
                context=context,
            ) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:512]
            try:
                parsed = json.loads(detail)
                message = str(parsed.get("error", detail))
            except json.JSONDecodeError:
                message = detail or f"controller returned HTTP {exc.code}"
            error = EnrollmentError(message, exc.code)
            if exc.code not in {502, 503, 504}:
                raise error from exc
            last_error = error
            continue
        except (
            urllib.error.URLError, TimeoutError, ConnectionError, http.client.HTTPException
        ) as exc:
            last_error = EnrollmentError(
                f"controller connection failed via {target}: {exc}"
            )
            continue

        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            last_error = EnrollmentError(
                f"controller {target} returned invalid JSON"
            )
            continue
        if not isinstance(value, dict):
            last_error = EnrollmentError(
                f"controller {target} returned invalid response"
            )
            continue
        value.setdefault("_controller_url", target)
        return value

    if last_error is not None:
        raise last_error
    raise EnrollmentError("all Controller endpoints failed")


def fanout_node_telemetry(
    controller_url: str,
    controller_urls: list[str] | tuple[str, ...],
    payload: dict[str, Any],
    *,
    credential: str,
) -> None:
    # Best effort and parallel: health is expiring runtime state. A slow/dead
    # Controller must not serialize the Node's normal heartbeat path.
    targets = _controller_candidates(controller_url, controller_urls)

    def send(target: str) -> None:
        request_json(
            target,
            "/v1/nodes/telemetry",
            payload,
            credential=credential,
            timeout=3,
            controller_urls=[],
        )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(4, len(targets))
    ) as executor:
        futures = [executor.submit(send, target) for target in targets]
        for future in futures:
            try:
                future.result()
            except EnrollmentError:
                continue

def write_local_enrollment(state_dir: Path, value: dict[str, Any]) -> None:
    atomic_json(state_dir / "enrollment.json", value)


def apply_remote_node_config(
    state_dir: Path,
    *,
    node_id: str,
    name: str,
    public_key: str,
    roles: dict[str, Any],
    created_at: int,
    last_seen: int,
    endpoints: list[dict[str, Any]] | None = None,
    initial_routes: list[str] | None = None,
) -> None:
    role_values = Capabilities.from_mapping(
        {str(key): bool(value) for key, value in roles.items()}
    )
    path = state_dir / "node.yaml"
    advertised_routes = canonical_advertised_routes(initial_routes)
    endpoint_values = canonical_endpoints(endpoints)
    if path.is_file():
        try:
            current = load_node_config(path)
            if current.node.id == node_id:
                created_at = current.node.created_at or created_at
            if current.node.id == node_id or initial_routes is None:
                advertised_routes = current.advertised_routes
            if endpoints is None:
                endpoint_values = current.node.endpoints
        except (OSError, ValueError):
            pass
    config = NodeConfig(
        version=1,
        node=Node(
            id=node_id,
            name=normalize_node_name(name),
            public_key=public_key,
            created_at=int(created_at),
            last_seen=int(last_seen),
            roles=role_values,
            endpoints=endpoint_values,
        ),
        advertised_routes=advertised_routes,
    )
    save_node_config(path, config)


def service_state(name: str) -> str:
    completed = subprocess.run(
        ["systemctl", "is-active", name],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() or "inactive"


def local_services(
    roles: dict[str, Any], role_config: dict[str, Any] | None = None,
) -> dict[str, str]:
    services: dict[str, str] = {"bpc-node": service_state("bpc-node.service")}
    mesh_only = routed_dataplane(role_config or {})
    if bool(roles.get("gateway")):
        services["gateway"] = service_state(
            "bpc-routed-node.service" if mesh_only else "xray.service"
        )
    if bool(roles.get("relay")):
        services["relay"] = service_state(
            "bpc-routed-node.service" if mesh_only else "bpc-agent-relay.service"
        )
    if bool(roles.get("controller")):
        services["controller"] = service_state("bpc-control.service")
        services["distributed-controller"] = service_state("bpc-controld.service")
    if bool(roles.get("gateway")) or bool(roles.get("site_router")):
        services["routed-mesh"] = service_state("bpc-routed-node.service")
    return services


def local_transport_runtime(
    state_dir: Path,
    roles: dict[str, Any],
) -> dict[str, Any]:
    if not bool(roles.get("relay")):
        return {}
    runtime = compatibility_agent_runtime_env(state_dir)
    if not runtime.is_file():
        return {}
    ports: list[int] = []
    raw_ports = read_env_value(runtime, "AGENT_WGSHIM_PORTS")
    for raw in raw_ports.split(","):
        try:
            port = int(raw.strip())
        except ValueError:
            continue
        if 1024 <= port <= 65535 and port not in ports:
            ports.append(port)
    try:
        tcp_port = int(read_env_value(runtime, "AGENT_WGSHIM_TCP_PORT") or "0")
    except ValueError:
        tcp_port = 0
    return normalize_transport_runtime(
        {
            "udp_ports": ports,
            "tcp_port": tcp_port,
            "overlay_public_key": read_env_value(
                runtime, "AGENT_WG_SERVER_PUBLIC_KEY"
            ),
        }
    )


def local_routed_links() -> list[dict[str, Any]]:
    path = Path("/run/bpc-connect/routed-status.json")
    if not path.is_file():
        return []
    try:
        value = read_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return []
    links = value.get("links", [])
    if not isinstance(links, list):
        return []
    return [dict(item) for item in links if isinstance(item, dict)][:64]


def _routed_binary() -> Path:
    machine = os.uname().machine.lower()
    if machine in {"x86_64", "amd64"}:
        arch = "amd64"
    elif machine in {"aarch64", "arm64"}:
        arch = "arm64"
    else:
        raise EnrollmentError(f"unsupported routed mesh architecture: {machine}")
    root = Path(os.environ.get("BPC_ROOT", "/opt/bpc"))
    return root / "current" / "bin" / f"bpc-routed-node-linux-{arch}"


def reconcile_routed_runtime(
    state_dir: Path,
    enrollment: dict[str, Any],
) -> None:
    roles = enrollment.get("roles", {})
    config = enrollment.get("config", {})
    routing = config.get("routing", {}) if isinstance(config, dict) else {}
    enabled = (
        isinstance(roles, dict)
        and (bool(roles.get("gateway")) or bool(roles.get("site_router")))
        and isinstance(routing, dict)
        and int(routing.get("version", 0) or 0) > 0
        and bool(routing.get("links"))
    )
    unit = Path("/etc/systemd/system/bpc-routed-node.service")
    if not unit.is_file():
        return
    if enabled:
        binary = _routed_binary()
        if not binary.is_file():
            raise EnrollmentError(f"routed mesh binary is missing: {binary}")
        subprocess.run(
            ["systemctl", "enable", "--now", "bpc-routed-node.service"],
            check=True,
        )
    else:
        subprocess.run(
            ["systemctl", "disable", "--now", "bpc-routed-node.service"],
            check=False,
            capture_output=True,
        )


def reconcile_roles(
    state_dir: Path,
    roles: dict[str, Any],
    role_config: dict[str, Any],
) -> dict[str, str]:
    try:
        return reconcile_transport_roles(
            state_dir,
            roles,
            role_config,
            deploy_dir=ROOT / "deploy",
        )
    except RuntimeCompatibilityError as exc:
        raise EnrollmentError(str(exc)) from exc


def stage_node_runtime(state_dir: Path) -> Path:
    with security_runtime_lock(state_dir):
        return _stage_node_runtime_locked(state_dir)


def _stage_node_runtime_locked(state_dir: Path) -> Path:
    version_path = ROOT / "VERSION"
    version = (
        version_path.read_text(encoding="utf-8").strip()
        if version_path.is_file()
        else "source"
    )
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}", version):
        raise EnrollmentError("invalid BPC runtime version")

    release_deploy = ROOT / "deploy"
    release_package = ROOT / "src" / "bpc_connect"
    if not (release_deploy / "bpc_node_enrollment.py").is_file():
        raise EnrollmentError("BPC Node enrollment runtime is missing")
    if not release_package.is_dir():
        raise EnrollmentError("BPC Python package is missing")

    runtime_version = state_dir / f"runtime-{version}"
    runtime_link = state_dir / "runtime"
    runtime_tmp = state_dir / f".runtime.{secrets.token_hex(4)}"
    runtime_tmp.mkdir(parents=True, mode=0o700)
    try:
        shutil.copytree(release_deploy, runtime_tmp / "deploy")
        (runtime_tmp / "src").mkdir(mode=0o700)
        shutil.copytree(release_package, runtime_tmp / "src" / "bpc_connect")
        (runtime_tmp / "VERSION").write_text(version + "\n", encoding="utf-8")

        # Security state is runtime data, not release content. Keep the signed
        # bytes, trust and revision floor across upgrades and same-version repair.
        for name in ("security-snapshot.json", "security-trust.json"):
            previous = runtime_link / name
            if previous.is_file():
                shutil.copyfile(previous, runtime_tmp / name)

        for directory in [runtime_tmp, *runtime_tmp.rglob("*")]:
            if directory.is_dir():
                os.chmod(directory, 0o700)
            elif directory.is_file():
                mode = 0o700 if directory.suffix == ".sh" else 0o600
                os.chmod(directory, mode)

        if runtime_version.exists():
            shutil.rmtree(runtime_version)
        os.replace(runtime_tmp, runtime_version)
    finally:
        if runtime_tmp.exists():
            shutil.rmtree(runtime_tmp)

    if runtime_link.exists() and not runtime_link.is_symlink():
        if runtime_link.is_dir():
            shutil.rmtree(runtime_link)
        else:
            runtime_link.unlink()
    link_tmp = state_dir / f".runtime-link.{secrets.token_hex(4)}"
    link_tmp.symlink_to(runtime_version.name)
    os.replace(link_tmp, runtime_link)
    return runtime_link


def running_routed_executable() -> Path | None:
    completed = subprocess.run(
        ["systemctl", "show", "--property=MainPID", "--value", "bpc-routed-node.service"],
        check=False, capture_output=True, text=True,
    )
    pid = completed.stdout.strip()
    if completed.returncode != 0:
        raise EnrollmentError("cannot inspect running routed runtime during update")
    if pid == "0":
        return None
    if not pid.isdecimal() or int(pid) <= 0:
        raise EnrollmentError("invalid routed runtime MainPID")
    return Path("/proc") / pid / "exe"


def restart_changed_routed_runtime() -> bool:
    running = running_routed_executable()
    if running is None:
        return False
    try:
        with running.open("rb") as handle:
            before = hashlib.file_digest(handle, "sha256").digest()
        with _routed_binary().open("rb") as handle:
            after = hashlib.file_digest(handle, "sha256").digest()
    except OSError as exc:
        raise EnrollmentError("cannot verify routed binary during update") from exc
    if before == after:
        return False
    subprocess.run(["systemctl", "restart", "bpc-routed-node.service"], check=True)
    return True


def install_runtime_service(state_dir: Path) -> None:
    runtime = stage_node_runtime(state_dir)
    runtime_entrypoint = runtime / "deploy" / "bpc_node_enrollment.py"
    unit = Path("/etc/systemd/system/bpc-node.service")
    content = f"""[Unit]
Description=BPC Node control-plane runtime
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {runtime_entrypoint} \
  --state-dir {state_dir} daemon
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths={state_dir}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
"""
    unit.write_text(content, encoding="utf-8")
    os.chmod(unit, 0o644)

    reconcile_service = Path("/etc/systemd/system/bpc-gateway-reconcile.service")
    reconcile_service.write_text(
        f"""[Unit]
Description=BPC Gateway replicated-state reconcile
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {runtime_entrypoint} \\
  --state-dir {state_dir} local-reconcile
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths={state_dir}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
""",
        encoding="utf-8",
    )
    os.chmod(reconcile_service, 0o644)

    reconcile_path = Path("/etc/systemd/system/bpc-gateway-reconcile.path")
    reconcile_path.write_text(
        f"""[Unit]
Description=Watch replicated BPC Gateway state

[Path]
PathChanged={state_dir / "control" / "devices"}
PathChanged={state_dir / "control" / "access"}
PathChanged={state_dir / "control" / "config.json"}
Unit=bpc-gateway-reconcile.service

[Install]
WantedBy=multi-user.target
""",
        encoding="utf-8",
    )
    os.chmod(reconcile_path, 0o644)

    routed_binary = _routed_binary()
    routed_unit = Path("/etc/systemd/system/bpc-routed-node.service")
    routed_unit.write_text(
        f"""[Unit]
Description=BPC routed mesh dataplane
After=network-online.target bpc-node.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={routed_binary} \\
  --enrollment {state_dir / "enrollment.json"} \\
  --interface bpcrt0 \\
  --status /run/bpc-connect/routed-status.json
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths={state_dir}
RuntimeDirectory=bpc-connect
RuntimeDirectoryMode=0755
ReadWritePaths=/run/bpc-connect
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
""",
        encoding="utf-8",
    )
    os.chmod(routed_unit, 0o644)

    current = enrolled_state(state_dir)
    current_roles = current.get("roles", {}) if isinstance(current, dict) else {}
    if (
        isinstance(current_roles, dict)
        and (
            bool(current_roles.get("gateway"))
            or bool(current_roles.get("site_router"))
        )
    ):
        sysctl = Path("/etc/sysctl.d/93-bpc-routed.conf")
        sysctl.write_text("net.ipv4.ip_forward=1\n", encoding="ascii")
        os.chmod(sysctl, 0o644)
        subprocess.run(["sysctl", "-q", "-p", str(sysctl)], check=True)

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "bpc-node.service"], check=True)
    subprocess.run(
        ["systemctl", "enable", "--now", "bpc-gateway-reconcile.path"],
        check=True,
    )
    subprocess.run(["systemctl", "restart", "bpc-node.service"], check=True)
    routing = current.get("config", {}).get("routing", {}) if isinstance(current, dict) else {}
    if isinstance(routing, dict) and routing.get("links"):
        restart_changed_routed_runtime()


def enrolled_state(state_dir: Path) -> dict[str, Any] | None:
    path = state_dir / "enrollment.json"
    if not path.is_file():
        return None
    return read_json(path)


def _local_advertised_routes(state_dir: Path) -> list[str]:
    path = state_dir / "node.yaml"
    if not path.is_file():
        return []
    try:
        config = load_node_config(path)
    except (OSError, ValueError):
        return []
    return list(config.advertised_routes)


def reconcile_local_gateway_state(state_dir: Path) -> None:
    lock_path = state_dir / "gateway-reconcile.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("a+", encoding="ascii") as lock_handle:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            reconcile_gateway_dataplane(state_dir)
            sync_access_firewall(state_dir / "control")
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def reconcile_startup_gateway_state(
    state_dir: Path,
    roles: dict[str, Any],
) -> bool:
    """Restore replicated gateway peers/Access before the first remote heartbeat.

    A reboot recreates the WireGuard interface from its interface-only wg-quick
    config, so kernel peer/endpoints are empty until canonical replicated state
    is reconciled. Do this immediately after transport roles start instead of
    depending on Controller reachability or the next heartbeat.
    """
    if not bool(roles.get("gateway")):
        return False
    if (enrollment_uses_routed_dataplane(enrolled_state(state_dir) or {})
            and not primary_compat_runtime(state_dir)):
        return False
    if not (state_dir / "control" / "config.json").is_file():
        return False
    try:
        reconcile_local_gateway_state(state_dir)
    except (
        GatewayDataplaneError,
        AccessError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise EnrollmentError(
            f"Gateway startup dataplane reconciliation failed: {exc}"
        ) from exc
    return True


def send_heartbeat(state_dir: Path, enrollment: dict[str, Any]) -> dict[str, Any]:
    roles = enrollment.get("roles", {})
    if not isinstance(roles, dict):
        roles = {}
    controllers = enrollment.get("controllers", [])
    if not isinstance(controllers, list):
        controllers = []
    software_version = (
        (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        if (ROOT / "VERSION").is_file()
        else "source"
    )
    payload = {
        "status": "online",
        "version": software_version,
        "protocol_version": BPC_PROTOCOL_VERSION,
        "state_schema_version": STATE_SCHEMA_VERSION,
        "advertised_routes": _local_advertised_routes(state_dir),
        "services": local_services(roles, enrollment.get("config", {}).get("role_config", {})),
        "transport": (
            {} if enrollment_uses_routed_dataplane(enrollment)
            else local_transport_runtime(state_dir, roles)
        ),
        "links": local_routed_links(),
    }
    credential = str(enrollment["credential"])
    fanout_node_telemetry(
        str(enrollment["controller_url"]),
        [str(item) for item in controllers],
        payload,
        credential=credential,
    )
    response = request_json(
        str(enrollment["controller_url"]),
        "/v1/nodes/heartbeat",
        payload,
        credential=credential,
        controller_urls=[str(item) for item in controllers],
    )
    selected = str(response.pop("_controller_url", enrollment["controller_url"]))
    enrollment["controller_url"] = selected

    response_roles = response.get("roles", {})
    config = response.get("config", {})
    if isinstance(response_roles, dict):
        enrollment["roles"] = response_roles
        roles = response_roles
    if isinstance(config, dict):
        enrollment["config"] = config
        response_controllers = config.get("controllers", [])
        if isinstance(response_controllers, list):
            pool = _controller_candidates(
                selected,
                [*[str(item) for item in controllers],
                 *[str(item) for item in response_controllers]],
            )
            enrollment["controllers"] = pool

    if bool(roles.get("gateway")):
        snapshot = response.get("security_snapshot")
        verification_key = str(
            response.get("security_snapshot_verification_key", "")
        ).strip()
        if not isinstance(snapshot, dict) or not verification_key:
            raise EnrollmentError("Gateway security snapshot is missing")
        try:
            installed = install_security_snapshot(
                state_dir,
                snapshot,
                verification_key,
            )
        except GatewaySnapshotError as exc:
            raise EnrollmentError(str(exc)) from exc
        enrollment["security_revision"] = int(installed.get("revision", 0))
        enrollment["security_expires_at"] = int(installed.get("expires_at", 0))
        control_config = state_dir / "control" / "config.json"
        if control_config.is_file() and not enrollment_uses_routed_dataplane(enrollment):
            try:
                reconcile_local_gateway_state(state_dir)
            except (
                GatewayDataplaneError,
                AccessError,
                OSError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                raise EnrollmentError(
                    f"Gateway dataplane reconciliation failed: {exc}"
                ) from exc

    enrollment["last_heartbeat"] = int(response.get("server_time", time.time()))
    write_local_enrollment(state_dir, enrollment)
    reconcile_routed_runtime(state_dir, enrollment)
    public_key = (state_dir / "identity" / "node.pub").read_text(
        encoding="utf-8"
    ).strip()
    apply_remote_node_config(
        state_dir,
        node_id=str(enrollment["node_id"]),
        name=str(enrollment["name"]),
        public_key=public_key,
        roles=dict(enrollment.get("roles", {})),
        created_at=int(enrollment.get("created_at", 0)),
        last_seen=int(enrollment["last_heartbeat"]),
        endpoints=enrollment.get("config", {}).get("endpoints"),
    )
    return response


def authorize_site_routes(control_dir: Path, node_id: str, routes: list[str]) -> None:
    """Controller-admin operation; never exposed through Node heartbeat."""
    if not re.fullmatch(r"[0-9a-f]{32}", node_id):
        raise EnrollmentError("invalid Node ID")
    strong_read(control_dir)
    path = control_dir / "nodes" / f"{node_id}.json"
    node = read_json(path)
    digest = node_record_digest(path, node)
    if node.get("revoked") or not node.get("roles", {}).get("site_router"):
        raise EnrollmentError("route policy requires an active site_router", 409)
    grants = normalize_advertised_routes(authorized_node_routes(node) + routes)
    try:
        validate_route_ownership(control_dir, node_id, grants)
    except TopologyError as exc:
        raise EnrollmentError(str(exc), 409) from exc
    node["authorized_routes"] = grants
    if bpc_control_state.cluster_enabled(control_dir):
        try:
            bpc_control_state.mutation(control_dir, "AuthorizeSiteRoutes", [{
                "op": "put", "path": path, "expected_sha256": digest,
                "data": json.dumps(node, sort_keys=True, separators=(",", ":")).encode(),
            }])
        except bpc_control_state.ControlStateError as exc:
            _raise_control_state(exc)
    else:
        atomic_json(path, node)


def public_node_endpoints(hosts: list[str]) -> list[dict[str, Any]]:
    endpoints = [item.to_mapping() for item in canonical_endpoints(
        [{"host": host} for host in hosts]
    )]
    if not endpoints:
        raise EnrollmentError("public-node requires --host with a public DNS hostname")
    for endpoint in endpoints:
        host = endpoint["host"]
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if "." in host:
                continue
        raise EnrollmentError("public-node requires a public DNS hostname")
    return endpoints


def primary_compat_runtime(state_dir: Path) -> bool:
    """The bootstrap API owns the existing Agent transport independently of mesh."""
    if read_env_value(state_dir / "control" / "runtime.env", "CONTROL_MODE") != "primary":
        return False
    node = load_node_config(state_dir / "node.yaml")
    cluster = read_json(state_dir / "cluster" / "cluster.json")
    marker = read_json(state_dir / "cluster" / "controller.json")
    return (cluster.get("controller_node_id") == node.node.id
            and marker.get("node_id") == node.node.id)


def durable_local_json(path: Path, value: dict[str, Any]) -> None:
    """Persist a registration credential before committing its hash through Raft."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def cmd_mesh_enable(args: argparse.Namespace) -> int:
    """Enroll the existing bootstrap identity; never bootstrap or replace transports."""
    if os.geteuid() != 0:
        raise EnrollmentError("run mesh-enable as root")
    if args.control_dir.resolve() != (args.state_dir / "control").resolve():
        raise EnrollmentError("mesh-enable requires the local canonical control directory")
    endpoints = public_node_endpoints(args.host)
    if not primary_compat_runtime(args.state_dir):
        raise EnrollmentError("mesh-enable requires the existing bootstrap primary API")
    node = load_node_config(args.state_dir / "node.yaml").node
    if not all(node.roles.has(role) for role in ("controller", "gateway", "relay")):
        raise EnrollmentError("bootstrap Node must already have controller,gateway,relay roles")
    if load_node_config(args.state_dir / "node.yaml").advertised_routes:
        raise EnrollmentError("bootstrap mesh enrollment does not authorize site routes")
    # Derive, but never regenerate or rewrite, the existing identity.
    derived = subprocess.run([
        "openssl", "pkey", "-in", str(args.state_dir / "identity" / "node.key"),
        "-pubout", "-outform", "DER",
    ], check=True, capture_output=True)
    public_key = base64.b64encode(derived.stdout).decode("ascii")
    if public_key != node.public_key or public_key != (
        args.state_dir / "identity" / "node.pub"
    ).read_text().strip():
        raise EnrollmentError("existing Node identity does not match its private key")
    strong_read(args.control_dir)
    member = read_json(args.state_dir / "cluster" / "controllers" / f"{node.id}.json")
    marker = read_json(args.state_dir / "cluster" / "controller.json")
    if (member.get("node_id") != node.id or member.get("state") != "voter"
            or member.get("raft_address") != marker.get("raft_address")):
        raise EnrollmentError("bootstrap Controller membership does not match local runtime")
    public_url = normalize_controller_url(str(member.get("public_url", "")))
    if urllib.parse.urlparse(public_url).hostname not in [item["host"] for item in endpoints]:
        raise EnrollmentError("mesh host must include the existing public API hostname")
    role_map = dict(node.roles.values)
    role_config = default_role_config(args.state_dir, [r for r, on in role_map.items() if on],
                                      dataplane="routed")
    journal_path = args.state_dir / "runtime" / "bootstrap-mesh-registration.json"
    lock_path = args.state_dir / ".bootstrap-mesh-registration.lock"
    with lock_path.open("a") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = enrolled_state(args.state_dir)
        journal = read_json(journal_path) if journal_path.is_file() else current
        if journal is not None:
            if (journal.get("node_id") != node.id or journal.get("runtime_mode") != "primary"
                    or journal.get("config", {}).get("endpoints") != endpoints
                    or journal.get("roles") != role_map):
                raise EnrollmentError("existing enrollment/registration conflicts with mesh-enable")
        else:
            journal = {
                "version": 1, "runtime_mode": "primary", "node_id": node.id,
                "name": node.name, "created_at": node.created_at,
                "joined_at": int(time.time()), "last_heartbeat": 0,
                "controller_url": public_url, "controllers": controller_public_urls(args.state_dir),
                "credential": secrets.token_hex(32), "roles": role_map,
                "config": {"version": 1, "heartbeat_interval": HEARTBEAT_INTERVAL,
                           "role_config": role_config, "endpoints": endpoints,
                           "advertised_routes": []},
            }
            # Before Raft: a lost response or interrupted local write can reuse this credential.
            durable_local_json(journal_path, journal)
        credential = str(journal.get("credential", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", credential):
            raise EnrollmentError("invalid saved bootstrap mesh credential")
        if current is not None and (current.get("credential") != credential
                                    or current.get("node_id") != node.id):
            raise EnrollmentError("local enrollment conflicts with saved registration")
        strong_read(args.control_dir)
        node_path = args.control_dir / "nodes" / f"{node.id}.json"
        fingerprint = public_key_fingerprint(public_key)
        indexes = [
            args.control_dir / "node-public-keys" / f"{fingerprint}.json",
            args.control_dir / "node-credentials" / f"{token_index(credential)}.json",
        ]
        if node_path.is_file():
            record = read_json(node_path)
            if (record.get("revoked") or record.get("public_key") != public_key
                    or record.get("roles") != role_map or record.get("endpoints") != endpoints
                    or record.get("role_config") != role_config
                    or any(not p.is_file() or read_json(p).get("node_id") != node.id
                           for p in indexes)):
                raise EnrollmentError("canonical bootstrap registration conflicts or is revoked")
        else:
            if current is not None or any(p.exists() for p in indexes):
                raise EnrollmentError("partial/conflicting canonical bootstrap registration")
            record = {
                "version": 1, "node_id": node.id, "name": node.name, "public_key": public_key,
                "public_key_fingerprint": fingerprint, "roles": role_map,
                "role_config": role_config, "endpoints": endpoints,
                "advertised_routes": [], "authorized_routes": [],
                "created_at": node.created_at, "last_seen": 0, "revoked": False,
                "last_status": "registered", "last_version": "", "services": {},
            }
            operations = [{"op": "put", "path": node_path, "if_absent": True,
                           "data": json.dumps(record, sort_keys=True,
                                              separators=(",", ":")).encode()}]
            operations.extend({"op": "put", "path": p, "if_absent": True,
                               "data": json.dumps({"node_id": node.id}).encode()} for p in indexes)
            try:
                bpc_control_state.mutation(
                    args.control_dir, "RegisterBootstrapMeshNode", operations,
                )
            except bpc_control_state.ControlStateError as exc:
                _raise_control_state(exc)
        if current is None:
            durable_local_json(args.state_dir / "enrollment.json", journal)
        # No Controller provisioning, transport reconciliation, or API restart here.
        install_runtime_service(args.state_dir)
        send_heartbeat(args.state_dir, enrolled_state(args.state_dir) or journal)
    print(f"Bootstrap mesh enabled: {node.name} ({node.id}); primary API/compatibility preserved")
    return 0


def cmd_node_configure(args: argparse.Namespace) -> int:
    """Promote an enrolled Controller without a new identity or join token.

    Controller membership is deliberately not edited by role configuration.
    Converting an existing compatibility Gateway requires a separate migration.
    """
    if not re.fullmatch(r"[0-9a-f]{32}", args.node_id):
        raise EnrollmentError("invalid Node ID")
    endpoints = public_node_endpoints(args.host)
    if not bpc_control_state.cluster_enabled(args.control_dir):
        raise EnrollmentError("node configure requires distributed control plane")
    strong_read(args.control_dir)
    path = args.control_dir / "nodes" / f"{args.node_id}.json"
    node = read_json(path)
    digest = node_record_digest(path, node)
    roles = node.get("roles", {})
    if node.get("revoked") or not isinstance(roles, dict) or not roles.get("controller"):
        raise EnrollmentError("public-node promotion requires an active enrolled Controller", 409)
    old_config = node.get("role_config", {})
    if (roles.get("gateway") or roles.get("relay")) and not (
        isinstance(old_config, dict) and routed_dataplane(old_config)
    ):
        raise EnrollmentError("existing compatibility transports require explicit migration", 409)
    node["roles"] = {**roles, "gateway": True, "relay": True}
    node["role_config"] = default_role_config(
        args.state_dir, [role for role, enabled in node["roles"].items() if enabled],
        dataplane="routed",
    )
    node["endpoints"] = endpoints
    try:
        bpc_control_state.mutation(args.control_dir, "ConfigurePublicNode", [{
            "op": "put", "path": path, "expected_sha256": digest,
            "data": json.dumps(node, sort_keys=True, separators=(",", ":")).encode(),
        }])
    except bpc_control_state.ControlStateError as exc:
        _raise_control_state(exc)
    print(f"Public Node configured: {node['name']} ({args.node_id}); dataplane=routed")
    return 0


def cmd_node_create(args: argparse.Namespace) -> int:
    roles = list(NODE_PRESETS[args.preset])
    endpoints = [item.to_mapping() for item in canonical_endpoints(
        [{"host": host} for host in args.host]
    )]
    if args.preset == "public-node":
        endpoints = public_node_endpoints(args.host)
        if not bpc_control_state.cluster_enabled(args.control_dir):
            raise EnrollmentError("public-node requires an initialized distributed control plane")
    controller_url = args.controller_url or discover_controller_url(args.control_dir)
    strong_read(args.control_dir)
    token = create_join_token(
        args.control_dir, controller_url=controller_url, roles=roles, name=args.name,
        expires_in=parse_duration(args.expires), endpoints=endpoints,
        advertised_routes=args.route,
        role_config=default_role_config(args.state_dir, roles, dataplane=args.dataplane),
    )
    bootstrap = "https://github.com/RomanKrike/bpc/releases/latest/download/install.sh"
    print(f"Node invitation: {args.name} ({', '.join(roles)}); expires in {args.expires}")
    print("Run as root on the target Node:")
    print(f"curl -fsSL {bootstrap} | bash -s -- join {shlex.quote(token)}")
    return 0


def cmd_token_create(args: argparse.Namespace) -> int:
    roles = normalize_roles(args.roles)
    controller_url = (
        normalize_controller_url(args.controller_url)
        if args.controller_url
        else discover_controller_url(args.control_dir)
    )
    if args.dataplane == "routed" and (args.gateway_port or args.gateway_reality_server_name):
        raise EnrollmentError("legacy Gateway options cannot be used with --dataplane routed")
    role_config = default_role_config(args.state_dir, roles, dataplane=args.dataplane)
    if "gateway" in role_config:
        if args.gateway_reality_server_name:
            role_config["gateway"]["reality_server_name"] = args.gateway_reality_server_name
        if args.gateway_port:
            role_config["gateway"]["xray_port"] = args.gateway_port
    token = create_join_token(
        args.control_dir,
        controller_url=controller_url,
        roles=roles,
        name=args.name,
        expires_in=parse_duration(args.expires),
        role_config=role_config,
    )
    print(token)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    nodes = list_nodes(args.control_dir)
    if not nodes:
        print("No enrolled Nodes.")
        return 0
    for node in nodes:
        roles = ",".join(
            sorted(
                str(role)
                for role, enabled in dict(node.get("roles", {})).items()
                if enabled
            )
        )
        state = "online" if node.get("online") else "offline"
        if node.get("revoked"):
            state = "left"
        print(
            f"{node.get('name')}\t{node.get('node_id')}\t{roles or '-'}\t"
            f"{state}\tlast_seen={node.get('last_seen', 0)}"
        )
    return 0


def resume_controller_provisioning(state_dir: Path, enrollment: dict[str, Any]) -> None:
    """Resume durable enrollment phases without consuming another invitation."""
    if not enrollment.get("roles", {}).get("controller"):
        return
    progress = enrollment.get("controller_provision")
    if not isinstance(progress, dict):
        # Older, fully configured Controllers have no provisioning journal.
        if (state_dir / "cluster" / "controller.json").is_file():
            return
        raise EnrollmentError("Controller enrollment is incomplete and has no recovery material")
    if progress.get("complete"):
        subprocess.run(["systemctl", "start", "bpc-controld.service"], check=True)
        return
    payload = progress["payload"]
    host = str(payload["advertise_host"])
    software_version = (
        (ROOT / "VERSION").read_text().strip() if (ROOT / "VERSION").is_file() else "source"
    )

    def checkpoint(phase: str) -> None:
        progress[phase] = True
        write_local_enrollment(state_dir, enrollment)

    def run_helper(name: str, *arguments: str) -> None:
        env = dict(os.environ, BPC_STATE_DIR=str(state_dir))
        result = subprocess.run([str(ROOT / "deploy" / name), *arguments], check=False, env=env)
        if result.returncode:
            raise EnrollmentError(
                f"{name} failed ({result.returncode}); rerun the same join command"
            )

    if not progress.get("trust_installed"):
        try:
            install_controller_enrollment(state_dir, payload)
        except ControllerEnrollmentError as exc:
            raise EnrollmentError(str(exc)) from exc
        checkpoint("trust_installed")
    if not progress.get("raft_ready"):
        # Reconcile/restart the runtime even if the previous attempt died after
        # service startup. Never re-bootstrap or replace an existing Raft log.
        run_helper("bpc-enable-cluster.sh", "--advertise-host", host, "--defer-marker")
        ready = request_json(
            str(enrollment["controller_url"]), "/v1/nodes/controller-ready",
            {"node_id": enrollment["node_id"]}, credential=str(enrollment["credential"]),
            timeout=90, controller_urls=enrollment.get("controllers", []),
        )
        if ready.get("state") != "voter":
            raise EnrollmentError("Controller did not complete voter promotion")
        checkpoint("raft_ready")
    try:
        activate_controller_marker(
            state_dir, node_id=str(enrollment["node_id"]), payload=payload,
            software_version=software_version,
        )
    except ControllerEnrollmentError as exc:
        raise EnrollmentError(str(exc)) from exc
    run_helper("bpc-enable-control-replica.sh", "--hostname", host)
    # Trust material now has its canonical local PKI files. Do not retain a
    # second CA private-key copy in the finished enrollment journal.
    progress["payload"] = {"advertise_host": host}
    checkpoint("complete")


def require_role_health(roles: dict[str, Any], results: dict[str, str]) -> None:
    for role, enabled in roles.items():
        if enabled and results.get(role) not in {"active", "configured"}:
            raise EnrollmentError(f"Node capability {role} is not ready: {results.get(role)}")


def reconcile_controller_runtime(state_dir: Path) -> None:
    """Update an existing Controller without bootstrap, identity or PKI changes."""
    marker_path = state_dir / "cluster" / "controller.json"
    if not marker_path.is_file():
        raise EnrollmentError("existing Controller marker is required")
    marker = read_json(marker_path)
    node = load_node_config(state_dir / "node.yaml")
    if marker.get("node_id") != node.node.id or not node.node.roles.has("controller"):
        raise EnrollmentError("Controller marker does not match local Node identity")
    enrollment = enrolled_state(state_dir)
    if (enrollment is not None and enrollment.get("runtime_mode") == "primary"
            and not primary_compat_runtime(state_dir)):
        raise EnrollmentError("bootstrap primary API mode/identity is inconsistent")
    if enrollment is not None:
        progress = enrollment.get("controller_provision", {})
        if isinstance(progress, dict) and progress and not progress.get("complete"):
            resume_controller_provisioning(state_dir, enrollment)
            return

    def address(key: str) -> tuple[str, int]:
        host, separator, raw_port = str(marker.get(key, "")).rpartition(":")
        if not separator or not host or ":" in host:
            raise EnrollmentError(f"invalid existing Controller {key}")
        port = int(raw_port)
        if not 1024 <= port <= 65535:
            raise EnrollmentError(f"invalid existing Controller {key}")
        return host, port

    host, raft_port = address("raft_address")
    api_host, api_port = address("cluster_api_address")
    _, local_port = address("local_api_address")
    if api_host != host:
        raise EnrollmentError("Controller advertised hosts do not agree")
    protected = [
        state_dir / "identity" / "node.key",
        state_dir / "identity" / "node.pub",
        Path(str(marker["certificate_file"])),
        Path(str(marker["key_file"])),
        Path(str(marker["ca_file"])),
        Path(str(marker["local_api_token_file"])),
    ]
    ca_key = state_dir / "cluster" / "pki" / "cluster-ca.key"
    if ca_key.is_file():
        protected.append(ca_key)
    fingerprints = {path: hashlib.sha256(path.read_bytes()).digest() for path in protected}
    env = dict(os.environ, BPC_STATE_DIR=str(state_dir))
    runtime_env = state_dir / "control" / "runtime.env"
    public_port = read_env_value(runtime_env, "CONTROL_PORT")
    if public_port:
        env["BPC_CONTROL_PORT"] = public_port
    command = [
        str(ROOT / "deploy" / "bpc-enable-cluster.sh"),
        "--advertise-host", host, "--raft-port", str(raft_port),
        "--cluster-api-port", str(api_port), "--local-api-port", str(local_port),
    ]
    completed = subprocess.run(command, check=False, env=env)
    if completed.returncode:
        raise EnrollmentError("existing Controller runtime reconciliation failed")
    if any(hashlib.sha256(path.read_bytes()).digest() != digest
           for path, digest in fingerprints.items()):
        raise EnrollmentError("Controller runtime changed protected identity or PKI files")
    if (enrollment is not None and enrollment.get("roles", {}).get("controller")
            and not primary_compat_runtime(state_dir)):
        completed = subprocess.run([
            str(ROOT / "deploy" / "bpc-enable-control-replica.sh"), "--hostname", host,
            "--port", public_port or "8444",
        ], check=False, env=env)
        if completed.returncode:
            raise EnrollmentError("Controller public API runtime reconciliation failed")


def cmd_join(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise EnrollmentError("run bpc join as root")
    existing = enrolled_state(args.state_dir)
    if existing is not None:
        roles = existing.get("roles", {})
        config = existing.get("config", {})
        if not isinstance(roles, dict):
            roles = {}
        if not isinstance(config, dict):
            config = {}
        role_config = config.get("role_config", {})
        if not isinstance(role_config, dict):
            role_config = {}
        if "controller_provision" in existing:
            public_key = (args.state_dir / "identity" / "node.pub").read_text().strip()
            apply_remote_node_config(
                args.state_dir, node_id=str(existing["node_id"]), name=str(existing["name"]),
                public_key=public_key, roles=roles, created_at=int(existing["created_at"]),
                last_seen=int(time.time()), endpoints=config.get("endpoints"),
                initial_routes=config.get("advertised_routes"),
            )
        resume_controller_provisioning(args.state_dir, existing)
        results = reconcile_roles(args.state_dir, roles, role_config)
        require_role_health(roles, results)
        install_runtime_service(args.state_dir)
        send_heartbeat(args.state_dir, existing)
        print(
            f"Node is already joined: {existing.get('name')} "
            f"({existing.get('node_id')}); enrollment preserved and runtime reconciled."
        )
        for role, state in sorted(results.items()):
            print(f"  {role}: {state}")
        return 0

    controller_urls, _ = parse_join_token_endpoints(args.token)
    controller_url = controller_urls[0]
    public_key = generate_node_identity(args.state_dir)
    try:
        controller_csr = ensure_controller_csr(args.state_dir)
    except ControllerEnrollmentError as exc:
        raise EnrollmentError(str(exc)) from exc
    software_version = (
        (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        if (ROOT / "VERSION").is_file()
        else "source"
    )
    response = request_json(
        controller_url,
        "/v1/nodes/join",
        {
            "token": args.token,
            "public_key": public_key,
            "name": socket.gethostname()[:64] or "bpc-node",
            "version": software_version,
            "protocol_version": BPC_PROTOCOL_VERSION,
            "state_schema_version": STATE_SCHEMA_VERSION,
            "controller_csr": controller_csr,
            "controller_advertise_host": getattr(
                args, "controller_advertise_host", None
            )
            or "",
        },
        controller_urls=controller_urls,
    )
    roles = response.get("roles", {})
    config = response.get("config", {})
    if not isinstance(roles, dict) or not isinstance(config, dict):
        raise EnrollmentError("controller returned invalid enrollment configuration")
    selected_controller = str(response.pop("_controller_url", controller_url))
    enrollment = {
        "version": 1,
        "controller_url": selected_controller,
        "controllers": _controller_candidates(
            selected_controller,
            [
                *controller_urls,
                *(
                    [
                        str(item)
                        for item in response.get("config", {}).get("controllers", [])
                    ]
                    if isinstance(response.get("config"), dict)
                    and isinstance(response.get("config", {}).get("controllers"), list)
                    else []
                ),
            ],
        ),
        "node_id": str(response["node_id"]),
        "name": str(response["name"]),
        "credential": str(response["credential"]),
        "created_at": int(response.get("created_at", time.time())),
        "joined_at": int(time.time()),
        "last_heartbeat": 0,
        "roles": roles,
        "config": config,
    }
    if roles.get("controller"):
        payload = response.get("controller")
        if not isinstance(payload, dict):
            raise EnrollmentError("Controller enrollment material is missing from join response")
        enrollment["controller_provision"] = {"payload": payload}
    write_local_enrollment(args.state_dir, enrollment)
    apply_remote_node_config(
        args.state_dir,
        node_id=enrollment["node_id"],
        name=enrollment["name"],
        public_key=public_key,
        roles=roles,
        created_at=enrollment["created_at"],
        last_seen=int(time.time()),
        endpoints=config.get("endpoints"),
        initial_routes=config.get("advertised_routes"),
    )
    role_config = config.get("role_config", {})
    if not isinstance(role_config, dict):
        role_config = {}

    resume_controller_provisioning(args.state_dir, enrollment)

    results = reconcile_roles(args.state_dir, roles, role_config)
    require_role_health(roles, results)
    install_runtime_service(args.state_dir)
    send_heartbeat(args.state_dir, enrollment)

    print(f"Node joined: {enrollment['name']} ({enrollment['node_id']})")
    enabled = ", ".join(sorted(role for role, value in roles.items() if value)) or "none"
    print(f"Roles: {enabled}")
    for role, state in sorted(results.items()):
        print(f"  {role}: {state}")
    return 0


def cmd_local_reconcile(args: argparse.Namespace) -> int:
    enrollment = enrolled_state(args.state_dir)
    if enrollment is None:
        raise EnrollmentError("node is not joined")
    roles = enrollment.get("roles", {})
    if not isinstance(roles, dict) or not bool(roles.get("gateway")):
        return 0
    if enrollment_uses_routed_dataplane(enrollment) and not primary_compat_runtime(args.state_dir):
        return 0
    control_config = args.state_dir / "control" / "config.json"
    if not control_config.is_file():
        return 0
    try:
        reconcile_local_gateway_state(args.state_dir)
    except (
        GatewayDataplaneError,
        AccessError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise EnrollmentError(
            f"Gateway dataplane reconciliation failed: {exc}"
        ) from exc
    return 0


def _display_routed_hops(
    hops: object,
    names: dict[str, str],
) -> str:
    if not isinstance(hops, list):
        return ""
    return " → ".join(names.get(str(item), str(item)) for item in hops)


def cmd_status(args: argparse.Namespace) -> int:
    enrollment = enrolled_state(args.state_dir)
    if enrollment is None:
        print("BPC: Not connected")
        return 1

    roles = enrollment.get("roles", {})
    if not isinstance(roles, dict):
        roles = {}
    config = enrollment.get("config", {})
    if not isinstance(config, dict):
        config = {}
    routing = config.get("routing", {})
    if not isinstance(routing, dict):
        routing = {}
    raw_names = routing.get("node_names", {})
    names = (
        {str(key): str(value) for key, value in raw_names.items()}
        if isinstance(raw_names, dict)
        else {}
    )

    status_path = Path(
        os.environ.get(
            "BPC_ROUTED_STATUS",
            "/run/bpc-connect/routed-status.json",
        )
    )
    routed_status: dict[str, Any] = {}
    if status_path.is_file():
        try:
            routed_status = read_json(status_path)
        except (OSError, ValueError, json.JSONDecodeError):
            routed_status = {}

    selected_paths = routed_status.get("selected_paths", [])
    if not isinstance(selected_paths, list):
        selected_paths = []
    selected = next(
        (item for item in selected_paths if isinstance(item, dict)),
        None,
    )

    routed_required = bool(roles.get("gateway")) or bool(roles.get("site_router"))
    routed_service = service_state("bpc-routed-node.service")
    if enrollment_uses_routed_dataplane(enrollment) and not routing.get("links"):
        print("BPC: Not connected (routed mesh awaits topology links)")
        print(f"Node: {enrollment.get('name')}")
        return 1
    if routed_required and routing.get("links"):
        try:
            policy_expires_at = int(routing.get("policy_expires_at", 0) or 0)
        except (TypeError, ValueError):
            policy_expires_at = 0
        if policy_expires_at <= int(time.time()):
            print("BPC: Not connected (routed policy expired or missing)")
            print("Restore Controller connectivity to refresh routing policy.")
            return 1
    if routed_required and routing.get("links") and routed_service != "active":
        print("BPC: Degraded")
    else:
        print("BPC: Connected")

    if selected is not None:
        hops = selected.get("hops", [])
        print("")
        print("Active path:")
        print(f"  {_display_routed_hops(hops, names)}")
        try:
            latency = float(selected.get("rtt_ms", 0) or 0)
        except (TypeError, ValueError):
            latency = 0.0
        print("")
        print("Latency:")
        print(f"  {latency:.1f} ms")

        standby_ids = selected.get("standby_path_ids", [])
        all_paths = routing.get("paths", [])
        if isinstance(standby_ids, list) and isinstance(all_paths, list):
            path_by_id = {
                str(item.get("id", "")): item
                for item in all_paths
                if isinstance(item, dict)
            }
            standby = [
                path_by_id.get(str(path_id))
                for path_id in standby_ids
                if str(path_id) in path_by_id
            ]
            if standby:
                print("")
                print("Standby:")
                for path in standby:
                    if path is None:
                        continue
                    print(
                        "  "
                        + _display_routed_hops(path.get("hops", []), names)
                    )
    else:
        print(f"Node: {enrollment.get('name')}")
        if routed_required:
            print(f"Routed mesh: {routed_service}")
    return 0

def cmd_leave(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise EnrollmentError("run bpc leave as root")
    enrollment = enrolled_state(args.state_dir)
    if enrollment is None:
        print("Node is not joined.")
        return 0
    try:
        request_json(
            str(enrollment["controller_url"]),
            "/v1/nodes/leave",
            {"node_id": str(enrollment["node_id"])},
            credential=str(enrollment["credential"]),
            controller_urls=[
                str(item)
                for item in enrollment.get("controllers", [])
                if isinstance(item, str)
            ],
        )
    except EnrollmentError as exc:
        if not args.force:
            raise
        print(f"WARNING: controller leave failed: {exc}", file=sys.stderr)

    subprocess.run(
        ["systemctl", "disable", "--now", "bpc-routed-node.service"],
        check=False,
        capture_output=True,
    )
    subprocess.run(
        ["systemctl", "disable", "--now", "bpc-node.service"],
        check=False,
        capture_output=True,
    )
    path = args.state_dir / "enrollment.json"
    archive = args.state_dir / "enrollment.left.json"
    if path.is_file():
        os.replace(path, archive)
        os.chmod(archive, 0o600)

    node_path = args.state_dir / "node.yaml"
    if node_path.is_file():
        current = load_node_config(node_path)
        cleared = NodeConfig(
            version=current.version,
            node=Node(
                id=current.node.id,
                name=current.node.name,
                public_key=current.node.public_key,
                created_at=current.node.created_at,
                last_seen=current.node.last_seen,
                roles=Capabilities.from_mapping({}),
                endpoints=current.node.endpoints,
            ),
            advertised_routes=current.advertised_routes,
        )
        save_node_config(node_path, cleared)
    print(f"Node left cluster: {enrollment.get('name')} ({enrollment.get('node_id')})")
    return 0


def cmd_daemon(args: argparse.Namespace) -> int:
    enrollment = enrolled_state(args.state_dir)
    if enrollment is None:
        raise EnrollmentError("node is not joined")
    config = enrollment.get("config", {})
    roles = enrollment.get("roles", {})
    role_config: dict[str, Any] = {}
    if isinstance(config, dict) and isinstance(config.get("role_config"), dict):
        role_config = dict(config["role_config"])
    if isinstance(roles, dict):
        try:
            reconcile_roles(args.state_dir, roles, role_config)
        except EnrollmentError as exc:
            print(f"role reconciliation warning: {exc}", file=sys.stderr)
        try:
            reconcile_startup_gateway_state(args.state_dir, roles)
        except EnrollmentError as exc:
            # The immediate heartbeat below retries reconciliation after remote
            # state refresh. Startup must remain available during service races.
            print(f"startup gateway reconciliation warning: {exc}", file=sys.stderr)

    while True:
        enrollment = enrolled_state(args.state_dir)
        if enrollment is None:
            return 0
        try:
            response = send_heartbeat(args.state_dir, enrollment)
            remote_config = response.get("config", {})
            remote_roles = response.get("roles", {})
            if isinstance(remote_config, dict) and isinstance(remote_roles, dict):
                remote_role_config = remote_config.get("role_config", {})
                if isinstance(remote_role_config, dict):
                    reconcile_roles(args.state_dir, remote_roles, remote_role_config)
            interval = int(
                remote_config.get("heartbeat_interval", HEARTBEAT_INTERVAL)
                if isinstance(remote_config, dict)
                else HEARTBEAT_INTERVAL
            )
        except (EnrollmentError, OSError, ValueError) as exc:
            print(f"heartbeat warning: {exc}", file=sys.stderr)
            roles = enrollment.get("roles", {})
            if isinstance(roles, dict) and bool(roles.get("gateway")):
                try:
                    snapshot = load_valid_security_snapshot(args.state_dir)
                    print(
                        "Gateway offline grace active: "
                        f"revision={snapshot.get('revision')} "
                        f"expires_at={snapshot.get('expires_at')}",
                        file=sys.stderr,
                    )
                except (GatewaySnapshotError, OSError, ValueError, json.JSONDecodeError):
                    subprocess.run(
                        ["systemctl", "stop", (
                            "bpc-routed-node.service"
                            if enrollment_uses_routed_dataplane(enrollment)
                            else "xray.service"
                        )],
                        check=False,
                        capture_output=True,
                    )
                    print(
                        "Gateway security snapshot expired/unavailable; "
                        "BPC gateway transport stopped fail-closed.",
                        file=sys.stderr,
                    )
            interval = HEARTBEAT_INTERVAL
        time.sleep(max(5, min(interval, 300)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BPC Node enrollment")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--control-dir", type=Path, default=DEFAULT_CONTROL_DIR)
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("node-create")
    create.add_argument("--name", required=True)
    create.add_argument("--preset", choices=sorted(NODE_PRESETS), required=True)
    create.add_argument("--host", action="append", default=[])
    create.add_argument("--route", action="append", default=[])
    create.add_argument("--expires", default="15m")
    create.add_argument("--controller-url")
    create.add_argument("--dataplane", choices=("compat", "routed"), default="compat")

    mesh = sub.add_parser("mesh-enable")
    mesh.add_argument("--host", action="append", required=True)
    mesh.add_argument("--preserve-compat", action="store_true", required=True)

    configure = sub.add_parser("node-configure")
    configure.add_argument("node_id")
    configure.add_argument("--preset", choices=("public-node",), required=True)
    configure.add_argument("--host", action="append", required=True)
    configure.add_argument("--dataplane", choices=("routed",), required=True)

    route_policy = sub.add_parser("route-authorize")
    route_policy.add_argument("node_id")
    route_policy.add_argument("--route", action="append", required=True)

    token = sub.add_parser("token-create")
    token.add_argument("--roles", action="append", required=True)
    token.add_argument("--name")
    token.add_argument("--expires", default="15m")
    token.add_argument("--controller-url")
    token.add_argument("--gateway-reality-server-name")
    token.add_argument("--gateway-port", type=int)
    token.add_argument("--dataplane", choices=("compat", "routed"), default="compat")

    sub.add_parser("list")

    join = sub.add_parser("join")
    join.add_argument("token")
    join.add_argument("--controller-advertise-host")

    sub.add_parser("status")
    sub.add_parser("runtime-install")
    sub.add_parser("controller-runtime-install")
    sub.add_parser("local-reconcile")

    leave = sub.add_parser("leave")
    leave.add_argument("--force", action="store_true")

    sub.add_parser("daemon")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "route-authorize":
            authorize_site_routes(args.control_dir, args.node_id, args.route)
            print("Site route policy updated.")
            return 0
        if args.command == "node-create":
            return cmd_node_create(args)
        if args.command == "mesh-enable":
            return cmd_mesh_enable(args)
        if args.command == "node-configure":
            return cmd_node_configure(args)
        if args.command == "token-create":
            return cmd_token_create(args)
        if args.command == "list":
            return cmd_list(args)
        if args.command == "join":
            return cmd_join(args)
        if args.command == "status":
            return cmd_status(args)
        if args.command == "runtime-install":
            if os.geteuid() != 0:
                raise EnrollmentError("run BPC runtime installation as root")
            if enrolled_state(args.state_dir) is None:
                raise EnrollmentError("node is not joined")
            install_runtime_service(args.state_dir)
            print("BPC Node runtime service installed.")
            return 0
        if args.command == "controller-runtime-install":
            if os.geteuid() != 0:
                raise EnrollmentError("run Controller runtime installation as root")
            reconcile_controller_runtime(args.state_dir)
            print("Existing Controller runtime reconciled; identity and PKI preserved.")
            return 0
        if args.command == "local-reconcile":
            return cmd_local_reconcile(args)
        if args.command == "leave":
            return cmd_leave(args)
        if args.command == "daemon":
            return cmd_daemon(args)
    except (EnrollmentError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
