#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bpc_connect.node import (  # noqa: E402
    Capabilities,
    Node,
    NodeConfig,
    load_node_config,
    save_node_config,
)

DEFAULT_STATE_DIR = Path("/etc/bpc-connect")
DEFAULT_CONTROL_DIR = DEFAULT_STATE_DIR / "ru-node" / "control"
TOKEN_PREFIX = "BPC-"
HEARTBEAT_INTERVAL = 30
MAX_CLOCK_SKEW = 300
ROLE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class EnrollmentError(RuntimeError):
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
    return url


def make_join_token(controller_url: str, secret: str) -> str:
    encoded = b64url_encode(normalize_controller_url(controller_url).encode("utf-8"))
    return f"{TOKEN_PREFIX}{encoded}.{secret}"


def parse_join_token(token: str) -> tuple[str, str]:
    value = token.strip()
    if not value.startswith(TOKEN_PREFIX) or "." not in value:
        raise EnrollmentError("invalid join token", 401)
    encoded, secret = value[len(TOKEN_PREFIX) :].rsplit(".", 1)
    if len(secret) != 64:
        raise EnrollmentError("invalid join token", 401)
    try:
        int(secret, 16)
        controller_url = b64url_decode(encoded).decode("utf-8")
    except (ValueError, UnicodeDecodeError, base64.binascii.Error) as exc:
        raise EnrollmentError("invalid join token", 401) from exc
    return normalize_controller_url(controller_url), secret


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


def default_role_config(state_dir: Path, roles: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if "gateway" in roles:
        reality_name = read_env_value(
            state_dir / "ru-node" / "client.env", "BPC_REALITY_SERVER_NAME"
        )
        result["gateway"] = {
            "reality_server_name": reality_name or "www.bing.com",
            "xray_port": 443,
        }
    if "relay" in roles:
        result["relay"] = {"mode": "agent"}
    return result


def create_join_token(
    control_dir: Path,
    *,
    controller_url: str,
    roles: list[str],
    name: str | None = None,
    expires_in: int = 900,
    role_config: dict[str, Any] | None = None,
    now: int | None = None,
) -> str:
    timestamp = int(time.time()) if now is None else int(now)
    if expires_in <= 0 or expires_in > 7 * 86400:
        raise EnrollmentError("invalid join token expiration")
    normalized_roles = normalize_roles(roles)
    normalized_name = normalize_node_name(name) if name else None
    secret = secrets.token_hex(32)
    token = make_join_token(controller_url, secret)
    index = token_index(secret)
    metadata = {
        "version": 1,
        "created_at": timestamp,
        "expires_at": timestamp + expires_in,
        "roles": normalized_roles,
        "name": normalized_name,
        "controller_url": normalize_controller_url(controller_url),
        "role_config": role_config or {},
    }
    atomic_json(control_dir / "node-join" / f"{index}.json", metadata)
    return token


def _join_record(control_dir: Path, token: str) -> tuple[Path, dict[str, Any], str]:
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


def enroll_node(
    control_dir: Path,
    *,
    token: str,
    public_key: str,
    presented_name: str,
    now: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    token_path, record, index = _join_record(control_dir, token)
    expires_at = int(record.get("expires_at", 0))
    if expires_at <= timestamp:
        token_path.unlink(missing_ok=True)
        atomic_json(
            control_dir / "node-join-used" / f"{index}.json",
            {"reason": "expired", "used_at": timestamp},
        )
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
    node_id = uuid.uuid4().hex
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
        "created_at": timestamp,
        "last_seen": timestamp,
        "revoked": False,
        "last_status": "joined",
        "last_version": "",
        "services": {},
    }

    node_path = control_dir / "nodes" / f"{node_id}.json"
    credential_path = control_dir / "node-credentials" / f"{credential_index}.json"
    try:
        atomic_json(node_path, node)
        atomic_json(public_index, {"node_id": node_id})
        atomic_json(credential_path, {"node_id": node_id})
        atomic_json(
            control_dir / "node-join-used" / f"{index}.json",
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
        },
    }


def authorize_node(control_dir: Path, credential: str) -> tuple[Path, dict[str, Any]]:
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


def node_heartbeat(
    control_dir: Path,
    *,
    credential: str,
    payload: dict[str, Any],
    now: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    node_path, node = authorize_node(control_dir, credential)
    node["last_seen"] = timestamp
    node["last_status"] = str(payload.get("status", "online"))[:64]
    node["last_version"] = str(payload.get("version", ""))[:32]
    services = payload.get("services", {})
    if isinstance(services, dict):
        node["services"] = {
            str(key)[:64]: str(value)[:64] for key, value in services.items()
        }
    atomic_json(node_path, node)
    return {
        "ok": True,
        "server_time": timestamp,
        "node_id": str(node["node_id"]),
        "name": str(node["name"]),
        "roles": dict(node.get("roles", {})),
        "config": {
            "version": 1,
            "heartbeat_interval": HEARTBEAT_INTERVAL,
            "role_config": dict(node.get("role_config", {})),
        },
    }


def leave_node(control_dir: Path, *, credential: str, now: int | None = None) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    node_path, node = authorize_node(control_dir, credential)
    node["revoked"] = True
    node["last_seen"] = timestamp
    node["last_status"] = "left"
    atomic_json(node_path, node)

    credential_path = control_dir / "node-credentials" / f"{token_index(credential)}.json"
    credential_path.unlink(missing_ok=True)
    fingerprint = str(node.get("public_key_fingerprint", ""))
    if fingerprint:
        (control_dir / "node-public-keys" / f"{fingerprint}.json").unlink(missing_ok=True)
    return {"ok": True, "node_id": str(node["node_id"])}


def list_nodes(control_dir: Path, now: int | None = None) -> list[dict[str, Any]]:
    timestamp = int(time.time()) if now is None else int(now)
    result: list[dict[str, Any]] = []
    for path in sorted((control_dir / "nodes").glob("*.json")):
        try:
            node = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        last_seen = int(node.get("last_seen", 0))
        node["online"] = (
            not bool(node.get("revoked", False))
            and last_seen > 0
            and timestamp - last_seen <= HEARTBEAT_INTERVAL * 3
        )
        result.append(node)
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


def request_json(
    controller_url: str,
    path: str,
    payload: dict[str, Any],
    *,
    credential: str | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if credential:
        headers["Authorization"] = f"Bearer {credential}"
    request = urllib.request.Request(
        normalize_controller_url(controller_url) + path,
        data=data,
        headers=headers,
        method="POST",
    )
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:512]
        try:
            parsed = json.loads(detail)
            message = str(parsed.get("error", detail))
        except json.JSONDecodeError:
            message = detail or f"controller returned HTTP {exc.code}"
        raise EnrollmentError(message, exc.code) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise EnrollmentError(f"controller connection failed: {exc}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EnrollmentError("controller returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise EnrollmentError("controller returned invalid response")
    return value


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
) -> None:
    role_values = Capabilities.from_mapping(
        {str(key): bool(value) for key, value in roles.items()}
    )
    path = state_dir / "node.yaml"
    if path.is_file():
        try:
            current = load_node_config(path)
            created_at = current.node.created_at or created_at
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
        ),
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


def local_services(roles: dict[str, Any]) -> dict[str, str]:
    services: dict[str, str] = {"bpc-node": service_state("bpc-node.service")}
    if bool(roles.get("gateway")):
        services["gateway"] = service_state("xray.service")
    if bool(roles.get("relay")):
        services["relay"] = service_state("bpc-agent-relay.service")
    if bool(roles.get("controller")):
        services["controller"] = service_state("bpc-control.service")
    return services


def _run_checked(args: list[str], *, env: dict[str, str] | None = None) -> None:
    completed = subprocess.run(args, check=False, env=env)
    if completed.returncode != 0:
        raise EnrollmentError(f"command failed ({completed.returncode}): {' '.join(args)}")


def reconcile_roles(
    state_dir: Path,
    roles: dict[str, Any],
    role_config: dict[str, Any],
) -> dict[str, str]:
    results: dict[str, str] = {}
    deploy = ROOT / "deploy"
    ru_dir = state_dir / "ru-node"

    if bool(roles.get("gateway")):
        gateway = role_config.get("gateway", {})
        if not isinstance(gateway, dict):
            gateway = {}
        if not (ru_dir / "config.json").is_file():
            env = dict(os.environ)
            env["BPC_DIR"] = str(ru_dir)
            env["REALITY_SERVER_NAME"] = str(
                gateway.get("reality_server_name", "www.bing.com")
            )
            env["XRAY_PORT"] = str(int(gateway.get("xray_port", 443)))
            _run_checked([str(deploy / "bootstrap-ru-node.sh")], env=env)
        else:
            subprocess.run(
                ["systemctl", "start", "xray.service"],
                check=False,
                capture_output=True,
            )
        results["gateway"] = service_state("xray.service")

    if bool(roles.get("relay")):
        relay = role_config.get("relay", {})
        if not isinstance(relay, dict):
            relay = {}
        mode = str(relay.get("mode", "agent"))
        if mode != "agent":
            results["relay"] = f"unsupported-mode:{mode}"
        elif (ru_dir / "agent" / "enabled").is_file():
            subprocess.run(
                ["systemctl", "start", "bpc-agent-relay.service"],
                check=False,
                capture_output=True,
            )
            results["relay"] = service_state("bpc-agent-relay.service")
        elif (ru_dir / "client.env").is_file():
            _run_checked([str(deploy / "bpc-enable-agent-dataplane.sh")])
            results["relay"] = service_state("bpc-agent-relay.service")
        else:
            results["relay"] = "pending:gateway-or-public-host"

    if bool(roles.get("controller")):
        if (ru_dir / "control" / "enabled").is_file():
            subprocess.run(
                ["systemctl", "start", "bpc-control.service"],
                check=False,
                capture_output=True,
            )
            results["controller"] = service_state("bpc-control.service")
        else:
            results["controller"] = "pending:tls-subscription-bootstrap"

    if bool(roles.get("site_router")):
        results["site_router"] = "pending:not-implemented-stage2"

    return results


def install_runtime_service(state_dir: Path) -> None:
    unit = Path("/etc/systemd/system/bpc-node.service")
    content = f"""[Unit]
Description=BPC Node control-plane runtime
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {ROOT / 'deploy' / 'bpc_node_enrollment.py'} --state-dir {state_dir} daemon
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
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
"""
    unit.write_text(content, encoding="utf-8")
    os.chmod(unit, 0o644)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "bpc-node.service"], check=True)
    subprocess.run(["systemctl", "restart", "bpc-node.service"], check=True)


def enrolled_state(state_dir: Path) -> dict[str, Any] | None:
    path = state_dir / "enrollment.json"
    if not path.is_file():
        return None
    return read_json(path)


def send_heartbeat(state_dir: Path, enrollment: dict[str, Any]) -> dict[str, Any]:
    roles = enrollment.get("roles", {})
    if not isinstance(roles, dict):
        roles = {}
    response = request_json(
        str(enrollment["controller_url"]),
        "/v1/nodes/heartbeat",
        {
            "status": "online",
            "version": (
                (ROOT / "VERSION").read_text(encoding="utf-8").strip()
                if (ROOT / "VERSION").is_file()
                else "source"
            ),
            "services": local_services(roles),
        },
        credential=str(enrollment["credential"]),
    )
    response_roles = response.get("roles", {})
    config = response.get("config", {})
    if isinstance(response_roles, dict):
        enrollment["roles"] = response_roles
    if isinstance(config, dict):
        enrollment["config"] = config
    enrollment["last_heartbeat"] = int(response.get("server_time", time.time()))
    write_local_enrollment(state_dir, enrollment)
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
    )
    return response


def cmd_token_create(args: argparse.Namespace) -> int:
    roles = normalize_roles(args.roles)
    controller_url = (
        normalize_controller_url(args.controller_url)
        if args.controller_url
        else discover_controller_url(args.control_dir)
    )
    role_config = default_role_config(args.state_dir, roles)
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


def cmd_join(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise EnrollmentError("run bpc join as root")
    existing = enrolled_state(args.state_dir)
    if existing is not None:
        print(
            f"Node is already joined: {existing.get('name')} "
            f"({existing.get('node_id')}). Run 'bpc leave' before joining another cluster."
        )
        return 0

    controller_url, _ = parse_join_token(args.token)
    public_key = generate_node_identity(args.state_dir)
    response = request_json(
        controller_url,
        "/v1/nodes/join",
        {
            "token": args.token,
            "public_key": public_key,
            "name": socket.gethostname()[:64] or "bpc-node",
        },
    )
    roles = response.get("roles", {})
    config = response.get("config", {})
    if not isinstance(roles, dict) or not isinstance(config, dict):
        raise EnrollmentError("controller returned invalid enrollment configuration")
    enrollment = {
        "version": 1,
        "controller_url": controller_url,
        "node_id": str(response["node_id"]),
        "name": str(response["name"]),
        "credential": str(response["credential"]),
        "created_at": int(response.get("created_at", time.time())),
        "joined_at": int(time.time()),
        "last_heartbeat": 0,
        "roles": roles,
        "config": config,
    }
    write_local_enrollment(args.state_dir, enrollment)
    apply_remote_node_config(
        args.state_dir,
        node_id=enrollment["node_id"],
        name=enrollment["name"],
        public_key=public_key,
        roles=roles,
        created_at=enrollment["created_at"],
        last_seen=int(time.time()),
    )
    role_config = config.get("role_config", {})
    if not isinstance(role_config, dict):
        role_config = {}
    results = reconcile_roles(args.state_dir, roles, role_config)
    install_runtime_service(args.state_dir)
    try:
        send_heartbeat(args.state_dir, enrollment)
    except EnrollmentError as exc:
        print(f"WARNING: initial heartbeat failed: {exc}", file=sys.stderr)

    print(f"Node joined: {enrollment['name']} ({enrollment['node_id']})")
    enabled = ", ".join(sorted(role for role, value in roles.items() if value)) or "none"
    print(f"Roles: {enabled}")
    for role, state in sorted(results.items()):
        print(f"  {role}: {state}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    enrollment = enrolled_state(args.state_dir)
    if enrollment is None:
        print("Enrollment: not joined")
        return 1
    roles = enrollment.get("roles", {})
    if not isinstance(roles, dict):
        roles = {}
    print("Enrollment: joined")
    print(f"Node: {enrollment.get('name')} ({enrollment.get('node_id')})")
    print(f"Controller: {enrollment.get('controller_url')}")
    print(
        "Roles: "
        + (", ".join(sorted(role for role, value in roles.items() if value)) or "none")
    )
    print(f"Last heartbeat: {enrollment.get('last_heartbeat', 0)}")
    for service, state in sorted(local_services(roles).items()):
        print(f"  {service}: {state}")
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
        )
    except EnrollmentError as exc:
        if not args.force:
            raise
        print(f"WARNING: controller leave failed: {exc}", file=sys.stderr)

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
            ),
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
            interval = HEARTBEAT_INTERVAL
        time.sleep(max(10, min(interval, 300)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BPC Node enrollment")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--control-dir", type=Path, default=DEFAULT_CONTROL_DIR)
    sub = parser.add_subparsers(dest="command", required=True)

    token = sub.add_parser("token-create")
    token.add_argument("--roles", action="append", required=True)
    token.add_argument("--name")
    token.add_argument("--expires", default="15m")
    token.add_argument("--controller-url")
    token.add_argument("--gateway-reality-server-name")
    token.add_argument("--gateway-port", type=int)

    sub.add_parser("list")

    join = sub.add_parser("join")
    join.add_argument("token")

    sub.add_parser("status")

    leave = sub.add_parser("leave")
    leave.add_argument("--force", action="store_true")

    sub.add_parser("daemon")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "token-create":
            return cmd_token_create(args)
        if args.command == "list":
            return cmd_list(args)
        if args.command == "join":
            return cmd_join(args)
        if args.command == "status":
            return cmd_status(args)
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
