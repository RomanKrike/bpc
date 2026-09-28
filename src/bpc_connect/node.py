from __future__ import annotations

import ipaddress
import os
import re
import socket
import time
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .errors import BPCConfigError
from .state import StateLayout

NODE_CONFIG_VERSION = 1
CORE_CAPABILITIES = ("controller", "gateway", "relay", "site_router")
NODE_PRESETS = {
    "public-node": ("controller", "gateway", "relay"),
    "site-router": ("site_router",),
}
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True)
class Endpoint:
    host: str
    public: bool = True
    enabled: bool = True

    def to_mapping(self) -> dict[str, Any]:
        return {"host": self.host, "public": self.public, "enabled": self.enabled}


def canonical_endpoints(raw: Any = None) -> tuple[Endpoint, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        raise BPCConfigError("endpoints must be a list")
    result: list[Endpoint] = []
    hosts: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            raise BPCConfigError("endpoint must be a mapping")
        host = item.get("host")
        if not isinstance(host, str):
            raise BPCConfigError("endpoint host must be a hostname")
        host = host.lower()
        if len(host) > 253 or not all(_HOST_LABEL_RE.fullmatch(x) for x in host.split(".")):
            raise BPCConfigError(f"Invalid endpoint hostname: {host!r}")
        public = item.get("public", True)
        enabled = item.get("enabled", True)
        if not isinstance(public, bool) or not isinstance(enabled, bool):
            raise BPCConfigError("endpoint public and enabled must be boolean")
        if host in hosts:
            raise BPCConfigError(f"Duplicate endpoint hostname: {host!r}")
        hosts.add(host)
        result.append(Endpoint(host, public, enabled))
    return tuple(result)


@dataclass(frozen=True)
class Capabilities:
    values: dict[str, bool]

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> Capabilities:
        values: dict[str, bool] = {name: False for name in CORE_CAPABILITIES}
        if raw is None:
            return cls(values)
        if not isinstance(raw, Mapping):
            raise BPCConfigError("roles must be a mapping")
        for raw_name, raw_enabled in raw.items():
            name = str(raw_name)
            if not _CAPABILITY_RE.fullmatch(name):
                raise BPCConfigError(f"Invalid capability name: {name!r}")
            if not isinstance(raw_enabled, bool):
                raise BPCConfigError(f"Capability {name!r} must be boolean")
            values[name] = raw_enabled
        return cls(values)

    def has(self, name: str) -> bool:
        return bool(self.values.get(name, False))

    def enabled(self) -> tuple[str, ...]:
        return tuple(sorted(name for name, enabled in self.values.items() if enabled))

    def with_updates(self, **updates: bool) -> Capabilities:
        values = dict(self.values)
        for name, enabled in updates.items():
            if not _CAPABILITY_RE.fullmatch(name):
                raise BPCConfigError(f"Invalid capability name: {name!r}")
            if not isinstance(enabled, bool):
                raise BPCConfigError(f"Capability {name!r} must be boolean")
            values[name] = enabled
        return Capabilities(values)


@dataclass(frozen=True)
class Node:
    id: str
    name: str
    public_key: str
    created_at: int
    last_seen: int
    roles: Capabilities
    endpoints: tuple[Endpoint, ...] = ()

    def has_capability(self, name: str) -> bool:
        return self.roles.has(name)


@dataclass(frozen=True)
class NodeConfig:
    version: int
    node: Node
    advertised_routes: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "node": {
                "id": self.node.id,
                "name": self.node.name,
                "public_key": self.node.public_key,
                "created_at": self.node.created_at,
                "last_seen": self.node.last_seen,
            },
            "roles": dict(sorted(self.node.roles.values.items())),
            "endpoints": [item.to_mapping() for item in self.node.endpoints],
            "advertised_routes": list(self.advertised_routes),
        }


def _require_mapping(raw: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise BPCConfigError(f"{context} must be a mapping")
    return raw


def _require_nonempty_text(mapping: Mapping[str, Any], key: str, context: str) -> str:
    value = str(mapping.get(key, "")).strip()
    if not value:
        raise BPCConfigError(f"Missing required key '{key}' in {context}")
    return value


def _require_timestamp(mapping: Mapping[str, Any], key: str, context: str) -> int:
    try:
        value = int(mapping.get(key, 0))
    except (TypeError, ValueError) as exc:
        raise BPCConfigError(f"{context}.{key} must be an integer timestamp") from exc
    if value < 0:
        raise BPCConfigError(f"{context}.{key} must be >= 0")
    return value


def canonical_advertised_routes(raw: Iterable[object] | None) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, (str, bytes, Mapping)):
        raise BPCConfigError("advertised_routes must be a list")
    result: list[str] = []
    seen: set[str] = set()
    for item in raw:
        try:
            network = ipaddress.ip_network(str(item).strip(), strict=False)
        except ValueError as exc:
            raise BPCConfigError(f"Invalid advertised route {item!r}: {exc}") from exc
        if network.version != 4:
            raise BPCConfigError("advertised_routes currently support IPv4 only")
        if network.prefixlen == 0:
            raise BPCConfigError("advertised_routes cannot contain a default route")
        value = str(network)
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(sorted(result))


def parse_node_config(raw: Any) -> NodeConfig:
    root = _require_mapping(raw, "root")
    try:
        version = int(root.get("version", 0))
    except (TypeError, ValueError) as exc:
        raise BPCConfigError("version must be an integer") from exc
    if version != NODE_CONFIG_VERSION:
        raise BPCConfigError(
            f"Unsupported node config version {version}; expected {NODE_CONFIG_VERSION}"
        )

    node_raw = _require_mapping(root.get("node"), "node")
    node_id = _require_nonempty_text(node_raw, "id", "node")
    name = _require_nonempty_text(node_raw, "name", "node")
    public_key = str(node_raw.get("public_key", "")).strip()
    created_at = _require_timestamp(node_raw, "created_at", "node")
    last_seen = _require_timestamp(node_raw, "last_seen", "node")
    roles = Capabilities.from_mapping(root.get("roles"))
    advertised_routes = canonical_advertised_routes(root.get("advertised_routes", []))

    return NodeConfig(
        version=version,
        node=Node(
            id=node_id,
            name=name,
            public_key=public_key,
            created_at=created_at,
            last_seen=last_seen,
            roles=roles,
            endpoints=canonical_endpoints(root.get("endpoints")),
        ),
        advertised_routes=advertised_routes,
    )


def load_node_config(path: str | Path) -> NodeConfig:
    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError:
        raise
    except yaml.YAMLError as exc:
        raise BPCConfigError(f"Invalid node YAML: {exc}") from exc
    return parse_node_config(raw)


def save_node_config(path: str | Path, config: NodeConfig) -> None:
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = yaml.safe_dump(
        config.to_mapping(),
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )
    tmp = config_path.with_name(f".{config_path.name}.{uuid.uuid4().hex[:8]}.tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, config_path)


def default_node_name() -> str:
    override = os.environ.get("BPC_NODE_NAME", "").strip()
    if override:
        return override
    hostname = socket.gethostname().strip()
    return hostname or "bpc-node"


def new_node_config(
    *,
    name: str | None = None,
    roles: Mapping[str, Any] | None = None,
    advertised_routes: Iterable[object] | None = None,
    endpoints: list[dict[str, Any]] | None = None,
    now: int | None = None,
) -> NodeConfig:
    timestamp = int(time.time()) if now is None else int(now)
    node_name = (name or default_node_name()).strip()
    if not node_name:
        raise BPCConfigError("node.name must not be empty")
    return NodeConfig(
        version=NODE_CONFIG_VERSION,
        node=Node(
            id=uuid.uuid4().hex,
            name=node_name,
            public_key="",
            created_at=timestamp,
            last_seen=0,
            roles=Capabilities.from_mapping(roles),
            endpoints=canonical_endpoints(endpoints),
        ),
        advertised_routes=canonical_advertised_routes(advertised_routes),
    )


def reconcile_node_config(
    state_dir: str | Path,
    *,
    name: str | None = None,
    capability_updates: Mapping[str, bool] | None = None,
    advertised_routes: Iterable[object] | None = None,
    touch_last_seen: bool = False,
    now: int | None = None,
) -> tuple[NodeConfig, bool]:
    state = StateLayout.from_root(state_dir)
    timestamp = int(time.time()) if now is None else int(now)

    if state.node_config.is_file():
        current = load_node_config(state.node_config)
        roles = current.node.roles
        if capability_updates:
            roles = roles.with_updates(**dict(capability_updates))
        routes = (
            current.advertised_routes
            if advertised_routes is None
            else canonical_advertised_routes(advertised_routes)
        )
        updated = NodeConfig(
            version=current.version,
            node=Node(
                id=current.node.id,
                name=(name.strip() if name and name.strip() else current.node.name),
                public_key=current.node.public_key,
                created_at=current.node.created_at,
                last_seen=timestamp if touch_last_seen else current.node.last_seen,
                roles=roles,
                endpoints=current.node.endpoints,
            ),
            advertised_routes=routes,
        )
        changed = updated != current
        if changed:
            save_node_config(state.node_config, updated)
        return updated, changed

    created = new_node_config(
        name=name,
        roles=capability_updates,
        advertised_routes=advertised_routes,
        now=timestamp,
    )
    if touch_last_seen:
        created = NodeConfig(
            version=created.version,
            node=Node(
                id=created.node.id,
                name=created.node.name,
                public_key=created.node.public_key,
                created_at=created.node.created_at,
                last_seen=timestamp,
                roles=created.node.roles,
                endpoints=created.node.endpoints,
            ),
            advertised_routes=created.advertised_routes,
        )
    save_node_config(state.node_config, created)
    return created, True


def set_capabilities(path: str | Path, updates: Mapping[str, bool]) -> NodeConfig:
    current = load_node_config(path)
    updated = NodeConfig(
        version=current.version,
        node=Node(
            id=current.node.id,
            name=current.node.name,
            public_key=current.node.public_key,
            created_at=current.node.created_at,
            last_seen=current.node.last_seen,
            roles=current.node.roles.with_updates(**dict(updates)),
            endpoints=current.node.endpoints,
        ),
        advertised_routes=current.advertised_routes,
    )
    save_node_config(path, updated)
    return updated


def set_advertised_routes(path: str | Path, routes: Iterable[object]) -> NodeConfig:
    current = load_node_config(path)
    updated = NodeConfig(
        version=current.version,
        node=current.node,
        advertised_routes=canonical_advertised_routes(routes),
    )
    save_node_config(path, updated)
    return updated


def set_node_identity(path: str | Path, public_key: str) -> NodeConfig:
    current = load_node_config(path)
    updated = NodeConfig(
        version=current.version,
        node=Node(
            id=current.node.id,
            name=current.node.name,
            public_key=public_key.strip(),
            created_at=current.node.created_at,
            last_seen=current.node.last_seen,
            roles=current.node.roles,
            endpoints=current.node.endpoints,
        ),
        advertised_routes=current.advertised_routes,
    )
    save_node_config(path, updated)
    return updated
