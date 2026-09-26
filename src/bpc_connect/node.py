from __future__ import annotations

import os
import re
import socket
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from .errors import BPCConfigError

NODE_CONFIG_VERSION = 1
CORE_CAPABILITIES = ("controller", "gateway", "relay", "site_router")
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


@dataclass(frozen=True)
class Capabilities:
    values: dict[str, bool]

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> "Capabilities":
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

    def with_updates(self, **updates: bool) -> "Capabilities":
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

    def has_capability(self, name: str) -> bool:
        return self.roles.has(name)


@dataclass(frozen=True)
class NodeConfig:
    version: int
    node: Node

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

    return NodeConfig(
        version=version,
        node=Node(
            id=node_id,
            name=name,
            public_key=public_key,
            created_at=created_at,
            last_seen=last_seen,
            roles=roles,
        ),
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


def _legacy_install_role(state_dir: Path) -> str:
    path = state_dir / "install.env"
    if not path.is_file():
        return ""
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("BPC_ROLE="):
                return line.partition("=")[2].strip()
    except OSError:
        return ""
    return ""


def infer_legacy_capabilities(state_dir: str | Path) -> dict[str, bool]:
    root = Path(state_dir)
    ru = root / "ru-node"
    has_ru_node = (
        (ru / "config.json").is_file()
        or (ru / "client.env").is_file()
        or _legacy_install_role(root) == "ru-node"
    )
    has_controller = (ru / "control" / "enabled").is_file()
    has_agent_relay = (ru / "agent" / "enabled").is_file()
    has_wgshim_relay = (ru / "wgshim" / "enabled").is_file()

    return {
        "controller": has_controller,
        "gateway": has_ru_node,
        "relay": has_agent_relay or has_wgshim_relay,
        "site_router": False,
    }


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
        ),
    )


def migrate_legacy_node(
    state_dir: str | Path,
    *,
    name: str | None = None,
    touch_last_seen: bool = False,
    now: int | None = None,
) -> tuple[NodeConfig, bool]:
    root = Path(state_dir)
    path = root / "node.yaml"
    timestamp = int(time.time()) if now is None else int(now)
    inferred = infer_legacy_capabilities(root)

    if path.is_file():
        current = load_node_config(path)
        values = dict(current.node.roles.values)
        for capability, enabled in inferred.items():
            if enabled:
                values[capability] = True
        node_name = current.node.name
        if name is not None and name.strip():
            node_name = name.strip()
        updated = NodeConfig(
            version=current.version,
            node=Node(
                id=current.node.id,
                name=node_name,
                public_key=current.node.public_key,
                created_at=current.node.created_at,
                last_seen=timestamp if touch_last_seen else current.node.last_seen,
                roles=Capabilities.from_mapping(values),
            ),
        )
        changed = updated != current
        if changed:
            save_node_config(path, updated)
        return updated, changed

    created = new_node_config(name=name, roles=inferred, now=timestamp)
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
            ),
        )
    save_node_config(path, created)
    return created, True


def set_capabilities(
    path: str | Path,
    updates: Mapping[str, bool],
) -> NodeConfig:
    current = load_node_config(path)
    roles = current.node.roles.with_updates(**dict(updates))
    updated = NodeConfig(
        version=current.version,
        node=Node(
            id=current.node.id,
            name=current.node.name,
            public_key=current.node.public_key,
            created_at=current.node.created_at,
            last_seen=current.node.last_seen,
            roles=roles,
        ),
    )
    save_node_config(path, updated)
    return updated
