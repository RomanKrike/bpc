from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from bpc_connect.state import StateLayout

LEGACY_NODE_DIRNAME = "ru-node"
LEGACY_DEVICE_SITE_ROUTER_ROLE = "gateway"


def legacy_node_dir(state_dir: str | Path) -> Path:
    return Path(state_dir) / LEGACY_NODE_DIRNAME


def legacy_control_dir(state_dir: str | Path) -> Path:
    return legacy_node_dir(state_dir) / "control"


def legacy_transport_dir(state_dir: str | Path, name: str) -> Path:
    return legacy_node_dir(state_dir) / name


def legacy_install_role(state_dir: str | Path) -> str:
    path = Path(state_dir) / "install.env"
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
    legacy = legacy_node_dir(root)
    has_gateway = (
        (legacy / "config.json").is_file()
        or (legacy / "client.env").is_file()
        or legacy_install_role(root) == LEGACY_NODE_DIRNAME
    )
    return {
        "controller": (legacy / "control" / "enabled").is_file(),
        "gateway": has_gateway,
        "relay": (legacy / "agent" / "enabled").is_file()
        or (legacy / "wgshim" / "enabled").is_file(),
        "site_router": False,
    }


def controller_state_dir(state_dir: str | Path) -> Path:
    """Resolve Controller state during the migration window.

    Canonical state always wins. Legacy state is read-only compatibility input
    until it is copied by the Stage 4.5 migration.
    """

    layout = StateLayout.from_root(state_dir)
    if layout.control_dir.is_dir():
        return layout.control_dir
    return legacy_control_dir(state_dir)


def is_legacy_site_router(device: dict[str, Any]) -> bool:
    return str(device.get("role", "")) == LEGACY_DEVICE_SITE_ROUTER_ROLE


def legacy_site_router_routes(device: dict[str, Any]) -> list[str]:
    if not is_legacy_site_router(device):
        return []
    raw = device.get("advertised_routes", [])
    if not isinstance(raw, list):
        return []
    routes: list[str] = []
    for value in raw:
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError:
            continue
        if network.version == 4 and network.prefixlen != 0:
            routes.append(str(network))
    return routes


def legacy_managed_routes(device: dict[str, Any]) -> list[str]:
    raw = device.get("managed_routes", [])
    if not isinstance(raw, list):
        return []
    return [str(value) for value in raw]


def apply_legacy_tunnel(device: dict[str, Any], config: dict[str, Any]) -> None:
    value = str(device.get("legacy_tunnel", "")).strip()
    if value:
        config["legacy_tunnel"] = value
