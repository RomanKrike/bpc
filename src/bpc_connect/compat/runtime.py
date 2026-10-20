from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from bpc_connect.compat.legacy import controller_state_dir, legacy_node_dir
from bpc_connect.state import StateLayout


class RuntimeCompatibilityError(RuntimeError):
    pass


def _read_env_value(path: Path, name: str) -> str:
    if not path.is_file():
        return ""
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep and key == name:
                return value.strip()
    except OSError:
        return ""
    return ""


def agent_runtime_env(state_dir: Path) -> Path:
    """Return the historical Agent runtime env behind the compatibility boundary."""
    return legacy_node_dir(state_dir) / "agent" / "runtime.env"


def service_state(name: str) -> str:
    completed = subprocess.run(
        ["systemctl", "is-active", name],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() or "inactive"


def routed_dataplane(role_config: dict[str, Any]) -> bool:
    """Explicit mesh mode never provisions the historical Agent transports."""
    gateway = role_config.get("gateway", {})
    return isinstance(gateway, dict) and gateway.get("mode") == "routed"


def default_role_config(
    state_dir: Path, roles: list[str], *, dataplane: str = "compat",
) -> dict[str, Any]:
    if dataplane not in {"compat", "routed"}:
        raise RuntimeCompatibilityError(f"unsupported dataplane: {dataplane}")
    result: dict[str, Any] = {}
    legacy = legacy_node_dir(state_dir)
    if "gateway" in roles:
        reality_name = _read_env_value(legacy / "client.env", "BPC_REALITY_SERVER_NAME")
        result["gateway"] = {
            "reality_server_name": reality_name or "www.bing.com",
            "xray_port": 443,
        }
        if dataplane == "routed":
            result["gateway"] = {"mode": "routed"}
    if "relay" in roles:
        result["relay"] = {"mode": "routed" if dataplane == "routed" else "agent"}
    if "site_router" in roles:
        result["site_router"] = {"advertised_routes": []}
    return result


def _run_checked(args: list[str], *, env: dict[str, str] | None = None) -> None:
    completed = subprocess.run(args, check=False, env=env)
    if completed.returncode != 0:
        raise RuntimeCompatibilityError(
            f"command failed ({completed.returncode}): {' '.join(args)}"
        )


def reconcile_transport_roles(
    state_dir: Path,
    roles: dict[str, Any],
    role_config: dict[str, Any],
    *,
    deploy_dir: Path,
) -> dict[str, str]:
    """Bridge canonical Node capabilities to the existing transport runtime.

    Historical state paths exist only in this compatibility module. New domain
    state remains Node-based.
    """

    results: dict[str, str] = {}
    legacy = legacy_node_dir(state_dir)

    mesh_only = routed_dataplane(role_config)
    gateway = role_config.get("gateway", {})
    if isinstance(gateway, dict) and gateway.get("mode", "compat") not in {"compat", "routed"}:
        raise RuntimeCompatibilityError("unsupported Gateway dataplane mode")
    relay = role_config.get("relay", {})
    relay_mode = relay.get("mode", "agent") if isinstance(relay, dict) else "agent"
    if (bool(roles.get("gateway")) and bool(roles.get("relay"))
            and mesh_only != (relay_mode == "routed")):
        raise RuntimeCompatibilityError("Gateway and Relay dataplane modes must agree")

    # Service readiness is assessed from routed policy/status after the first
    # heartbeat supplies links. No legacy service is started in this mode.
    if mesh_only and bool(roles.get("gateway")):
        results["gateway"] = "configured"
    if relay_mode == "routed" and bool(roles.get("relay")):
        results["relay"] = "configured"

    if bool(roles.get("gateway")) and not mesh_only:
        gateway = role_config.get("gateway", {})
        if not isinstance(gateway, dict):
            gateway = {}
        if not (legacy / "config.json").is_file():
            env = dict(os.environ)
            env["BPC_DIR"] = str(legacy)
            env["REALITY_SERVER_NAME"] = str(
                gateway.get("reality_server_name", "www.bing.com")
            )
            env["XRAY_PORT"] = str(int(gateway.get("xray_port", 443)))
            _run_checked([str(deploy_dir / "bootstrap-ru-node.sh")], env=env)
        else:
            subprocess.run(
                ["systemctl", "start", "xray.service"],
                check=False,
                capture_output=True,
            )
        results["gateway"] = service_state("xray.service")

    if bool(roles.get("relay")) and relay_mode != "routed":
        relay = role_config.get("relay", {})
        if not isinstance(relay, dict):
            relay = {}
        mode = str(relay.get("mode", "agent"))
        if mode != "agent":
            results["relay"] = f"unsupported-mode:{mode}"
        elif (legacy / "agent" / "enabled").is_file():
            subprocess.run(
                ["systemctl", "start", "bpc-agent-relay.service"],
                check=False,
                capture_output=True,
            )
            results["relay"] = service_state("bpc-agent-relay.service")
        elif (legacy / "client.env").is_file():
            _run_checked([str(deploy_dir / "bpc-enable-agent-dataplane.sh")])
            results["relay"] = service_state("bpc-agent-relay.service")
        else:
            results["relay"] = "pending:gateway-or-public-host"

    if bool(roles.get("controller")):
        control = controller_state_dir(state_dir)
        if (control / "enabled").is_file():
            subprocess.run(
                ["systemctl", "start", "bpc-control.service"],
                check=False,
                capture_output=True,
            )
            results["controller"] = service_state("bpc-control.service")
        else:
            results["controller"] = "pending:tls-bootstrap"

    if bool(roles.get("site_router")):
        state = StateLayout.from_root(state_dir)
        configured = state.node_config.is_file()
        results["site_router"] = "configured" if configured else "pending:model"

    return results
