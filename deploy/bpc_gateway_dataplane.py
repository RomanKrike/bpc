#!/usr/bin/env python3
from __future__ import annotations

import base64
import ipaddress
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

MODULE_DIR = Path(__file__).resolve().parent
SOURCE_ROOT = MODULE_DIR / "src"
if not (SOURCE_ROOT / "bpc_connect").is_dir():
    SOURCE_ROOT = MODULE_DIR.parent / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from bpc_connect.compat.legacy import compat_site_routes  # noqa: E402


class GatewayDataplaneError(RuntimeError):
    pass


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise GatewayDataplaneError(f"{path} does not contain a JSON object")
    return value


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(value, encoding="ascii")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _run_wg(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["wg", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise GatewayDataplaneError(detail or f"wg {' '.join(args)} failed")
    return completed


def _valid_wireguard_key(value: str) -> bool:
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except (ValueError, base64.binascii.Error):
        return False
    return len(raw) == 32 and any(raw)


def _valid_address(value: str) -> bool:
    try:
        address = ipaddress.ip_interface(value.strip())
    except ValueError:
        return False
    return address.version == 4 and address.network.prefixlen == 32


def _owned_interface(control_dir: Path, config: dict[str, Any]) -> tuple[str, Path]:
    interface = str(config.get("wireguard_interface", "")).strip()
    key_dir = Path(str(config.get("wgshim_key_dir", "")).strip())
    if not interface or not str(key_dir):
        raise GatewayDataplaneError("canonical dataplane config is incomplete")
    ownership_path = key_dir.parent / "ownership.json"
    ownership = _read_json(ownership_path)
    if (
        ownership.get("owner") != "bpc"
        or ownership.get("kind") != "wireguard-interface"
        or str(ownership.get("name", "")) != interface
    ):
        raise GatewayDataplaneError(
            f"refusing dataplane reconciliation: ownership is not proven for {interface}"
        )
    if _run_wg("show", interface, check=False).returncode != 0:
        raise GatewayDataplaneError(f"WireGuard interface is unavailable: {interface}")
    return interface, key_dir


def _active_devices(control_dir: Path) -> dict[str, dict[str, str]]:
    devices: dict[str, dict[str, str]] = {}
    directory = control_dir / "devices"
    if not directory.is_dir():
        return devices
    for path in sorted(directory.glob("*.json")):
        try:
            value = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError, GatewayDataplaneError):
            continue
        if not bool(value.get("enabled", True)):
            continue
        if bool(value.get("revoked", False)) or value.get("revoked_at") not in (None, "", 0):
            continue
        device_id = str(value.get("id", value.get("device_id", ""))).strip()
        public_key = str(value.get("wireguard_public_key", "")).strip()
        address = str(value.get("wireguard_address", "")).strip()
        psk = str(value.get("wgshim_psk", "")).strip()
        if (
            not device_id
            or not _valid_wireguard_key(public_key)
            or not _valid_address(address)
            or not _valid_wireguard_key(psk)
        ):
            continue
        devices[device_id] = {
            "wireguard_public_key": public_key,
            "wireguard_address": address,
            "wgshim_psk": psk,
            "allowed_ips": ",".join([address, *compat_site_routes(value)]),
        }
    return devices


def reconcile_gateway_dataplane(state_dir: Path) -> dict[str, int]:
    """Materialize replicated Device state into this Node's local dataplane.

    Only peers previously managed by this reconciler are removed. Site-router,
    compatibility and operator-managed WireGuard peers remain untouched.
    """

    control_dir = state_dir / "control"
    config_path = control_dir / "config.json"
    if not config_path.is_file():
        raise GatewayDataplaneError("canonical control config is unavailable")
    config = _read_json(config_path)
    interface, key_dir = _owned_interface(control_dir, config)
    wanted = _active_devices(control_dir)

    state_path = state_dir / "gateway-dataplane-managed.json"
    previous: dict[str, Any] = {}
    if state_path.is_file():
        previous = _read_json(state_path)
    previous_devices = previous.get("devices", {})
    if not isinstance(previous_devices, dict):
        raise GatewayDataplaneError("invalid gateway dataplane ownership state")

    if previous and previous.get("interface") != interface:
        raise GatewayDataplaneError("gateway ownership ledger belongs to another interface")

    for device_id, item in wanted.items():
        _atomic_text(key_dir / f"{device_id}.key", item["wgshim_psk"] + "\n")
        _run_wg(
            "set",
            interface,
            "peer",
            item["wireguard_public_key"],
            "allowed-ips",
            item["allowed_ips"],
        )

    wanted_ids = set(wanted)
    wanted_public_keys = {
        item["wireguard_public_key"] for item in wanted.values()
    }
    removed = 0
    for device_id, raw_previous in previous_devices.items():
        if not isinstance(raw_previous, dict):
            continue
        old_public_key = str(raw_previous.get("wireguard_public_key", "")).strip()
        if old_public_key and old_public_key not in wanted_public_keys:
            _run_wg("set", interface, "peer", old_public_key, "remove")
        if device_id not in wanted_ids:
            (key_dir / f"{device_id}.key").unlink(missing_ok=True)
            removed += 1

    _atomic_json(
        state_path,
        {
            "version": 1,
            "interface": interface,
            "devices": {
                device_id: {
                    "wireguard_public_key": item["wireguard_public_key"],
                    "wireguard_address": item["wireguard_address"],
                }
                for device_id, item in sorted(wanted.items())
            },
        },
    )
    return {"active": len(wanted), "removed": removed}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Reconcile BPC Gateway dataplane")
    parser.add_argument("--state-dir", type=Path, default=Path("/etc/bpc-connect"))
    args = parser.parse_args()
    try:
        result = reconcile_gateway_dataplane(args.state_dir)
    except (GatewayDataplaneError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
    print(f"Gateway dataplane: active={result['active']} removed={result['removed']}")
