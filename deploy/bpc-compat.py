#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bpc_connect.compat.legacy import (  # noqa: E402
    compat_site_routes,
    controller_state_dir,
    is_compat_site_router,
)


def read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("record is not an object")
    return value


def gateway_list(state_dir: Path) -> int:
    control = controller_state_dir(state_dir)
    found = False
    for path in sorted((control / "devices").glob("*.json")):
        try:
            device = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if not is_compat_site_router(device):
            continue
        found = True
        name = str(device.get("device", device.get("name", "?")))
        address = str(device.get("wireguard_address", "?"))
        routes = ",".join(compat_site_routes(device)) or "-"
        revoked = bool(device.get("revoked", False))
        print(f"{name}: address={address} revoked={revoked} routes={routes}")
    if not found:
        print("No legacy BP Gateway records.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="BPC legacy compatibility utilities")
    parser.add_argument("--state-dir", type=Path, default=Path("/etc/bpc-connect"))
    parser.add_argument("command", choices=("gateway-list",))
    args = parser.parse_args()
    if args.command == "gateway-list":
        return gateway_list(args.state_dir)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
