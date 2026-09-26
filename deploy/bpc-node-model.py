#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bpc_connect.errors import BPCConfigError  # noqa: E402
from bpc_connect.node import (  # noqa: E402
    CORE_CAPABILITIES,
    load_node_config,
    migrate_legacy_node,
    set_capabilities,
)

DEFAULT_STATE_DIR = Path("/etc/bpc-connect")


def service_state(name: str) -> str:
    completed = subprocess.run(
        ["systemctl", "is-active", name],
        check=False,
        capture_output=True,
        text=True,
    )
    value = completed.stdout.strip()
    return value or "inactive"


def capability_runtime_state(state_dir: Path, capability: str) -> str:
    ru = state_dir / "ru-node"
    if capability == "controller":
        if not (ru / "control" / "enabled").is_file():
            return "configured"
        return service_state("bpc-control.service")
    if capability == "gateway":
        if not (ru / "config.json").is_file():
            return "configured"
        return service_state("xray.service")
    if capability == "relay":
        states: list[str] = []
        if (ru / "agent" / "enabled").is_file():
            states.append(f"agent={service_state('bpc-agent-relay.service')}")
        if (ru / "wgshim" / "enabled").is_file():
            states.append(f"wgshim={service_state('bpc-wgshim.service')}")
        return ",".join(states) if states else "configured"
    if capability == "site_router":
        return "configured"
    return "configured"


def cmd_migrate(args: argparse.Namespace) -> int:
    config, changed = migrate_legacy_node(
        args.state_dir,
        name=args.name,
        touch_last_seen=False,
    )
    action = "updated" if changed else "unchanged"
    print(f"Node config {action}: {args.state_dir / 'node.yaml'}")
    print(f"Node: {config.node.name} ({config.node.id})")
    print(f"Capabilities: {', '.join(config.node.roles.enabled()) or 'none'}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    config, _ = migrate_legacy_node(
        args.state_dir,
        name=args.name,
        touch_last_seen=False,
    )
    enabled = config.node.roles.enabled()
    print(f"Node: {config.node.name}")
    print(f"ID: {config.node.id}")
    print(f"Config version: {config.version}")
    print(f"Capabilities: {', '.join(enabled) or 'none'}")
    print(f"Last seen: {config.node.last_seen}")
    for capability in enabled:
        print(
            f"  {capability}: "
            f"{capability_runtime_state(args.state_dir, capability)}"
        )
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    path = args.state_dir / "node.yaml"
    if not path.is_file():
        migrate_legacy_node(args.state_dir, name=args.name, touch_last_seen=False)
    config = load_node_config(path)
    sys.stdout.write(
        yaml.safe_dump(
            config.to_mapping(),
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )
    )
    return 0


def cmd_capability(args: argparse.Namespace) -> int:
    path = args.state_dir / "node.yaml"
    if not path.is_file():
        migrate_legacy_node(args.state_dir, name=args.name, touch_last_seen=False)
    enabled = args.state == "enable"
    config = set_capabilities(path, {args.capability: enabled})
    state = "enabled" if enabled else "disabled"
    print(f"Capability {args.capability}: {state}")
    print(f"Capabilities: {', '.join(config.node.roles.enabled()) or 'none'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bpc-node-model")
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help="BPC state directory",
    )
    parser.add_argument("--name", help="Override node name during migration/reconciliation")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    sub.add_parser("status")
    sub.add_parser("info")

    capability = sub.add_parser("capability")
    capability.add_argument("capability")
    capability.add_argument("state", choices=("enable", "disable"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "migrate":
            return cmd_migrate(args)
        if args.command == "status":
            return cmd_status(args)
        if args.command == "info":
            return cmd_info(args)
        if args.command == "capability":
            return cmd_capability(args)
    except (BPCConfigError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
