#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bpc_connect.compat.legacy import (  # noqa: E402
    capability_runtime_markers,
    migrate_legacy_node,
)
from bpc_connect.errors import BPCConfigError  # noqa: E402
from bpc_connect.node import load_node_config, reconcile_node_config, set_capabilities  # noqa: E402
from bpc_connect.state import StateLayout  # noqa: E402

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
    markers = capability_runtime_markers(state_dir, capability)
    if capability == "controller":
        return service_state("bpc-control.service") if any(p.is_file() for p in markers) else "configured"
    if capability == "gateway":
        return service_state("xray.service") if any(p.is_file() for p in markers) else "configured"
    if capability == "relay":
        if not any(p.is_file() for p in markers):
            return "configured"
        states = []
        for service in ("bpc-agent-relay.service", "bpc-wgshim.service"):
            value = service_state(service)
            if value != "inactive":
                states.append(f"{service.removesuffix('.service')}={value}")
        return ",".join(states) if states else "configured"
    return "configured"


def ensure_config(args: argparse.Namespace):
    state = StateLayout.from_root(args.state_dir)
    if state.node_config.is_file():
        return load_node_config(state.node_config)
    config, _ = migrate_legacy_node(
        args.state_dir,
        name=args.name,
        touch_last_seen=False,
    )
    return config


def cmd_migrate(args: argparse.Namespace) -> int:
    config, changed = migrate_legacy_node(
        args.state_dir,
        name=args.name,
        touch_last_seen=False,
    )
    action = "updated" if changed else "unchanged"
    print(f"Node config {action}: {StateLayout.from_root(args.state_dir).node_config}")
    print(f"Node: {config.node.name} ({config.node.id})")
    print(f"Capabilities: {', '.join(config.node.roles.enabled()) or 'none'}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    config = ensure_config(args)
    enabled = config.node.roles.enabled()
    print(f"Node: {config.node.name}")
    print(f"ID: {config.node.id}")
    print(f"Config version: {config.version}")
    print(f"Capabilities: {', '.join(enabled) or 'none'}")
    print(f"Last seen: {config.node.last_seen}")
    if config.advertised_routes:
        print(f"Advertised routes: {', '.join(config.advertised_routes)}")
    for capability in enabled:
        print(f"  {capability}: {capability_runtime_state(args.state_dir, capability)}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    config = ensure_config(args)
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
    state = StateLayout.from_root(args.state_dir)
    if not state.node_config.is_file():
        reconcile_node_config(args.state_dir, name=args.name)
    enabled = args.state == "enable"
    config = set_capabilities(state.node_config, {args.capability: enabled})
    word = "enabled" if enabled else "disabled"
    print(f"Capability {args.capability}: {word}")
    print(f"Capabilities: {', '.join(config.node.roles.enabled()) or 'none'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bpc-node-model")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--name", help="Override node name during reconciliation")
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
