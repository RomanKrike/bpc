#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "deploy"))

from bpc_node_enrollment import generate_node_identity, normalize_roles  # noqa: E402

from bpc_connect.compat.legacy import legacy_control_dir, legacy_node_dir  # noqa: E402
from bpc_connect.compat.migration import format_report, migrate_canonical_state  # noqa: E402
from bpc_connect.compat.runtime import (  # noqa: E402
    RuntimeCompatibilityError,
    default_role_config,
    reconcile_transport_roles,
)
from bpc_connect.node import (  # noqa: E402
    CORE_CAPABILITIES,
    reconcile_node_config,
    set_node_identity,
)
from bpc_connect.state import StateLayout  # noqa: E402


class ClusterInitError(RuntimeError):
    pass


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def run_checked(command: list[str]) -> None:
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        raise ClusterInitError(
            f"command failed ({completed.returncode}): {' '.join(command)}"
        )


def existing_subscription_ready(state_dir: Path) -> bool:
    subscription = legacy_node_dir(state_dir) / "subscription"
    return (subscription / "enabled").is_file() and (subscription / "runtime.env").is_file()


def existing_controller_ready(state_dir: Path) -> bool:
    canonical = StateLayout.from_root(state_dir).control_dir
    return (canonical / "enabled").is_file() or (
        legacy_control_dir(state_dir) / "enabled"
    ).is_file()


def _env_value(path: Path, key: str) -> str:
    if not path.is_file():
        return ""
    prefix = f"{key}="
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    return ""


def controller_advertise_host(state: StateLayout, explicit: str | None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    for path, key in (
        (state.control_dir / "runtime.env", "CONTROL_HOST"),
        (legacy_node_dir(state.root) / "subscription" / "runtime.env", "SUBSCRIPTION_HOST"),
    ):
        value = _env_value(path, key)
        if value:
            return value
    raise ClusterInitError(
        "Controller advertise hostname is unknown; pass --hostname <DNS-name>"
    )


def ensure_cluster_record(state: StateLayout, node_id: str, now: int) -> dict[str, Any]:
    path = state.cluster_dir / "cluster.json"
    if path.is_file():
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ClusterInitError("invalid canonical cluster state")
        existing_controller = str(value.get("controller_node_id", ""))
        if existing_controller and existing_controller != node_id:
            raise ClusterInitError(
                "this state directory is already initialized by another Controller Node"
            )
        return value

    value = {
        "version": 1,
        "cluster_id": uuid.uuid4().hex,
        "created_at": now,
        "controller_node_id": node_id,
        "protocol_version": 1,
        "state_schema_version": 1,
    }
    atomic_json(path, value)
    return value


def cmd_init(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise ClusterInitError("run bpc init as root")

    roles = normalize_roles(args.roles or ["controller,gateway,relay"])
    if "controller" not in roles:
        raise ClusterInitError("the first BPC Node must include the controller capability")

    state = StateLayout.from_root(args.state_dir)

    # A clean first Controller needs trusted HTTPS. Existing installations can
    # reuse their already provisioned subscription certificate. Refuse before
    # changing state when neither source exists.
    if (
        not existing_controller_ready(state.root)
        and not existing_subscription_ready(state.root)
        and not args.hostname
    ):
        raise ClusterInitError(
            "trusted Controller TLS is not provisioned; pass --hostname <DNS-name> "
            "for the first initialization"
        )

    report = migrate_canonical_state(state.root)

    updates = {name: name in roles for name in CORE_CAPABILITIES}
    config, _ = reconcile_node_config(
        state.root,
        name=args.name,
        capability_updates=updates,
        touch_last_seen=True,
    )
    public_key = generate_node_identity(state.root)
    config = set_node_identity(state.node_config, public_key)
    cluster = ensure_cluster_record(state, config.node.id, int(time.time()))

    role_config = default_role_config(state.root, roles)
    gateway = role_config.get("gateway")
    if isinstance(gateway, dict):
        if args.reality_server_name:
            gateway["reality_server_name"] = args.reality_server_name
        if args.gateway_port:
            gateway["xray_port"] = args.gateway_port

    try:
        runtime = reconcile_transport_roles(
            state.root,
            {role: True for role in roles},
            role_config,
            deploy_dir=ROOT / "deploy",
        )
    except RuntimeCompatibilityError as exc:
        raise ClusterInitError(str(exc)) from exc

    if not existing_subscription_ready(state.root) and not existing_controller_ready(state.root):
        command = [
            str(ROOT / "deploy" / "bpc-enable-subscription.sh"),
            "--hostname",
            args.hostname,
        ]
        run_checked(command)

    advertise_host = controller_advertise_host(state, args.hostname)
    run_checked(
        [
            str(ROOT / "deploy" / "bpc-enable-cluster.sh"),
            "--advertise-host",
            advertise_host,
            "--bootstrap",
        ]
    )
    runtime["distributed_controller"] = subprocess.run(
        ["systemctl", "is-active", "bpc-controld.service"],
        check=False,
        capture_output=True,
        text=True,
    ).stdout.strip() or "inactive"

    if not existing_controller_ready(state.root):
        run_checked([str(ROOT / "deploy" / "bpc-enable-control.sh")])
    elif not (state.control_dir / "enabled").is_file():
        # Legacy Controller state was copied to canonical state by migration.
        run_checked([str(ROOT / "deploy" / "bpc-enable-control.sh")])
    else:
        subprocess.run(
            ["systemctl", "restart", "bpc-control.service"],
            check=False,
            capture_output=True,
        )

    runtime["controller"] = subprocess.run(
        ["systemctl", "is-active", "bpc-control.service"],
        check=False,
        capture_output=True,
        text=True,
    ).stdout.strip() or "inactive"

    print(format_report(report))
    print()
    print(f"Cluster initialized: {cluster['cluster_id']}")
    print(f"Node: {config.node.name} ({config.node.id})")
    print(f"Roles: {', '.join(config.node.roles.enabled())}")
    for role, status in sorted(runtime.items()):
        print(f"  {role}: {status}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BPC cluster bootstrap")
    parser.add_argument("--state-dir", type=Path, default=Path("/etc/bpc-connect"))
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--name")
    init.add_argument("--roles", action="append")
    init.add_argument("--hostname")
    init.add_argument("--reality-server-name")
    init.add_argument("--gateway-port", type=int)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "init":
            return cmd_init(args)
    except (ClusterInitError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
