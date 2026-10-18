#!/usr/bin/env python3
"""Explicit Device ingress on an enrolled routed Controller/Gateway.

Reuses the existing owned Agent dataplane without starting Xray or changing
canonical cluster config. Run under an independent, pre-armed rollback watchdog.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bpc_gateway_snapshot as snapshots  # noqa: E402
import bpc_node_enrollment as node  # noqa: E402


def check_snapshot(state: Path) -> None:
    # Relay runs with ProtectSystem=strict. Share the existing lock read-only;
    # never create/chmod state from this service's startup guard.
    with (state / "security-runtime.lock").open("rb") as lock:
        node.fcntl.flock(lock.fileno(), node.fcntl.LOCK_SH)
        snapshots._load_valid_security_snapshot(state)


def enable(state: Path, host: str, *, systemd_dir: Path = Path("/etc/systemd/system")) -> None:
    if not node.re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", host):
        raise ValueError("invalid public host")
    record = node.enrolled_state(state) or {}
    roles = record.get("roles", {})
    if not all(roles.get(role) for role in ("controller", "gateway", "relay")):
        raise ValueError("requires an enrolled Controller/Gateway/Relay")
    if not node.enrollment_uses_routed_dataplane(record):
        raise ValueError("requires routed mesh mode")
    node.load_valid_security_snapshot(state)
    config = node.read_json(state / "control/config.json")
    if not config.get("wireguard_server_private_key"):
        raise ValueError("canonical overlay identity is missing; refusing a new key")
    if config.get("wireguard_interface") != "bpcag0":
        raise ValueError("unsupported Device ingress interface")
    if node.primary_compat_runtime(state):
        raise ValueError("bootstrap ingress is already managed by its existing runtime")
    enabled = node.device_ingress_enabled(state)
    journal_path = state / "device-ingress-provision.json"
    journal = node.read_json(journal_path) if journal_path.exists() else {}
    if journal and journal != {"version": 1, "node_id": record["node_id"], "host": host}:
        raise ValueError("Device ingress provisioning journal does not match local Node/host")
    legacy = state / "ru-node"
    agent = legacy / "agent"
    if Path(config.get("wgshim_key_dir", "")) != agent / "wgshim-keys":
        raise ValueError("canonical Device key directory does not match local ingress")
    if not enabled and not journal and (agent.exists() or (legacy / "client.env").exists()
                        or Path("/sys/class/net/bpcag0").exists()
                        or Path("/etc/wireguard/bpcag0.conf").exists()):
        raise ValueError("existing ingress resources require inspection; refusing adoption")
    dropin = systemd_dir / "bpc-agent-relay.service.d/40-device-ingress.conf"
    expected = ("[Service]\nExecStartPre=/usr/bin/python3 "
                "/opt/bpc/current/deploy/bpc-enable-device-ingress.py --check\n")
    if dropin.exists() and dropin.read_text() != expected:
        raise ValueError("unknown Device ingress service guard; refusing overwrite")
    node.atomic_json(journal_path, {"version": 1, "node_id": record["node_id"], "host": host})
    legacy.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Only the public host is needed; no historical proxy bootstrap is invoked.
    temporary = legacy / ".client.env.device-ingress.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as output:
        output.write(f"BPC_RU_HOST={host}\n")
    os.replace(temporary, legacy / "client.env")
    env = dict(os.environ, BPC_STATE_DIR=str(state), BPC_SKIP_NODE_MODEL="true",
               BPC_AGENT_WG_SUBNET=str(config["wireguard_subnet"]),
               BPC_AGENT_WG_SERVER_ADDRESS=str(config["wireguard_server_address"]),
               BPC_AGENT_WG_MTU=str(config["wireguard_mtu"]),
               BPC_AGENT_WG_KEEPALIVE=str(config["wireguard_keepalive"]))
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text(expected)
    subprocess.run(["bash", str(Path(__file__).with_name("bpc-enable-agent-dataplane.sh"))],
                   env=env, check=True, timeout=240)
    # Do not advertise the new gateway until canonical peers and Access exist.
    node.reconcile_local_gateway_state(state)
    node.atomic_json(state / "device-ingress.json", {
        "version": 1, "node_id": record["node_id"],
    })
    journal_path.unlink()
    print(json.dumps({"ok": True, "node_id": record["node_id"], "host": host}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path("/etc/bpc-connect"))
    parser.add_argument("--host")
    parser.add_argument("--check", action="store_true", help="validate signed security lease only")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root")
    if args.check:
        check_snapshot(args.state_dir)
    elif args.host:
        enable(args.state_dir, args.host)
    else:
        parser.error("--host is required for provisioning")
