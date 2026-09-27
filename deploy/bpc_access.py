#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

MODULE_DIR = Path(__file__).resolve().parent
if (MODULE_DIR / "src" / "bpc_connect").is_dir():
    SOURCE_ROOT = MODULE_DIR / "src"
else:
    SOURCE_ROOT = MODULE_DIR.parent / "src"
sys.path.insert(0, str(SOURCE_ROOT))

import bpc_control_state  # noqa: E402

from bpc_connect.compat.legacy import compat_route_grants, is_compat_site_router  # noqa: E402

DEFAULT_CONTROL_DIR = Path("/etc/bpc-connect/control")
CHAIN_NAME = "BPC-ACCESS"


class AccessError(RuntimeError):
    pass


def atomic_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return value


def _access_dir(root: Path) -> Path:
    return root / "access"


def _record_path(root: Path, subject_type: str, subject_id: str) -> Path:
    if subject_type not in {"user", "device"}:
        raise AccessError(f"unsupported Access subject type: {subject_type}")
    if not subject_id:
        raise AccessError("Access subject ID is empty")
    return _access_dir(root) / f"{subject_type}-{subject_id}.json"


def canonical_cidr(raw: str) -> str:
    try:
        network = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError as exc:
        raise AccessError(f"invalid CIDR {raw!r}: {exc}") from exc
    if network.version != 4:
        raise AccessError("Access currently supports IPv4 CIDRs only")
    if network.prefixlen == 0:
        raise AccessError("0.0.0.0/0 is not allowed; BPC remains split-tunnel")
    return str(network)


def _canonical_networks(values: list[object]) -> list[ipaddress.IPv4Network]:
    result: list[ipaddress.IPv4Network] = []
    seen: set[str] = set()
    for raw in values:
        try:
            canonical = canonical_cidr(str(raw))
        except AccessError:
            continue
        if canonical in seen:
            continue
        seen.add(canonical)
        result.append(ipaddress.ip_network(canonical, strict=False))
    return result


def load_access(root: Path, subject_type: str, subject_id: str) -> dict[str, Any]:
    path = _record_path(root, subject_type, subject_id)
    if not path.is_file():
        return {
            "version": 1,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "allow": [],
            "deny": [],
            "updated_at": 0,
        }
    try:
        value = read_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise AccessError(f"invalid Access record: {path}") from exc
    if value.get("subject_type") != subject_type or str(value.get("subject_id", "")) != subject_id:
        raise AccessError(f"Access record subject mismatch: {path}")
    allow = value.get("allow", [])
    deny = value.get("deny", [])
    if not isinstance(allow, list) or not isinstance(deny, list):
        raise AccessError(f"Access record contains invalid allow/deny lists: {path}")
    value["allow"] = [str(network) for network in _canonical_networks(allow)]
    value["deny"] = [str(network) for network in _canonical_networks(deny)]
    return value


def list_access(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    directory = _access_dir(root)
    if not directory.is_dir():
        return records
    for path in sorted(directory.glob("*.json")):
        try:
            value = read_json(path)
            subject_type = str(value.get("subject_type", ""))
            subject_id = str(value.get("subject_id", ""))
            if subject_type not in {"user", "device"} or not subject_id:
                continue
            records.append(load_access(root, subject_type, subject_id))
        except (OSError, ValueError, json.JSONDecodeError, AccessError):
            continue
    return records


def set_access(
    root: Path,
    subject_type: str,
    subject_id: str,
    effect: str,
    cidrs: list[str],
    *,
    now: int | None = None,
) -> dict[str, Any]:
    if effect not in {"allow", "deny"}:
        raise AccessError("Access effect must be allow or deny")
    canonical = [canonical_cidr(value) for value in cidrs]
    if not canonical:
        raise AccessError("at least one CIDR is required")

    record_path = _record_path(root, subject_type, subject_id)
    existing_raw: bytes | None = None
    if bpc_control_state.cluster_enabled(root):
        try:
            bpc_control_state.strong_read(root)
            if record_path.is_file():
                existing_raw = record_path.read_bytes()
        except bpc_control_state.ControlStateError as exc:
            raise AccessError(str(exc)) from exc
    record = load_access(root, subject_type, subject_id)
    allow = list(record["allow"])
    deny = list(record["deny"])
    target = allow if effect == "allow" else deny
    opposite = deny if effect == "allow" else allow

    for cidr in canonical:
        # grant/revoke toggles the exact rule. Broader/narrower rules remain so
        # deterministic deny precedence still applies for overlaps.
        opposite[:] = [item for item in opposite if item != cidr]
        if cidr not in target:
            target.append(cidr)

    record["allow"] = sorted(set(allow))
    record["deny"] = sorted(set(deny))
    record["updated_at"] = int(time.time()) if now is None else int(now)
    if bpc_control_state.cluster_enabled(root):
        operation: dict[str, Any] = {
            "op": "put",
            "path": record_path,
            "data": json.dumps(
                record, sort_keys=True, separators=(",", ":")
            ).encode("utf-8"),
        }
        if existing_raw is None:
            operation["if_absent"] = True
        else:
            operation["expected_sha256"] = hashlib.sha256(existing_raw).hexdigest()
        try:
            bpc_control_state.mutation(
                root,
                "SetAccess",
                [operation],
                issued_at=record["updated_at"],
            )
        except bpc_control_state.ControlStateError as exc:
            raise AccessError(str(exc)) from exc
    else:
        atomic_json(record_path, record)
    return record


def _subtract_denies(
    allows: list[ipaddress.IPv4Network],
    denies: list[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    fragments = list(allows)
    for deny in denies:
        next_fragments: list[ipaddress.IPv4Network] = []
        for network in fragments:
            if not network.overlaps(deny):
                next_fragments.append(network)
                continue
            if network.subnet_of(deny):
                continue
            if deny.subnet_of(network):
                next_fragments.extend(network.address_exclude(deny))
                continue
            # IPv4 CIDRs that overlap are always nested, but fail closed if a
            # future network implementation violates that assumption.
        fragments = next_fragments
    collapsed = list(ipaddress.collapse_addresses(fragments))
    return sorted(collapsed, key=lambda item: (int(item.network_address), item.prefixlen))


def effective_networks(root: Path, device: dict[str, Any]) -> list[ipaddress.IPv4Network]:
    if bpc_control_state.cluster_enabled(root):
        try:
            bpc_control_state.strong_read(root)
        except bpc_control_state.ControlStateError as exc:
            raise AccessError(str(exc)) from exc
    if not bool(device.get("enabled", True)):
        return []
    if bool(device.get("revoked", False)) or device.get("revoked_at") not in (None, "", 0):
        return []

    allows: list[ipaddress.IPv4Network] = []
    denies: list[ipaddress.IPv4Network] = []

    user_id = str(device.get("user_id", "")).strip()
    device_id = str(device.get("id", device.get("device_id", ""))).strip()
    if user_id:
        record = load_access(root, "user", user_id)
        allows.extend(_canonical_networks(list(record["allow"])))
        denies.extend(_canonical_networks(list(record["deny"])))
    if device_id:
        record = load_access(root, "device", device_id)
        allows.extend(_canonical_networks(list(record["allow"])))
        denies.extend(_canonical_networks(list(record["deny"])))

    # Historical Device route grants are read only through the compatibility
    # adapter. Access deny rules still override them.
    allows.extend(_canonical_networks(compat_route_grants(device)))

    return _subtract_denies(
        list(ipaddress.collapse_addresses(allows)),
        list(ipaddress.collapse_addresses(denies)),
    )


def effective_routes(root: Path, device: dict[str, Any]) -> list[str]:
    return [str(network) for network in effective_networks(root, device)]


def destination_allowed(root: Path, device: dict[str, Any], destination: str) -> bool:
    try:
        address = ipaddress.ip_address(destination)
    except ValueError:
        return False
    if address.version != 4:
        return False
    return any(address in network for network in effective_networks(root, device))


def _run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if check and completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise AccessError(message or f"{' '.join(command)} exited with {completed.returncode}")
    return completed


def _active_client_devices(root: Path) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    for path in sorted((root / "devices").glob("*.json")):
        try:
            device = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if is_compat_site_router(device):
            continue
        if not bool(device.get("enabled", True)):
            continue
        if bool(device.get("revoked", False)) or device.get("revoked_at") not in (None, "", 0):
            continue
        raw_address = str(device.get("wireguard_address", "")).strip()
        if not raw_address:
            continue
        try:
            interface = ipaddress.ip_interface(raw_address)
        except ValueError:
            continue
        if interface.version != 4:
            continue
        device = dict(device)
        device["_access_source"] = f"{interface.ip}/32"
        devices.append(device)
    return devices


def _require_owned_wireguard_interface(root: Path, config: dict[str, Any]) -> str:
    interface = str(config.get("wireguard_interface", "")).strip()
    key_dir = str(config.get("wgshim_key_dir", "")).strip()
    if not interface or not key_dir:
        raise AccessError("BPC WireGuard ownership evidence is incomplete")
    ownership_path = Path(key_dir).parent / "ownership.json"
    try:
        value = read_json(ownership_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise AccessError(
            f"refusing firewall mutation: BPC ownership is not proven for {interface}"
        ) from exc
    if (
        value.get("owner") != "bpc"
        or value.get("kind") != "wireguard-interface"
        or str(value.get("name", "")) != interface
    ):
        raise AccessError(
            f"refusing firewall mutation: BPC ownership is not proven for {interface}"
        )
    return interface


def sync_access_firewall(root: Path) -> None:
    try:
        config = read_json(root / "config.json")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise AccessError("BPC control config is unavailable") from exc
    interface = _require_owned_wireguard_interface(root, config)

    state_path = root / "access-firewall.json"
    previous: dict[str, Any] = {}
    if state_path.is_file():
        try:
            previous = read_json(state_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise AccessError("invalid BPC Access firewall ownership state") from exc

    chain_check = _run(["iptables", "-nL", CHAIN_NAME], check=False)
    chain_exists = chain_check.returncode == 0
    if chain_exists:
        if (
            previous.get("chain") != CHAIN_NAME
            or not str(previous.get("interface", "")).strip()
        ):
            raise AccessError(
                f"refusing firewall mutation: ownership is not proven for chain {CHAIN_NAME}"
            )
    else:
        _run(["iptables", "-N", CHAIN_NAME])
    _run(["iptables", "-F", CHAIN_NAME])

    # Replies for a connection that was permitted by the initiating Device must
    # remain valid even if the return packet originates from another BPC peer.
    _run(
        [
            "iptables",
            "-A",
            CHAIN_NAME,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ]
    )

    for device in _active_client_devices(root):
        source = str(device["_access_source"])
        for route in effective_routes(root, device):
            _run(["iptables", "-A", CHAIN_NAME, "-s", source, "-d", route, "-j", "ACCEPT"])
        # Default deny is scoped per active client source. Gateway/static peer
        # traffic is not caught by this rule.
        _run(["iptables", "-A", CHAIN_NAME, "-s", source, "-j", "DROP"])

    previous_interface = str(previous.get("interface", "")).strip()
    if previous_interface and previous_interface != interface:
        while _run(
            ["iptables", "-C", "FORWARD", "-i", previous_interface, "-j", CHAIN_NAME],
            check=False,
        ).returncode == 0:
            _run(["iptables", "-D", "FORWARD", "-i", previous_interface, "-j", CHAIN_NAME])

    # Keep Access ahead of the broad Agent FORWARD accept rule. Dataplane
    # reconciliation can reinsert its own rule at position 1, so remove every
    # existing jump and reinsert exactly one jump at the top.
    while _run(
        ["iptables", "-C", "FORWARD", "-i", interface, "-j", CHAIN_NAME],
        check=False,
    ).returncode == 0:
        _run(["iptables", "-D", "FORWARD", "-i", interface, "-j", CHAIN_NAME])
    _run(["iptables", "-I", "FORWARD", "1", "-i", interface, "-j", CHAIN_NAME])

    atomic_json(
        state_path,
        {
            "version": 1,
            "interface": interface,
            "chain": CHAIN_NAME,
            "updated_at": int(time.time()),
        },
    )


def _resolve_subject(
    root: Path,
    *,
    username: str | None,
    device_identifier: str | None,
) -> tuple[str, str, str]:
    if bool(username) == bool(device_identifier):
        raise AccessError("specify exactly one of --user or --device")

    if username:
        from bpc_identity import load_user_by_username

        user = load_user_by_username(root, username)
        if user is None:
            raise AccessError(f"user not found: {username}")
        return "user", str(user["id"]), str(user["username"])

    from bpc_identity import resolve_device

    device = resolve_device(root, str(device_identifier))
    device_id = str(device.get("id", device.get("device_id", "")))
    label = str(device.get("name", device.get("device", device_id)))
    return "device", device_id, label


def _subject_label(root: Path, record: dict[str, Any]) -> str:
    subject_type = str(record.get("subject_type", ""))
    subject_id = str(record.get("subject_id", ""))
    try:
        if subject_type == "user":
            from bpc_identity import load_user

            return str(load_user(root, subject_id).get("username", subject_id))
        from bpc_identity import load_device

        device = load_device(root, subject_id)
        return str(device.get("name", device.get("device", subject_id)))
    except Exception:
        return subject_id


def cmd_list(args: argparse.Namespace) -> int:
    root = Path(args.state_dir)
    selected: tuple[str, str, str] | None = None
    if args.user or args.device:
        selected = _resolve_subject(root, username=args.user, device_identifier=args.device)

    records = list_access(root)
    if selected is not None:
        records = [
            record
            for record in records
            if record["subject_type"] == selected[0] and record["subject_id"] == selected[1]
        ]
        if not records:
            records = [load_access(root, selected[0], selected[1])]

    if not records:
        print("No Access rules.")
        return 0
    for record in records:
        label = _subject_label(root, record)
        allow = ",".join(record["allow"]) or "-"
        deny = ",".join(record["deny"]) or "-"
        print(
            f"{record['subject_type']}:{label}  id={record['subject_id']}  "
            f"allow={allow}  deny={deny}"
        )
    return 0


def _change(args: argparse.Namespace, effect: str) -> int:
    root = Path(args.state_dir)
    subject_type, subject_id, label = _resolve_subject(
        root,
        username=args.user,
        device_identifier=args.device,
    )
    set_access(root, subject_type, subject_id, effect, list(args.cidrs))
    sync_access_firewall(root)
    print(
        f"Access {effect}: {subject_type}:{label} "
        f"{','.join(canonical_cidr(value) for value in args.cidrs)}"
    )
    print(
        "Client routes update on the next config sync; BPC Node enforcement is active now."
    )
    return 0


def cmd_grant(args: argparse.Namespace) -> int:
    return _change(args, "allow")


def cmd_revoke(args: argparse.Namespace) -> int:
    return _change(args, "deny")


def cmd_sync_firewall(args: argparse.Namespace) -> int:
    sync_access_firewall(Path(args.state_dir))
    return 0


def _add_subject_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--user")
    group.add_argument("--device")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="BPC Access administration")
    result.add_argument("--state-dir", default=str(DEFAULT_CONTROL_DIR))
    commands = result.add_subparsers(dest="command", required=True)

    listing = commands.add_parser("list")
    group = listing.add_mutually_exclusive_group()
    group.add_argument("--user")
    group.add_argument("--device")
    listing.set_defaults(func=cmd_list)

    grant = commands.add_parser("grant")
    _add_subject_options(grant)
    grant.add_argument("cidrs", nargs="+")
    grant.set_defaults(func=cmd_grant)

    revoke = commands.add_parser("revoke")
    _add_subject_options(revoke)
    revoke.add_argument("cidrs", nargs="+")
    revoke.set_defaults(func=cmd_revoke)

    sync = commands.add_parser("sync-firewall", help=argparse.SUPPRESS)
    sync.set_defaults(func=cmd_sync_firewall)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return int(args.func(args))
    except AccessError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
