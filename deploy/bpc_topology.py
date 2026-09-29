#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Iterable

DEFAULT_CONTROL_DIR = Path("/etc/bpc-connect/control")
DEFAULT_TELEMETRY_TTL = 90
MAX_INTERMEDIATE_PUBLIC_NODES = 2
MAX_PATH_HOPS = 4
VALID_HEALTH = {"healthy", "degraded", "failed", "unknown"}


class TopologyError(RuntimeError):
    pass


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TopologyError(f"{path} does not contain a JSON object")
    return value


def _atomic_local_json(path: Path, value: dict[str, Any]) -> None:
    """Write ephemeral state outside the Raft-backed control directory."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def telemetry_root(control_dir: Path) -> Path:
    return Path(control_dir).resolve().parent / "runtime" / "topology"


def node_telemetry_path(control_dir: Path, node_id: str) -> Path:
    value = str(node_id).strip()
    if not value or "/" in value or "\\" in value or len(value) > 128:
        raise TopologyError("invalid Node id for telemetry")
    return telemetry_root(control_dir) / "nodes" / f"{value}.json"


def route_owner(record: dict[str, Any]) -> str:
    return str(record.get("owner_node_id", record.get("node_id", ""))).strip()


def _node_is_revoked(control_dir: Path, node_id: str) -> bool:
    path = Path(control_dir) / "nodes" / f"{node_id}.json"
    if not path.is_file():
        return False
    try:
        return bool(_read_json(path).get("revoked", False))
    except (OSError, ValueError, json.JSONDecodeError, TopologyError):
        return False


def route_records(control_dir: Path, *, include_revoked: bool = False) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    directory = Path(control_dir) / "routes"
    if not directory.is_dir():
        return result
    for path in sorted(directory.glob("*.json")):
        try:
            record = _read_json(path)
            network = ipaddress.ip_network(str(record.get("cidr", "")).strip(), strict=False)
        except (OSError, ValueError, json.JSONDecodeError, TopologyError):
            continue
        owner = route_owner(record)
        if network.version != 4 or network.prefixlen == 0 or not owner:
            continue
        if not include_revoked and _node_is_revoked(control_dir, owner):
            continue
        record = dict(record)
        record["cidr"] = str(network)
        record["owner_node_id"] = owner
        result.append(record)
    return result


def validate_route_ownership(
    control_dir: Path,
    owner_node_id: str,
    cidrs: Iterable[str],
) -> None:
    """Reject a live Node claiming an overlapping prefix owned by another Node."""
    owner = str(owner_node_id).strip()
    if not owner:
        raise TopologyError("route owner is empty")
    wanted: list[ipaddress.IPv4Network] = []
    for raw in cidrs:
        try:
            network = ipaddress.ip_network(str(raw).strip(), strict=False)
        except ValueError as exc:
            raise TopologyError(f"invalid advertised route {raw!r}") from exc
        if network.version != 4:
            raise TopologyError("route ownership currently supports IPv4 only")
        if network.prefixlen == 0:
            raise TopologyError(
                "site_router default route requires an explicit default-route policy"
            )
        wanted.append(network)

    for record in route_records(control_dir):
        existing_owner = route_owner(record)
        if not existing_owner or existing_owner == owner:
            continue
        try:
            existing = ipaddress.ip_network(str(record["cidr"]), strict=False)
        except ValueError:
            continue
        for candidate in wanted:
            if candidate.overlaps(existing):
                raise TopologyError(
                    f"route {candidate} owned by {owner} overlaps {existing} "
                    f"owned by {existing_owner}"
                )


def _bounded_float(
    raw: Any,
    *,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    return min(maximum, max(minimum, value))


def normalize_links(
    node_id: str,
    raw: Any,
    *,
    now: int,
) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in raw[:64]:
        if not isinstance(item, dict):
            continue
        target = str(item.get("to", item.get("to_node", ""))).strip()
        if not target or target == node_id or len(target) > 128:
            continue
        health = str(item.get("health", "unknown")).strip().lower()
        if health not in VALID_HEALTH:
            health = "unknown"
        try:
            last_seen = int(item.get("last_seen", now) or now)
        except (TypeError, ValueError):
            last_seen = now
        last_seen = min(now + 300, max(0, last_seen))
        link_id = str(item.get("id", "")).strip()
        if not link_id:
            link_id = hashlib.sha256(
                f"{node_id}\0{target}".encode("utf-8")
            ).hexdigest()[:24]
        key = (node_id, target)
        if key in seen:
            continue
        seen.add(key)
        result.append(
            {
                "id": link_id[:128],
                "from": node_id,
                "to": target,
                "health": health,
                "rtt_ms": _bounded_float(
                    item.get("rtt_ms", item.get("rtt", 0)),
                    default=0,
                    minimum=0,
                    maximum=600_000,
                ),
                "loss_percent": _bounded_float(
                    item.get("loss_percent", item.get("loss", 0)),
                    default=0,
                    minimum=0,
                    maximum=100,
                ),
                "cost": _bounded_float(
                    item.get("cost", 0),
                    default=0,
                    minimum=0,
                    maximum=1_000_000,
                ),
                "last_seen": last_seen,
            }
        )
    return result


def write_node_telemetry(
    control_dir: Path,
    node_id: str,
    *,
    payload: dict[str, Any],
    compatibility: str,
    transport: dict[str, Any] | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    services = payload.get("services", {})
    if not isinstance(services, dict):
        services = {}
    try:
        protocol_version = int(payload.get("protocol_version", 0) or 0)
    except (TypeError, ValueError):
        protocol_version = 0
    try:
        schema_version = int(payload.get("state_schema_version", 0) or 0)
    except (TypeError, ValueError):
        schema_version = 0
    record = {
        "version": 1,
        "node_id": str(node_id),
        "last_seen": timestamp,
        "last_status": str(payload.get("status", "online"))[:64],
        "last_version": str(payload.get("version", ""))[:64],
        "protocol_version": protocol_version,
        "state_schema_version": schema_version,
        "compatibility": str(compatibility),
        "services": {
            str(key)[:64]: str(value)[:64]
            for key, value in services.items()
        },
        "transport": dict(transport or {}),
        "links": normalize_links(str(node_id), payload.get("links", []), now=timestamp),
    }
    _atomic_local_json(node_telemetry_path(control_dir, str(node_id)), record)
    return record


def read_node_telemetry(control_dir: Path, node_id: str) -> dict[str, Any] | None:
    path = node_telemetry_path(control_dir, node_id)
    try:
        return _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError, TopologyError):
        return None


def merge_node_telemetry(
    control_dir: Path,
    node: dict[str, Any],
    *,
    now: int | None = None,
    ttl: int = DEFAULT_TELEMETRY_TTL,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    merged = dict(node)
    node_id = str(node.get("node_id", node.get("id", ""))).strip()
    telemetry = read_node_telemetry(control_dir, node_id) if node_id else None
    if telemetry is not None:
        for key in (
            "last_seen",
            "last_status",
            "last_version",
            "protocol_version",
            "state_schema_version",
            "compatibility",
            "services",
            "transport",
        ):
            if key in telemetry:
                merged[key] = telemetry[key]
    try:
        last_seen = int(merged.get("last_seen", 0) or 0)
    except (TypeError, ValueError):
        last_seen = 0
    merged["online"] = (
        not bool(merged.get("revoked", False))
        and last_seen > 0
        and timestamp - last_seen <= ttl
    )
    return merged


def topology_snapshot(
    control_dir: Path,
    *,
    now: int | None = None,
    ttl: int = DEFAULT_TELEMETRY_TTL,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    nodes: list[dict[str, Any]] = []
    node_ids: set[str] = set()
    node_dir = Path(control_dir) / "nodes"
    if node_dir.is_dir():
        for path in sorted(node_dir.glob("*.json")):
            try:
                canonical = _read_json(path)
            except (OSError, ValueError, json.JSONDecodeError, TopologyError):
                continue
            runtime = merge_node_telemetry(
                control_dir, canonical, now=timestamp, ttl=ttl
            )
            node_id = str(runtime.get("node_id", runtime.get("id", ""))).strip()
            if not node_id:
                continue
            node_ids.add(node_id)
            nodes.append(
                {
                    "id": node_id,
                    "name": str(runtime.get("name", node_id)),
                    "roles": dict(runtime.get("roles", {}))
                    if isinstance(runtime.get("roles"), dict)
                    else {},
                    "endpoints": list(runtime.get("endpoints", []))
                    if isinstance(runtime.get("endpoints"), list)
                    else [],
                    "online": bool(runtime.get("online", False)),
                    "last_seen": int(runtime.get("last_seen", 0) or 0),
                    "revoked": bool(runtime.get("revoked", False)),
                }
            )

    links: list[dict[str, Any]] = []
    for node_id in sorted(node_ids):
        telemetry = read_node_telemetry(control_dir, node_id)
        if not telemetry:
            continue
        try:
            observed = int(telemetry.get("last_seen", 0) or 0)
        except (TypeError, ValueError):
            observed = 0
        if observed <= 0 or timestamp - observed > ttl:
            continue
        raw_links = telemetry.get("links", [])
        if not isinstance(raw_links, list):
            continue
        for link in raw_links:
            if (
                isinstance(link, dict)
                and str(link.get("from", "")) == node_id
                and str(link.get("to", "")) in node_ids
            ):
                links.append(dict(link))

    routes = [
        {
            "cidr": str(record["cidr"]),
            "owner_node_id": route_owner(record),
            "updated_at": int(record.get("updated_at", 0) or 0),
        }
        for record in route_records(control_dir)
    ]
    return {
        "version": 1,
        "generated_at": timestamp,
        "nodes": nodes,
        "links": links,
        "routes": routes,
    }


def route_for_destination(
    topology: dict[str, Any],
    destination: str,
) -> dict[str, Any]:
    try:
        address = ipaddress.ip_address(destination)
    except ValueError as exc:
        raise TopologyError(f"invalid destination {destination!r}") from exc
    if address.version != 4:
        raise TopologyError("route explanation currently supports IPv4 only")

    matches: list[tuple[ipaddress.IPv4Network, dict[str, Any]]] = []
    for item in topology.get("routes", []):
        if not isinstance(item, dict):
            continue
        try:
            network = ipaddress.ip_network(str(item.get("cidr", "")), strict=False)
        except ValueError:
            continue
        if address in network:
            matches.append((network, item))
    if not matches:
        raise TopologyError(f"no BPC route owns {destination}")
    longest = max(network.prefixlen for network, _ in matches)
    winners = [(network, item) for network, item in matches if network.prefixlen == longest]
    owners = {str(item.get("owner_node_id", "")) for _, item in winners}
    if len(owners) != 1:
        raise TopologyError(
            f"ambiguous route ownership for {destination}: {', '.join(sorted(owners))}"
        )
    network, item = sorted(winners, key=lambda value: str(value[0]))[0]
    return {"cidr": str(network), "owner_node_id": next(iter(owners)), **item}


def _public_node_ids(topology: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for node in topology.get("nodes", []):
        if not isinstance(node, dict):
            continue
        roles = node.get("roles", {})
        if not isinstance(roles, dict):
            continue
        if bool(roles.get("gateway")) and bool(roles.get("relay")):
            result.add(str(node.get("id", "")))
    return result


def _candidate_from_links(
    hops: list[str],
    links: list[dict[str, Any]],
    *,
    owner: str,
    cidr: str,
) -> dict[str, Any]:
    rtt = sum(float(link.get("rtt_ms", 0) or 0) for link in links)
    cost = sum(float(link.get("cost", 0) or 0) for link in links)
    survival = 1.0
    health = "healthy"
    last_seen = 0
    for link in links:
        loss = _bounded_float(
            link.get("loss_percent", 0),
            default=0,
            minimum=0,
            maximum=100,
        )
        survival *= 1.0 - loss / 100.0
        if str(link.get("health", "unknown")) != "healthy":
            health = "degraded"
        observed = int(link.get("last_seen", 0) or 0)
        last_seen = observed if last_seen == 0 else min(last_seen, observed)
    loss_percent = (1.0 - survival) * 100.0
    path_id = hashlib.sha256(
        f"{owner}\0{cidr}\0{'|'.join(hops)}".encode("utf-8")
    ).hexdigest()[:24]
    return {
        "id": path_id,
        "owner_node_id": owner,
        "cidr": cidr,
        "hops": list(hops),
        "health": health,
        "rtt_ms": round(rtt, 3),
        "loss_percent": round(loss_percent, 3),
        "cost": round(cost, 3),
        "score": round(cost + rtt + loss_percent * 10.0, 3),
        "last_seen": last_seen,
    }


def validate_path(
    topology: dict[str, Any],
    candidate: dict[str, Any],
    *,
    max_intermediate_public_nodes: int = MAX_INTERMEDIATE_PUBLIC_NODES,
) -> None:
    hops = [str(item) for item in candidate.get("hops", [])]
    if len(hops) < 2 or len(hops) > MAX_PATH_HOPS:
        raise TopologyError("path hop count is outside the supported bound")
    if len(set(hops)) != len(hops):
        raise TopologyError("path contains a routing loop")
    owner = str(candidate.get("owner_node_id", ""))
    if not owner or hops[-1] != owner:
        raise TopologyError("path does not terminate at the route owner")
    public = _public_node_ids(topology)
    intermediates = sum(1 for hop in hops[1:-1] if hop in public)
    if intermediates > max_intermediate_public_nodes:
        raise TopologyError("path exceeds the intermediate Public Node limit")


def candidate_paths(
    topology: dict[str, Any],
    source_node_id: str,
    owner_node_id: str,
    *,
    cidr: str,
    max_intermediate_public_nodes: int = MAX_INTERMEDIATE_PUBLIC_NODES,
) -> list[dict[str, Any]]:
    source = str(source_node_id).strip()
    owner = str(owner_node_id).strip()
    if not source or not owner:
        raise TopologyError("source and owner are required")
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for link in topology.get("links", []):
        if not isinstance(link, dict):
            continue
        if str(link.get("health", "unknown")) == "failed":
            continue
        start = str(link.get("from", "")).strip()
        target = str(link.get("to", "")).strip()
        if not start or not target or start == target:
            continue
        adjacency.setdefault(start, []).append(link)

    result: list[dict[str, Any]] = []
    public = _public_node_ids(topology)

    def walk(node: str, hops: list[str], path_links: list[dict[str, Any]]) -> None:
        if len(hops) > MAX_PATH_HOPS:
            return
        if node == owner:
            candidate = _candidate_from_links(
                hops, path_links, owner=owner, cidr=cidr
            )
            validate_path(
                topology,
                candidate,
                max_intermediate_public_nodes=max_intermediate_public_nodes,
            )
            result.append(candidate)
            return
        for link in adjacency.get(node, []):
            target = str(link.get("to", ""))
            if target in hops:
                continue
            new_hops = [*hops, target]
            intermediate_count = sum(
                1 for hop in new_hops[1:-1] if hop in public
            )
            if intermediate_count > max_intermediate_public_nodes:
                continue
            walk(target, new_hops, [*path_links, link])

    walk(source, [source], [])
    result.sort(key=lambda item: (item["score"], item["rtt_ms"], item["id"]))
    return result


def choose_best_path(
    candidates: Iterable[dict[str, Any]],
    *,
    current_path_id: str | None = None,
    minimum_improvement: float = 10.0,
) -> dict[str, Any] | None:
    healthy = [
        dict(item)
        for item in candidates
        if str(item.get("health", "")) in {"healthy", "degraded"}
    ]
    if not healthy:
        return None
    healthy.sort(key=lambda item: (float(item.get("score", 0)), str(item.get("id", ""))))
    best = healthy[0]
    if current_path_id:
        current = next(
            (item for item in healthy if str(item.get("id", "")) == current_path_id),
            None,
        )
        if current is not None:
            improvement = float(current.get("score", 0)) - float(best.get("score", 0))
            if improvement < minimum_improvement:
                return current
    return best


def _source_node(control_dir: Path, explicit: str | None) -> str:
    if explicit:
        return explicit
    enrollment = Path(control_dir).resolve().parent / "enrollment.json"
    if enrollment.is_file():
        try:
            value = _read_json(enrollment)
            node_id = str(value.get("node_id", "")).strip()
            if node_id:
                return node_id
        except (OSError, ValueError, json.JSONDecodeError, TopologyError):
            pass
    raise TopologyError("source Node is unknown; pass --from-node")


def _all_candidates(
    topology: dict[str, Any],
    source: str,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for route in topology.get("routes", []):
        if not isinstance(route, dict):
            continue
        owner = str(route.get("owner_node_id", ""))
        cidr = str(route.get("cidr", ""))
        key = (owner, cidr)
        if not owner or not cidr or key in seen:
            continue
        seen.add(key)
        result.extend(candidate_paths(topology, source, owner, cidr=cidr))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect BPC topology and routed paths")
    parser.add_argument("--control-dir", type=Path, default=DEFAULT_CONTROL_DIR)
    sub = parser.add_subparsers(dest="command", required=True)

    path = sub.add_parser("path")
    path_sub = path.add_subparsers(dest="path_command", required=True)
    path_list = path_sub.add_parser("list")
    path_list.add_argument("--from-node")
    path_show = path_sub.add_parser("show")
    path_show.add_argument("path_id")
    path_show.add_argument("--from-node")

    route = sub.add_parser("route")
    route_sub = route.add_subparsers(dest="route_command", required=True)
    explain = route_sub.add_parser("explain")
    explain.add_argument("destination")
    explain.add_argument("--from-node")

    args = parser.parse_args()
    graph = topology_snapshot(args.control_dir)
    source = _source_node(args.control_dir, getattr(args, "from_node", None))

    if args.command == "path" and args.path_command == "list":
        candidates = _all_candidates(graph, source)
        if not candidates:
            print("No healthy routed paths.")
            return 1
        for item in candidates:
            print(
                f"{item['id']}  {' -> '.join(item['hops'])}  "
                f"health={item['health']} rtt={item['rtt_ms']:.1f}ms "
                f"loss={item['loss_percent']:.1f}% cost={item['cost']:.1f}"
            )
        return 0

    if args.command == "path" and args.path_command == "show":
        candidates = _all_candidates(graph, source)
        item = next((value for value in candidates if value["id"] == args.path_id), None)
        if item is None:
            raise TopologyError(f"path not found: {args.path_id}")
        print(json.dumps(item, indent=2, sort_keys=True))
        return 0

    if args.command == "route" and args.route_command == "explain":
        route_record = route_for_destination(graph, args.destination)
        candidates = candidate_paths(
            graph,
            source,
            str(route_record["owner_node_id"]),
            cidr=str(route_record["cidr"]),
        )
        selected = choose_best_path(candidates)
        print(f"Destination: {args.destination}")
        print(f"Route: {route_record['cidr']}")
        print(f"Owner: {route_record['owner_node_id']}")
        if selected is None:
            print("Selected: none (no healthy end-to-end path)")
            return 1
        print("Selected: " + " -> ".join(selected["hops"]))
        alternatives = [item for item in candidates if item["id"] != selected["id"]]
        if alternatives:
            print("Alternatives:")
            for item in alternatives:
                print("  " + " -> ".join(item["hops"]))
        return 0

    raise TopologyError("unsupported topology command")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TopologyError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
