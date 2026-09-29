#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import secrets
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

DEFAULT_CONTROL_DIR = Path("/etc/bpc-connect/control")
DEFAULT_TELEMETRY_TTL = 90
ROUTED_MESH_PORT = 24446
MAX_INTERMEDIATE_PUBLIC_NODES = 2
# Device ingress is outside the Node frame: two Public Nodes plus owner.
MAX_PATH_HOPS = 3
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


def _canonical_nodes(control_dir: Path) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    directory = Path(control_dir) / "nodes"
    if not directory.is_dir():
        return nodes
    for path in sorted(directory.glob("*.json")):
        try:
            node = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError, TopologyError):
            continue
        node_id = str(node.get("node_id", node.get("id", ""))).strip()
        if not node_id or bool(node.get("revoked", False)):
            continue
        nodes.append(node)
    return nodes


def _is_public_node(node: dict[str, Any]) -> bool:
    roles = node.get("roles", {})
    return (
        isinstance(roles, dict)
        and bool(roles.get("gateway"))
        and bool(roles.get("relay"))
    )


def _is_site_router(node: dict[str, Any]) -> bool:
    roles = node.get("roles", {})
    return isinstance(roles, dict) and bool(roles.get("site_router"))


def _link_pair(a: str, b: str) -> tuple[str, str]:
    left, right = sorted((str(a).strip(), str(b).strip()))
    if not left or not right or left == right:
        raise TopologyError("canonical topology link requires two distinct Nodes")
    return left, right


def topology_link_id(a: str, b: str) -> str:
    left, right = _link_pair(a, b)
    return hashlib.sha256(
        f"{left}\0{right}".encode()
    ).hexdigest()[:32]


def topology_link_path(control_dir: Path, a: str, b: str) -> Path:
    return (
        Path(control_dir)
        / "topology"
        / "links"
        / f"{topology_link_id(a, b)}.json"
    )


def topology_link_records(control_dir: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    directory = Path(control_dir) / "topology" / "links"
    if not directory.is_dir():
        return result
    for path in sorted(directory.glob("*.json")):
        try:
            record = _read_json(path)
            left, right = _link_pair(
                str(record.get("a_node_id", "")),
                str(record.get("b_node_id", "")),
            )
            psk = base64.b64decode(
                str(record.get("psk", "")), validate=True
            )
        except (
            OSError,
            ValueError,
            json.JSONDecodeError,
            TopologyError,
            base64.binascii.Error,
        ):
            continue
        if len(psk) != 32:
            continue
        item = dict(record)
        item["a_node_id"] = left
        item["b_node_id"] = right
        item["id"] = topology_link_id(left, right)
        result.append(item)
    return result


def desired_topology_pairs(control_dir: Path) -> set[tuple[str, str]]:
    nodes = _canonical_nodes(control_dir)
    public = [
        str(node.get("node_id", node.get("id", "")))
        for node in nodes
        if _is_public_node(node)
    ]
    sites = [
        str(node.get("node_id", node.get("id", "")))
        for node in nodes
        if _is_site_router(node)
    ]
    pairs: set[tuple[str, str]] = set()
    for index, left in enumerate(public):
        for right in public[index + 1 :]:
            pairs.add(_link_pair(left, right))
    for site in sites:
        for public_node in public:
            if site != public_node:
                pairs.add(_link_pair(site, public_node))
    return pairs


def _new_topology_link(a: str, b: str, now: int) -> dict[str, Any]:
    left, right = _link_pair(a, b)
    return {
        "version": 1,
        "id": topology_link_id(left, right),
        "a_node_id": left,
        "b_node_id": right,
        "psk": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "port": ROUTED_MESH_PORT,
        "cost": 10,
        "created_at": int(now),
    }


def ensure_topology_links(
    control_dir: Path,
    *,
    now: int | None = None,
) -> list[dict[str, Any]]:
    """Reconcile stable link credentials only when topology membership changes."""
    import bpc_control_state

    timestamp = int(time.time()) if now is None else int(now)
    desired = desired_topology_pairs(control_dir)
    existing_records = topology_link_records(control_dir)
    existing = {
        _link_pair(
            str(record["a_node_id"]),
            str(record["b_node_id"]),
        ): record
        for record in existing_records
    }

    for pair in sorted(desired):
        if pair in existing:
            continue
        record = _new_topology_link(*pair, timestamp)
        target = topology_link_path(control_dir, *pair)
        raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        if bpc_control_state.cluster_enabled(control_dir):
            try:
                bpc_control_state.mutation(
                    control_dir,
                    "CreateTopologyLink",
                    [
                        {
                            "op": "put",
                            "path": target,
                            "data": raw,
                            "if_absent": True,
                        }
                    ],
                    issued_at=timestamp,
                )
            except bpc_control_state.ControlStateError as exc:
                # Another concurrent heartbeat may have committed exactly this
                # deterministic pair. Only that conflict is benign.
                if exc.status != 409:
                    raise
        else:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not target.exists():
                _atomic_local_json(target, record)
        try:
            committed = _read_json(target)
        except (OSError, ValueError, json.JSONDecodeError, TopologyError):
            continue
        existing[pair] = committed

    obsolete = [
        record
        for pair, record in existing.items()
        if pair not in desired
    ]
    if obsolete:
        if bpc_control_state.cluster_enabled(control_dir):
            operations = [
                {
                    "op": "delete",
                    "path": topology_link_path(
                        control_dir,
                        str(record["a_node_id"]),
                        str(record["b_node_id"]),
                    ),
                }
                for record in obsolete
            ]
            bpc_control_state.mutation(
                control_dir,
                "DeleteObsoleteTopologyLinks",
                operations,
                issued_at=timestamp,
            )
        else:
            for record in obsolete:
                topology_link_path(
                    control_dir,
                    str(record["a_node_id"]),
                    str(record["b_node_id"]),
                ).unlink(missing_ok=True)

    return topology_link_records(control_dir)


def _public_endpoint(node: dict[str, Any], port: int) -> str:
    endpoints = node.get("endpoints", [])
    if not isinstance(endpoints, list):
        return ""
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        if not bool(endpoint.get("enabled", True)) or not bool(
            endpoint.get("public", True)
        ):
            continue
        host = str(endpoint.get("host", "")).strip()
        if host:
            return f"{host}:{port}"
    return ""


def routing_config_for_node(
    control_dir: Path,
    node_id: str,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    nodes = {
        str(node.get("node_id", node.get("id", ""))): node
        for node in _canonical_nodes(control_dir)
    }
    local = nodes.get(str(node_id))
    if local is None:
        raise TopologyError("routing config requested for an unknown Node")

    links: list[dict[str, Any]] = []
    for record in topology_link_records(control_dir):
        left = str(record["a_node_id"])
        right = str(record["b_node_id"])
        if str(node_id) not in {left, right}:
            continue
        peer_id = right if str(node_id) == left else left
        peer = nodes.get(peer_id)
        if peer is None:
            continue
        try:
            port = int(record.get("port", ROUTED_MESH_PORT))
        except (TypeError, ValueError):
            port = ROUTED_MESH_PORT
        links.append(
            {
                "id": str(record["id"]),
                "peer_node_id": peer_id,
                "peer_name": str(peer.get("name", peer_id)),
                "psk": str(record["psk"]),
                "peer_endpoint": _public_endpoint(peer, port)
                if _is_public_node(peer)
                else "",
                "peer_public": _is_public_node(peer),
                "peer_site_router": _is_site_router(peer),
                "port": port,
                "cost": float(record.get("cost", 10) or 10),
            }
        )

    graph = topology_snapshot(control_dir, now=timestamp)
    paths: list[dict[str, Any]] = []
    transit_paths: list[dict[str, Any]] = []
    public_ids = sorted(_public_node_ids(graph))
    seen_routes: set[tuple[str, str]] = set()
    for route in graph.get("routes", []):
        if not isinstance(route, dict):
            continue
        owner = str(route.get("owner_node_id", ""))
        cidr = str(route.get("cidr", ""))
        key = (owner, cidr)
        if not owner or not cidr or key in seen_routes:
            continue
        seen_routes.add(key)
        if _is_public_node(local):
            paths.extend(
                candidate_paths(
                    graph,
                    str(node_id),
                    owner,
                    cidr=cidr,
                )
            )
        for source in public_ids:
            for candidate in candidate_paths(
                graph,
                source,
                owner,
                cidr=cidr,
                include_failed=True,
            ):
                if str(node_id) in candidate["hops"]:
                    transit_paths.append(candidate)

    overlay_subnet = ""
    try:
        control_config = _read_json(Path(control_dir) / "config.json")
    except (OSError, ValueError, json.JSONDecodeError, TopologyError):
        control_config = {}
    try:
        subnet = ipaddress.ip_network(
            str(control_config.get("wireguard_subnet", "")),
            strict=False,
        )
    except ValueError:
        subnet = None
    if subnet is not None and subnet.version == 4:
        overlay_subnet = str(subnet)

    return {
        "version": 1,
        "listen_port": ROUTED_MESH_PORT,
        "overlay_subnet": overlay_subnet,
        "local_public": _is_public_node(local),
        "local_site_router": _is_site_router(local),
        "node_names": {
            item_id: str(node.get("name", item_id))
            for item_id, node in sorted(nodes.items())
        },
        "links": sorted(links, key=lambda item: item["peer_node_id"]),
        "paths": paths,
        "transit_paths": transit_paths,
        "routes": [
            {
                "cidr": str(record["cidr"]),
                "owner_node_id": route_owner(record),
            }
            for record in route_records(control_dir)
        ],
    }


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
                f"{node_id}\0{target}".encode()
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

    link_map: dict[tuple[str, str], dict[str, Any]] = {}
    for record in topology_link_records(control_dir):
        left = str(record.get("a_node_id", ""))
        right = str(record.get("b_node_id", ""))
        if left not in node_ids or right not in node_ids:
            continue
        try:
            cost = float(record.get("cost", 10) or 10)
        except (TypeError, ValueError):
            cost = 10.0
        for start, target in ((left, right), (right, left)):
            link_map[(start, target)] = {
                "id": str(record.get("id", topology_link_id(left, right))),
                "from": start,
                "to": target,
                "health": "unknown",
                "rtt_ms": 0.0,
                "loss_percent": 0.0,
                "cost": cost,
                "last_seen": 0,
            }

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
                link_map[(node_id, str(link["to"]))] = dict(link)
    links = [
        link_map[key]
        for key in sorted(link_map)
    ]

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
    uncertainty_penalty = 0.0
    last_seen = 0
    for link in links:
        loss = _bounded_float(
            link.get("loss_percent", 0),
            default=0,
            minimum=0,
            maximum=100,
        )
        survival *= 1.0 - loss / 100.0
        link_health = str(link.get("health", "unknown"))
        if link_health == "failed":
            health = "failed"
            uncertainty_penalty += 1_000_000.0
        elif link_health != "healthy" and health != "failed":
            health = "degraded"
            uncertainty_penalty += 1_000.0
        observed = int(link.get("last_seen", 0) or 0)
        last_seen = observed if last_seen == 0 else min(last_seen, observed)
    loss_percent = (1.0 - survival) * 100.0
    path_id = hashlib.sha256(
        f"{owner}\0{cidr}\0{'|'.join(hops)}".encode()
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
        "score": round(
            cost + rtt + loss_percent * 10.0 + uncertainty_penalty,
            3,
        ),
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
    include_failed: bool = False,
) -> list[dict[str, Any]]:
    source = str(source_node_id).strip()
    owner = str(owner_node_id).strip()
    if not source or not owner:
        raise TopologyError("source and owner are required")
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for link in topology.get("links", []):
        if not isinstance(link, dict):
            continue
        if (
            not include_failed
            and str(link.get("health", "unknown")) == "failed"
        ):
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
    healthy.sort(
        key=lambda item: (
            0 if str(item.get("health", "")) == "healthy" else 1,
            float(item.get("score", 0)),
            str(item.get("id", "")),
        )
    )
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


def _node_name_map(topology: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in topology.get("nodes", []):
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("id", "")).strip()
        if node_id:
            result[node_id] = str(node.get("name", node_id))
    return result


def _display_hops(hops: Iterable[str], names: dict[str, str]) -> str:
    return " -> ".join(names.get(str(hop), str(hop)) for hop in hops)


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
    names = _node_name_map(graph)
    source = _source_node(args.control_dir, getattr(args, "from_node", None))

    if args.command == "path" and args.path_command == "list":
        candidates = _all_candidates(graph, source)
        if not candidates:
            print("No healthy routed paths.")
            return 1
        for item in candidates:
            print(
                f"{item['id']}  {_display_hops(item['hops'], names)}  "
                f"health={item['health']} rtt={item['rtt_ms']:.1f}ms "
                f"loss={item['loss_percent']:.1f}% cost={item['cost']:.1f}"
            )
        return 0

    if args.command == "path" and args.path_command == "show":
        candidates = _all_candidates(graph, source)
        item = next((value for value in candidates if value["id"] == args.path_id), None)
        if item is None:
            raise TopologyError(f"path not found: {args.path_id}")
        display = dict(item)
        display["hop_names"] = [names.get(str(hop), str(hop)) for hop in item["hops"]]
        display["owner_name"] = names.get(
            str(item["owner_node_id"]), str(item["owner_node_id"])
        )
        print(json.dumps(display, indent=2, sort_keys=True))
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
        owner_id = str(route_record["owner_node_id"])
        print(f"Owner: {names.get(owner_id, owner_id)}")
        if selected is None:
            print("Selected: none (no healthy end-to-end path)")
            return 1
        print("Selected: " + _display_hops(selected["hops"], names))
        alternatives = [item for item in candidates if item["id"] != selected["id"]]
        if alternatives:
            print("Alternatives:")
            for item in alternatives:
                print("  " + _display_hops(item["hops"], names))
        return 0

    raise TopologyError("unsupported topology command")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TopologyError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
