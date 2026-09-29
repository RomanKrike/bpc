from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "deploy"))

import bpc_node_enrollment as enrollment  # noqa: E402
import bpc_topology as topology  # noqa: E402


def _join(
    control: Path,
    *,
    name: str,
    roles: list[str],
    now: int,
) -> dict[str, object]:
    token = enrollment.create_join_token(
        control,
        controller_url="https://ru-01.example:8444",
        roles=roles,
        name=name,
        now=now,
    )
    return enrollment.enroll_node(
        control,
        token=token,
        public_key=base64.b64encode(os.urandom(32)).decode(),
        presented_name=name,
        now=now + 1,
    )


def test_heartbeat_runtime_state_is_ephemeral_not_canonical(tmp_path: Path) -> None:
    control = tmp_path / "control"
    joined = _join(
        control,
        name="ru-01",
        roles=["gateway", "relay"],
        now=100,
    )
    enrollment.node_heartbeat(
        control,
        credential=str(joined["credential"]),
        payload={
            "status": "online",
            "version": "0.21.0",
            "protocol_version": 1,
            "state_schema_version": 1,
            "services": {"gateway": "active", "relay": "active"},
            "transport": {
                "udp_ports": [24444],
                "overlay_public_key": base64.b64encode(os.urandom(32)).decode(),
            },
        },
        now=120,
    )

    canonical = enrollment.read_json(
        control / "nodes" / f"{joined['node_id']}.json"
    )
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
        assert key not in canonical

    runtime = topology.read_node_telemetry(control, str(joined["node_id"]))
    assert runtime is not None
    assert runtime["last_seen"] == 120
    assert runtime["services"] == {"gateway": "active", "relay": "active"}

    merged = enrollment.list_nodes(control, now=121)[0]
    assert merged["online"] is True
    assert merged["last_seen"] == 120
    assert merged["services"] == {"gateway": "active", "relay": "active"}


def test_route_owner_cannot_claim_another_live_owner_prefix(tmp_path: Path) -> None:
    control = tmp_path / "control"
    first = _join(control, name="home-01", roles=["site_router"], now=1_000)
    second = _join(control, name="home-02", roles=["site_router"], now=1_100)

    enrollment.node_heartbeat(
        control,
        credential=str(first["credential"]),
        payload={
            "protocol_version": 1,
            "state_schema_version": 1,
            "advertised_routes": ["192.168.88.0/24"],
        },
        now=1_200,
    )

    with pytest.raises(enrollment.EnrollmentError, match="overlaps") as conflict:
        enrollment.node_heartbeat(
            control,
            credential=str(second["credential"]),
            payload={
                "protocol_version": 1,
                "state_schema_version": 1,
                "advertised_routes": ["192.168.88.128/25"],
            },
            now=1_201,
        )
    assert conflict.value.status == 409

    records = topology.route_records(control)
    assert len(records) == 1
    assert records[0]["owner_node_id"] == first["node_id"]


def test_revoked_owner_releases_route_for_reassignment(tmp_path: Path) -> None:
    control = tmp_path / "control"
    first = _join(control, name="home-01", roles=["site_router"], now=2_000)
    enrollment.node_heartbeat(
        control,
        credential=str(first["credential"]),
        payload={
            "protocol_version": 1,
            "state_schema_version": 1,
            "advertised_routes": ["192.168.88.0/24"],
        },
        now=2_010,
    )
    enrollment.leave_node(
        control,
        credential=str(first["credential"]),
        now=2_020,
    )
    assert topology.route_records(control) == []

    second = _join(control, name="home-02", roles=["site_router"], now=2_100)
    enrollment.node_heartbeat(
        control,
        credential=str(second["credential"]),
        payload={
            "protocol_version": 1,
            "state_schema_version": 1,
            "advertised_routes": ["192.168.88.0/24"],
        },
        now=2_110,
    )
    assert topology.route_records(control)[0]["owner_node_id"] == second["node_id"]


def test_topology_enumerates_direct_and_multi_hop_without_loops(tmp_path: Path) -> None:
    control = tmp_path / "control"
    ru01 = _join(control, name="ru-01", roles=["gateway", "relay"], now=3_000)
    ru02 = _join(control, name="ru-02", roles=["gateway", "relay"], now=3_100)
    ge01 = _join(control, name="ge-01", roles=["gateway", "relay"], now=3_200)
    home = _join(control, name="home-01", roles=["site_router"], now=3_300)

    home_id = str(home["node_id"])
    ru01_id = str(ru01["node_id"])
    ru02_id = str(ru02["node_id"])
    ge01_id = str(ge01["node_id"])

    enrollment.node_heartbeat(
        control,
        credential=str(home["credential"]),
        payload={
            "protocol_version": 1,
            "state_schema_version": 1,
            "advertised_routes": ["192.168.88.0/24"],
        },
        now=3_400,
    )

    topology.write_node_telemetry(
        control,
        ru02_id,
        payload={
            "status": "online",
            "links": [
                {"to": home_id, "health": "healthy", "rtt_ms": 55, "cost": 10},
                {"to": ru01_id, "health": "healthy", "rtt_ms": 5, "cost": 1},
            ],
        },
        compatibility="compatible",
        now=3_400,
    )
    topology.write_node_telemetry(
        control,
        ru01_id,
        payload={
            "status": "online",
            "links": [
                {"to": home_id, "health": "healthy", "rtt_ms": 50, "cost": 10},
                {"to": ru02_id, "health": "healthy", "rtt_ms": 5, "cost": 1},
                {"to": ge01_id, "health": "healthy", "rtt_ms": 20, "cost": 1},
            ],
        },
        compatibility="compatible",
        now=3_400,
    )
    topology.write_node_telemetry(
        control,
        ge01_id,
        payload={
            "status": "online",
            "links": [
                {"to": ru02_id, "health": "healthy", "rtt_ms": 20, "cost": 1}
            ],
        },
        compatibility="compatible",
        now=3_400,
    )

    graph = topology.topology_snapshot(control, now=3_401)
    paths = topology.candidate_paths(
        graph,
        ru02_id,
        home_id,
        cidr="192.168.88.0/24",
    )
    hop_sets = [item["hops"] for item in paths]
    assert [ru02_id, home_id] in hop_sets
    assert [ru02_id, ru01_id, home_id] in hop_sets
    assert any(len(hops) == 3 and hops[0] == ru02_id and hops[-1] == home_id for hops in hop_sets)
    assert all(len(hops) == len(set(hops)) for hops in hop_sets)
    assert all(len(hops) <= topology.MAX_PATH_HOPS for hops in hop_sets)

    selected = topology.choose_best_path(paths)
    assert selected is not None
    assert selected["hops"] == [ru02_id, home_id]


def test_failed_direct_link_falls_back_to_multi_hop(tmp_path: Path) -> None:
    control = tmp_path / "control"
    ru01 = _join(control, name="ru-01", roles=["gateway", "relay"], now=4_000)
    ru02 = _join(control, name="ru-02", roles=["gateway", "relay"], now=4_100)
    home = _join(control, name="home-01", roles=["site_router"], now=4_200)
    ru01_id, ru02_id, home_id = map(
        str, (ru01["node_id"], ru02["node_id"], home["node_id"])
    )
    enrollment.node_heartbeat(
        control,
        credential=str(home["credential"]),
        payload={
            "protocol_version": 1,
            "state_schema_version": 1,
            "advertised_routes": ["192.168.88.0/24"],
        },
        now=4_300,
    )
    topology.write_node_telemetry(
        control,
        ru02_id,
        payload={
            "links": [
                {"to": home_id, "health": "failed", "rtt_ms": 80},
                {"to": ru01_id, "health": "healthy", "rtt_ms": 5},
            ]
        },
        compatibility="compatible",
        now=4_300,
    )
    topology.write_node_telemetry(
        control,
        ru01_id,
        payload={
            "links": [
                {"to": home_id, "health": "healthy", "rtt_ms": 70},
                {"to": ru02_id, "health": "healthy", "rtt_ms": 5},
            ]
        },
        compatibility="compatible",
        now=4_300,
    )

    graph = topology.topology_snapshot(control, now=4_301)
    paths = topology.candidate_paths(
        graph, ru02_id, home_id, cidr="192.168.88.0/24"
    )
    assert [item["hops"] for item in paths] == [[ru02_id, ru01_id, home_id]]


def test_stale_telemetry_is_not_a_healthy_link(tmp_path: Path) -> None:
    control = tmp_path / "control"
    a = _join(control, name="ru-01", roles=["gateway", "relay"], now=5_000)
    b = _join(control, name="home-01", roles=["site_router"], now=5_100)
    topology.write_node_telemetry(
        control,
        str(a["node_id"]),
        payload={
            "links": [
                {"to": str(b["node_id"]), "health": "healthy", "rtt_ms": 10}
            ]
        },
        compatibility="compatible",
        now=5_200,
    )
    graph = topology.topology_snapshot(control, now=5_400, ttl=90)
    assert graph["links"] == []


def test_path_budget_counts_ingress_public_node() -> None:
    graph = {
        "nodes": [
            {"id": name, "roles": {"gateway": True, "relay": True}}
            for name in ("ru-02", "ru-01", "ge-01")
        ] + [{"id": "home-01", "roles": {"site_router": True}}],
        "links": [
            {"from": start, "to": end, "health": "healthy", "rtt_ms": 1}
            for start, end in (
                ("ru-02", "ru-01"), ("ru-01", "ge-01"), ("ge-01", "home-01")
            )
        ],
    }
    assert topology.candidate_paths(
        graph, "ru-02", "home-01", cidr="192.168.88.0/24"
    ) == []
