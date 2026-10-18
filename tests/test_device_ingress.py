from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "deploy"))
import bpc_node_enrollment as enrollment  # noqa: E402

from bpc_connect.compat import runtime  # noqa: E402


def test_real_host_service_commands_are_blocked():
    with pytest.raises(AssertionError, match="real host service"):
        subprocess.run(["systemctl", "--version"], check=True)


def record(root):
    value = {"node_id": "a" * 32, "roles": {"gateway": True, "relay": True},
             "config": {"role_config": {"gateway": {"mode": "routed"},
                                        "relay": {"mode": "routed"}}}}
    (root / "enrollment.json").write_text(json.dumps(value))
    return value


def test_ingress_opt_in_is_bound_to_node(tmp_path):
    record(tmp_path)
    assert not runtime.device_ingress_enabled(tmp_path)
    marker = tmp_path / "device-ingress.json"
    marker.write_text(json.dumps({"version": 1, "node_id": "b" * 32}))
    with pytest.raises(runtime.RuntimeCompatibilityError, match="local Node"):
        runtime.device_ingress_enabled(tmp_path)
    marker.write_text(json.dumps({"version": 1, "node_id": "a" * 32}))
    assert runtime.device_ingress_enabled(tmp_path)


def test_opted_in_mesh_starts_only_existing_ingress_units(tmp_path, monkeypatch):
    value = record(tmp_path)
    (tmp_path / "device-ingress.json").write_text(json.dumps({
        "version": 1, "node_id": value["node_id"],
    }))
    calls = []
    monkeypatch.setattr(runtime, "_run_checked", lambda args: calls.append(args))
    runtime.reconcile_transport_roles(tmp_path, value["roles"],
                                      value["config"]["role_config"], deploy_dir=tmp_path)
    assert calls == [["systemctl", "start", unit] for unit in (
        "wg-quick@bpcag0.service", "bpc-agent-dataplane-firewall.service",
        "bpc-agent-relay.service",
    )]


def test_role_withdrawal_stops_ingress_before_rejecting(tmp_path, monkeypatch):
    value = record(tmp_path)
    (tmp_path / "device-ingress.json").write_text(json.dumps({
        "version": 1, "node_id": value["node_id"],
    }))
    calls = []
    monkeypatch.setattr(runtime, "_run_checked", calls.append)
    with pytest.raises(runtime.RuntimeCompatibilityError, match="requires gateway"):
        runtime.reconcile_transport_roles(tmp_path, {"relay": True},
                                          value["config"]["role_config"], deploy_dir=tmp_path)
    assert calls == [["systemctl", "stop", "bpc-agent-relay.service"]]


@pytest.mark.parametrize("routed,enabled,expected", [
    (True, False, False), (True, True, True), (False, False, True),
])
def test_heartbeat_advertises_only_enabled_ingress(tmp_path, monkeypatch,
                                                 routed, enabled, expected):
    value = record(tmp_path)
    value.update(name="gw", credential="test", controller_url="https://gw.example:8444")
    value["roles"] = {"relay": True}  # Avoid unrelated Gateway snapshot installation.
    if not routed:
        value["config"] = {}
    identity = tmp_path / "identity"
    identity.mkdir()
    (identity / "node.pub").write_text("key")
    monkeypatch.setattr(enrollment, "gateway_has_device_ingress", lambda _: enabled)
    monkeypatch.setattr(enrollment, "local_services", lambda *a: {"relay": "active"})
    monkeypatch.setattr(enrollment, "local_transport_runtime", lambda *a: {"udp_ports": [24445]})
    monkeypatch.setattr(enrollment, "service_state", lambda _: "active")
    monkeypatch.setattr(enrollment, "fanout_node_telemetry", lambda *a, **k: None)
    captured = []
    monkeypatch.setattr(enrollment, "request_json", lambda url, path, payload, **kw:
                        captured.append(payload) or {"server_time": 10})
    monkeypatch.setattr(enrollment, "reconcile_routed_runtime", lambda *a: None)
    monkeypatch.setattr(enrollment, "apply_remote_node_config", lambda *a, **k: None)
    enrollment.send_heartbeat(tmp_path, value)
    assert bool(captured[0]["transport"]) is expected


@pytest.mark.parametrize("ingress_state,count", [("active", 2), ("inactive", 1)])
def test_discovery_counts_two_nodes_without_ip_dns_alias_gateway(tmp_path, ingress_state, count):
    from test_node_join_api import control_server

    overlay = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    config = {"wireguard_server_public_key": overlay, "wgshim_server": "192.0.2.1:24445"}
    nodes = tmp_path / "nodes"
    nodes.mkdir()
    for number in (1, 2):
        node = {"node_id": str(number), "name": f"gw-{number}",
                "last_seen": int(time.time()), "roles": {"gateway": True, "relay": True},
                "services": {"relay": "active", "device-ingress":
                             "active" if number == 1 else ingress_state},
                "endpoints": [{"host": f"gw-{number}.example"}],
                "transport": {"udp_ports": [24445, 34445], "overlay_public_key": overlay,
                              "public_host": f"192.0.2.{number}"}}
        (nodes / f"{number}.json").write_text(json.dumps(node))
    handler = object.__new__(control_server.ControlHandler)
    handler.server = SimpleNamespace(state_dir=str(tmp_path))
    paths = handler._discovered_transport_paths(config)
    assert len({path["node"] for path in paths}) == count
    assert paths[0]["node"] == "gw-1"
    assert {path["endpoint"] for path in paths} == {
        f"192.0.2.{n}:{port}" for n in range(1, count + 1) for port in (24445, 34445)
    }


@pytest.mark.parametrize("host", ["bad host", "a:22", "-bad", "x/y", "x\nInjected=1"])
def test_transport_rejects_invalid_public_host(host):
    assert "public_host" not in enrollment.normalize_transport_runtime({"public_host": host})


def test_startup_reconciles_opted_in_routed_gateway(tmp_path, monkeypatch):
    value = record(tmp_path)
    (tmp_path / "control").mkdir()
    (tmp_path / "control/config.json").write_text("{}")
    monkeypatch.setattr(enrollment, "gateway_has_device_ingress", lambda _: True)
    calls = []
    monkeypatch.setattr(enrollment, "reconcile_local_gateway_state", calls.append)
    assert enrollment.reconcile_startup_gateway_state(tmp_path, value["roles"])
    assert calls == [tmp_path]


@pytest.mark.parametrize("resume", [False, True])
def test_explicit_provisioning_keeps_cluster_config_and_enrollment(tmp_path, monkeypatch, resume):
    source = Path(__file__).parents[1] / "deploy/bpc-enable-device-ingress.py"
    spec = importlib.util.spec_from_file_location("device_ingress_enable", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    value = record(tmp_path)
    value["roles"]["controller"] = True
    node_bytes = json.dumps(value)
    (tmp_path / "enrollment.json").write_text(node_bytes)
    control = tmp_path / "control"
    control.mkdir()
    config = {"wireguard_server_private_key": "test-only", "wireguard_interface": "bpcag0",
              "wgshim_key_dir": str(tmp_path / "ru-node/agent/wgshim-keys"),
              "wireguard_subnet": "10.253.0.0/24", "wireguard_server_address": "10.253.0.1/24",
              "wireguard_mtu": 1360, "wireguard_keepalive": 25}
    original = json.dumps(config)
    (control / "config.json").write_text(original)
    monkeypatch.setattr(enrollment, "load_valid_security_snapshot", lambda _: {})
    monkeypatch.setattr(enrollment, "primary_compat_runtime", lambda _: False)
    monkeypatch.setattr(enrollment, "device_ingress_enabled", lambda _: not resume)
    if resume:
        (tmp_path / "device-ingress-provision.json").write_text(json.dumps({
            "version": 1, "node_id": value["node_id"], "host": "192.0.2.2",
        }))
    events = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **kwargs:
                        events.append(("installer", command, kwargs["env"])))
    monkeypatch.setattr(enrollment, "reconcile_local_gateway_state",
                        lambda _: events.append(("peers-and-access",)))
    module.enable(tmp_path, "192.0.2.2", systemd_dir=tmp_path / "units")
    assert [item[0] for item in events] == ["installer", "peers-and-access"]
    assert events[0][2]["BPC_SKIP_NODE_MODEL"] == "true"
    assert (control / "config.json").read_text() == original
    assert (tmp_path / "enrollment.json").read_text() == node_bytes
    assert json.loads((tmp_path / "device-ingress.json").read_text()) == {
        "version": 1, "node_id": value["node_id"],
    }
    guard = (tmp_path / "units/bpc-agent-relay.service.d/40-device-ingress.conf").read_text()
    assert "--check" in guard
    assert not (tmp_path / "device-ingress-provision.json").exists()


def test_relay_security_guard_uses_existing_read_only_lock(tmp_path, monkeypatch):
    source = Path(__file__).parents[1] / "deploy/bpc-enable-device-ingress.py"
    spec = importlib.util.spec_from_file_location("device_ingress_check", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    path = tmp_path / "security-runtime.lock"
    path.write_bytes(b"")
    original = Path.open
    modes = []

    def opened(self, mode="r", *args, **kwargs):
        if self == path:
            modes.append(mode)
            assert mode == "rb"
        return original(self, mode, *args, **kwargs)

    verified = []
    monkeypatch.setattr(Path, "open", opened)
    monkeypatch.setattr(module.snapshots, "_load_valid_security_snapshot", verified.append)
    module.check_snapshot(tmp_path)
    assert modes == ["rb"] and verified == [tmp_path]
