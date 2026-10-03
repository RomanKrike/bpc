from __future__ import annotations

import importlib.util
import json
import socketserver
import sys
import threading
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "mesh_traffic", Path(__file__).parents[1] / "scripts/acceptance-mesh-traffic.py",
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


@pytest.fixture
def echo():
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            while data := self.request.recv(65536):
                self.request.sendall(data)

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            sock.sendto(data, self.client_address)

    tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), TCP)
    tcp.daemon_threads = True
    udp = socketserver.ThreadingUDPServer(tcp.server_address, UDP)
    udp.daemon_threads = True
    for server in (tcp, udp):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield tcp.server_address
    for server in (tcp, udp):
        server.shutdown()
        server.server_close()


def test_two_tcp_sockets_and_udp_use_real_echo_without_reconnect(echo):
    traffic = probe.Traffic(*echo, duration=0.3, interval=0.02)
    for thread in traffic.start(include_icmp=False):
        thread.join(timeout=3)
        assert not thread.is_alive()
    results = traffic.report()
    for name in ("tcp_small", "tcp_stream", "udp"):
        assert results[name]["successes"] >= 2
        assert not results[name]["fatal_error"]
    for name in ("tcp_small", "tcp_stream"):
        assert results[name]["connection_count"] == 1
        assert results[name]["source_before"] == results[name]["source_after"]


def test_closed_tcp_is_reported_without_reconnecting():
    class Drop(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.recv(65536)

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Drop)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        traffic = probe.Traffic(*server.server_address, duration=0.2, interval=0.02)
        traffic.tcp("tcp_small", 64)
        result = traffic.report()["tcp_small"]
        assert result["connection_count"] == 1
        assert result["successes"] == 0
        assert "closed" in result["fatal_error"]
    finally:
        server.shutdown()
        server.server_close()


def test_final_outage_is_included_in_gap(monkeypatch):
    traffic = probe.Traffic("127.0.0.1", 19090, duration=2, interval=0.1)
    traffic.results["udp"]["samples"] = [{"elapsed_ms": 100, "ok": True}]
    monkeypatch.setattr(probe.time, "monotonic", lambda: traffic.started + 2)
    assert traffic.report()["udp"]["max_success_gap_ms"] == 1900


def test_agent_status_projection_excludes_credentials():
    view = probe.agent_view({
        "device_id": "device", "tunnel_address": "10.253.0.3/32",
        "routes": ["192.168.88.0/24"], "device_token": "secret",
        "transport": {"endpoint": "node:443", "private_key": "secret"},
    })
    assert "secret" not in str(view)
    assert view["device_id"] == "device"


def test_live_mode_requires_agent_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "probe", "--target", "127.0.0.1", "--scenario", "D", "--report", str(tmp_path / "out"),
    ])
    with pytest.raises(SystemExit) as error:
        probe.main()
    assert error.value.code == 2
    assert not (tmp_path / "out").exists()


def test_successful_collector_cannot_mark_live_acceptance_passed(echo, tmp_path, monkeypatch):
    report = tmp_path / "traffic.json"
    monkeypatch.setattr(sys, "argv", [
        "probe", "--target", echo[0], "--port", str(echo[1]), "--scenario", "A",
        "--duration", "1", "--interval-ms", "20", "--scope", "harness-validation",
        "--report", str(report),
    ])
    # This test validates report/CLI semantics, not operating-system ICMP.
    monkeypatch.setattr(probe.Traffic, "icmp", lambda traffic: traffic.sample("icmp", True))
    assert probe.main() == 0
    value = json.loads(report.read_text())
    assert value["measurement_complete"]
    assert value["scope"] == "harness-validation"
    assert value["acceptance_status"] == "unreviewed"
    assert value["live_mesh_passed"] is False
    assert value["traffic"]["tcp_small"]["connection_count"] == 1
