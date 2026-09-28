from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "deploy"))
import bpc_node_enrollment as enrollment  # noqa: E402


@pytest.mark.parametrize("failure", ["trust", "runtime", "ready", "marker", "public"])
def test_controller_provisioning_resumes_each_failed_phase(tmp_path, monkeypatch, failure):
    calls = []
    failed = False

    def action(phase):
        nonlocal failed
        calls.append(phase)
        if phase == failure and not failed:
            failed = True
            raise enrollment.EnrollmentError("interrupted")

    def install(state, payload):
        action("trust")

    def run(command, **kwargs):
        if command[0] == "systemctl":
            action("start")
        else:
            action("runtime" if "cluster.sh" in command[0] else "public")
            assert kwargs["env"]["BPC_STATE_DIR"] == str(tmp_path)
        return SimpleNamespace(returncode=0)

    def ready(*args, **kwargs):
        action("ready")
        assert args[1] == "/v1/nodes/controller-ready"
        return {"ok": True, "state": "voter"}

    monkeypatch.setattr(enrollment, "install_controller_enrollment", install)
    monkeypatch.setattr(enrollment, "activate_controller_marker", lambda *a, **k: action("marker"))
    monkeypatch.setattr(enrollment.subprocess, "run", run)
    monkeypatch.setattr(enrollment, "request_json", ready)
    record = {
        "roles": {"controller": True},
        "node_id": "a" * 32,
        "credential": "secret",
        "controller_url": "https://ru-01.blinpi.ru:8444",
        "controllers": ["https://ru-01.blinpi.ru:8444"],
        "controller_provision": {
            "payload": {
                "advertise_host": "ru-02.blinpi.ru",
                "cluster_ca_key": "private-ca-key",
            }
        },
    }
    enrollment.write_local_enrollment(tmp_path, record)
    with pytest.raises(enrollment.EnrollmentError, match="interrupted"):
        enrollment.resume_controller_provisioning(tmp_path, record)
    restored = enrollment.enrolled_state(tmp_path)
    enrollment.resume_controller_provisioning(tmp_path, restored)
    done = enrollment.enrolled_state(tmp_path)
    assert done["controller_provision"]["complete"]
    assert "private-ca-key" not in (tmp_path / "enrollment.json").read_text()
    assert (tmp_path / "enrollment.json").stat().st_mode & 0o777 == 0o600
    if failure != "trust":
        assert calls.count("trust") == 1
    if failure in {"marker", "public"}:
        assert calls.count("ready") == 1
    before = calls.copy()
    enrollment.resume_controller_provisioning(tmp_path, done)
    assert calls == [*before, "start"]


def test_failed_promotion_does_not_start_public_api(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(enrollment, "install_controller_enrollment", lambda *a: None)
    monkeypatch.setattr(
        enrollment.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command) or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(enrollment, "request_json", lambda *a, **k: {"state": "nonvoter"})
    record = {
        "roles": {"controller": True},
        "node_id": "a" * 32,
        "credential": "secret",
        "controller_url": "https://ru-01.blinpi.ru:8444",
        "controller_provision": {"payload": {"advertise_host": "ru-02.blinpi.ru"}},
    }
    with pytest.raises(enrollment.EnrollmentError, match="voter promotion"):
        enrollment.resume_controller_provisioning(tmp_path, record)
    assert len(calls) == 1
    assert "bpc-enable-cluster.sh" in calls[0][0]


@pytest.mark.parametrize("presented,expected", [("", 200), ("ru-02.blinpi.ru", 200),
                                               ("wrong.example", 403)])
def test_public_join_uses_invitation_hostname(tmp_path, monkeypatch, presented, expected):
    import threading

    from test_node_join_api import control_server, post_json

    monkeypatch.setattr(control_server, "join_token_metadata", lambda *a: {
        "roles": ["controller", "gateway", "relay"],
        "endpoints": [{"host": "ru-02.blinpi.ru", "public": True, "enabled": True}],
    })
    issued = []

    def issue(*a, **kwargs):
        issued.append(kwargs["advertise_host"])
        return {"advertise_host": kwargs["advertise_host"]}, {}

    monkeypatch.setattr(control_server, "build_controller_enrollment", issue)
    monkeypatch.setattr(control_server, "enroll_node", lambda *a, **k: {"config": {}})
    monkeypatch.setattr(control_server, "controller_public_urls", lambda *a: [])
    server = control_server.ControlServer(("127.0.0.1", 0), control_server.ControlHandler)
    server.state_dir = str(tmp_path)
    server.node_join_lock = threading.Lock()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, response = post_json(server.server_address[1], "/v1/nodes/join", {
            "token": "test", "controller_advertise_host": presented,
            "protocol_version": 1, "state_schema_version": 1,
        })
        assert status == expected
        assert issued == (["ru-02.blinpi.ru"] if expected == 200 else [])
        if expected == 200:
            assert response["controller"]["advertise_host"] == "ru-02.blinpi.ru"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("state", ["inactive", "failed", "pending:tls-bootstrap", None])
def test_join_does_not_claim_ready_for_unhealthy_capability(state):
    with pytest.raises(enrollment.EnrollmentError, match="not ready"):
        enrollment.require_role_health({"controller": True}, {"controller": state})



def test_controller_discovers_paths_only_from_live_matching_public_nodes(tmp_path):
    from test_node_join_api import control_server

    overlay = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    config = {
        "wireguard_server_public_key": overlay,
        "wgshim_server": "ru-01.example:24444",
    }
    (tmp_path / "config.json").write_text(json.dumps(config), encoding="utf-8")
    nodes = tmp_path / "nodes"
    nodes.mkdir()
    now = int(time.time())

    def node(name, host, ports, key=overlay, *, active=True):
        (nodes / f"{name}.json").write_text(
            json.dumps(
                {
                    "node_id": name,
                    "name": name,
                    "last_seen": now,
                    "roles": {"gateway": True, "relay": True},
                    "services": {"relay": "active" if active else "inactive"},
                    "endpoints": [{"host": host, "public": True, "enabled": True}],
                    "transport": {
                        "udp_ports": ports,
                        "overlay_public_key": key,
                    },
                }
            ),
            encoding="utf-8",
        )

    node("ru-01", "ru-01.example", [31001, 31002])
    node("ru-02", "ru-02.example", [32001, 32002])
    node(
        "wrong-key",
        "wrong.example",
        [33001],
        key="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
    )
    node("inactive", "inactive.example", [34001], active=False)

    handler = object.__new__(control_server.ControlHandler)
    handler.server = SimpleNamespace(state_dir=str(tmp_path))
    paths = handler._discovered_transport_paths(config)

    assert paths[:5] == [
        {
            "node": "ru-01",
            "endpoint": "ru-01.example:24444",
            "peer_public_key": overlay,
        },
        {
            "node": "ru-01",
            "endpoint": "ru-01.example:31001",
            "peer_public_key": overlay,
        },
        {
            "node": "ru-02",
            "endpoint": "ru-02.example:32001",
            "peer_public_key": overlay,
        },
        {
            "node": "ru-01",
            "endpoint": "ru-01.example:31002",
            "peer_public_key": overlay,
        },
        {
            "node": "ru-02",
            "endpoint": "ru-02.example:32002",
            "peer_public_key": overlay,
        },
    ]
    encoded = json.dumps(paths)
    assert "wrong.example" not in encoded
    assert "inactive.example" not in encoded
