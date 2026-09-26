from __future__ import annotations

import base64
import http.client
import importlib.util
import json
import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).parents[1]
DEPLOY = ROOT / "deploy"
sys.path.insert(0, str(DEPLOY))

import bpc_node_enrollment as enrollment  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "bpc_control_server_stage2",
    DEPLOY / "bpc-control-server.py",
)
assert spec is not None and spec.loader is not None
control_server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control_server)


def post_json(
    port: int,
    path: str,
    payload: dict[str, object],
    credential: str | None = None,
) -> tuple[int, dict[str, object]]:
    headers = {"Content-Type": "application/json"}
    if credential:
        headers["Authorization"] = f"Bearer {credential}"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST",
            path,
            body=json.dumps(payload, separators=(",", ":")),
            headers=headers,
        )
        response = connection.getresponse()
        raw = response.read()
    finally:
        connection.close()
    value = json.loads(raw) if raw else {}
    assert isinstance(value, dict)
    return response.status, value


def test_node_join_api_end_to_end(tmp_path: Path) -> None:
    token = enrollment.create_join_token(
        tmp_path,
        controller_url="https://controller.example:8444",
        roles=["gateway", "relay"],
        name="ge-02",
        expires_in=900,
    )
    public_key = base64.b64encode(os.urandom(44)).decode("ascii")

    server = control_server.ControlServer(
        ("127.0.0.1", 0),
        control_server.ControlHandler,
    )
    server.state_dir = str(tmp_path)
    server.enroll_lock = threading.Lock()
    server.node_join_lock = threading.Lock()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = int(server.server_address[1])
        status, joined = post_json(
            port,
            "/v1/nodes/join",
            {"token": token, "public_key": public_key, "name": "fresh-host"},
        )
        assert status == 200
        assert joined["name"] == "ge-02"
        assert joined["roles"] == {"gateway": True, "relay": True}

        credential = str(joined["credential"])
        status, heartbeat = post_json(
            port,
            "/v1/nodes/heartbeat",
            {
                "status": "online",
                "version": "0.15.0",
                "services": {"gateway": "active", "relay": "active"},
            },
            credential=credential,
        )
        assert status == 200
        assert heartbeat["ok"] is True
        assert heartbeat["node_id"] == joined["node_id"]

        replay_status, replay = post_json(
            port,
            "/v1/nodes/join",
            {"token": token, "public_key": public_key, "name": "fresh-host"},
        )
        assert replay_status == 409
        assert "already been used" in str(replay["error"])

        leave_status, left = post_json(
            port,
            "/v1/nodes/leave",
            {"node_id": joined["node_id"]},
            credential=credential,
        )
        assert leave_status == 200
        assert left["ok"] is True

        denied_status, denied = post_json(
            port,
            "/v1/nodes/heartbeat",
            {"status": "online"},
            credential=credential,
        )
        assert denied_status == 401
        assert "invalid node credential" in str(denied["error"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
