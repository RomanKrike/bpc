"""Actual public HTTP handler; existing server imports require Linux."""

from __future__ import annotations

import base64
import http.client
import importlib.util
import json
import sys
import threading
from pathlib import Path

import pytest

if sys.platform != "linux":
    pytest.skip("public Controller server requires Linux fcntl", allow_module_level=True)

from p2p_support import seed_p2p  # noqa: E402
from test_p2p_authority import FakeConsensus  # noqa: E402

DEPLOY = Path(__file__).parents[1] / "deploy"
sys.path.insert(0, str(DEPLOY))
import bpc_control_state  # noqa: E402
import bpc_p2p  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "bpc_control_server_p2p", DEPLOY / "bpc-control-server.py"
)
assert spec and spec.loader
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


def test_public_p2p_http_lifecycle(tmp_path, monkeypatch):
    context = seed_p2p(tmp_path)
    consensus = FakeConsensus()
    monkeypatch.setattr(bpc_control_state, "strong_read", consensus.barrier)
    monkeypatch.setattr(bpc_control_state, "mutation", consensus.commit)
    server = controller.ControlServer(("127.0.0.1", 0), controller.ControlHandler)
    server.state_dir = str(context["control"])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(method, path, token=None, **body):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            connection.request(method, path, json.dumps(body) if body else None, headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    try:
        assert request("GET", "/v1/p2p/info")[0] == 401
        status, info = request("GET", "/v1/p2p/info", context["tokens"][1])
        assert status == 200 and info["capabilities"] == [bpc_p2p.CAPABILITY]
        capability = {"capabilities": [bpc_p2p.CAPABILITY]}
        status, grant = request(
            "POST",
            "/v1/p2p/issue",
            context["tokens"][0],
            host_device_id=context["devices"][1]["id"],
            **capability,
        )
        assert status == 200 and grant["ticket"]
        message = bpc_p2p.consent_message(
            context["tokens"][1], info["device_id"], False, info["access_sha256"]
        )
        proof = base64.b64encode(context["keys"][1].sign(message)).decode()
        status, _ = request(
            "POST",
            "/v1/p2p/consent",
            context["tokens"][1],
            enabled=False,
            expected_sha256=info["access_sha256"],
            signature=proof,
            **capability,
        )
        assert status == 200
        status, policy = request(
            "POST", "/v1/p2p/sync", context["tokens"][0], tickets=[grant["ticket"]], **capability
        )
        assert status == 200
        envelope = json.loads(base64.b64decode(policy["checkpoint"]))
        assert json.loads(base64.b64decode(envelope["payload"]))["allowed"] == []
        assert (
            request(
                "POST",
                "/v1/p2p/issue",
                context["tokens"][0],
                host_device_id=context["devices"][1]["id"],
                user_id=context["owner"],
                **capability,
            )[0]
            == 400
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
