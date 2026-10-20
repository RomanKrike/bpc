"""Existing-device recovery must never recreate identity or undo revocation."""
from __future__ import annotations

import base64
import http.client
import json
import sys
import threading
from pathlib import Path

import pytest

if sys.platform != "linux":
    pytest.skip("Controller imports require Linux", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).parents[1] / "deploy"))

import bpc_control_state  # noqa: E402
import bpc_identity as identity  # noqa: E402
from p2p_support import seed_p2p, write_json  # noqa: E402
from test_p2p_authority import FakeConsensus  # noqa: E402
from test_p2p_http import controller  # noqa: E402


@pytest.mark.parametrize("case,code", [
    ("ok", 200), ("missing-id", 400), ("different-id", 409),
    ("unknown-key", 409), ("wrong-owner", 409), ("revoked", 403),
    ("disabled-user", 403), ("wrong-wg", 409), ("bad-proof", 401),
])
def test_reauthenticate_existing_device(tmp_path, monkeypatch, case, code):
    context = seed_p2p(tmp_path)
    root = context["control"]
    consensus = FakeConsensus()
    monkeypatch.setattr(bpc_control_state, "strong_read", consensus.barrier)
    monkeypatch.setattr(bpc_control_state, "mutation", consensus.commit)
    device = context["devices"][0]
    token, _ = identity.issue_access_credential(root, user_id=context["owner"],
                                               device_id=None, scope="login")
    if case == "revoked":
        device["revoked"] = True
    if case == "wrong-owner":
        device["user_id"] = "e" * 32
    write_json(root / "devices" / f"{device['id']}.json", device)
    if case == "disabled-user":
        write_json(root / "identity/users" / f"{context['owner']}.json",
                   {"id": context["owner"], "enabled": False})
    body = {"device_id": device["id"], "name": "pc004", "public_key": device["public_key"],
            "wireguard_public_key": device["wireguard_public_key"], "version": "test"}
    signer = context["keys"][0]
    if case == "missing-id":
        body.pop("device_id")
    if case == "different-id":
        body["device_id"] = "d" * 32
    if case == "unknown-key":
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        signer = Ed25519PrivateKey.generate()
        body["public_key"] = base64.b64encode(signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    if case == "wrong-wg":
        body["wireguard_public_key"] = base64.b64encode(b"q" * 32).decode()
    body["proof"] = base64.b64encode(signer.sign(identity.registration_message(
        token, body["public_key"], body["wireguard_public_key"]))).decode()
    if case == "bad-proof":
        body["proof"] = base64.b64encode(b"x" * 64).decode()
    # Transport rendering is already covered elsewhere; this suite exercises the
    # real HTTP identity/credential logic and forbids identity metadata writes.
    monkeypatch.setattr(controller.ControlHandler, "_config_for_device", lambda *a: {})
    monkeypatch.setattr(controller.ControlHandler, "_wireguard_profile_for_device", lambda *a: {})
    monkeypatch.setattr(controller.ControlHandler, "_put_device",
                        lambda *a, **k: pytest.fail("recovery rewrote identity"))
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    server = controller.ControlServer(("127.0.0.1", 0), controller.ControlHandler)
    server.state_dir = str(root)
    server.enroll_lock = threading.Lock()
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("POST", "/v1/devices/reauthenticate", json.dumps(body), {
            "Content-Type": "application/json", "Authorization": "Bearer " + token})
        response = connection.getresponse()
        result = json.loads(response.read())
        assert response.status == code, result
        connection.close()
        after = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        if case != "ok":
            assert before == after
        else:
            assert result["device_id"] == device["id"] and result["refresh_token"]
            user, saved, _ = identity.authorize_access_credential(root, result["access_token"],
                                                                required_scope="device")
            assert user["id"] == context["owner"] and saved["id"] == device["id"]
            for path, data in before.items():
                if str(path).startswith(("devices/", "access/")):
                    assert after[path] == data
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
