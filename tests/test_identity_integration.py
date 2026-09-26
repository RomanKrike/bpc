from __future__ import annotations

import base64
import http.client
import importlib.util
import json
import sys
import threading
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).parents[1]
DEPLOY = ROOT / "deploy"
sys.path.insert(0, str(DEPLOY))

import bpc_identity as identity  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "bpc_control_server_identity",
    DEPLOY / "bpc-control-server.py",
)
assert spec is not None and spec.loader is not None
control_server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control_server)


def request_json(
    port: int,
    method: str,
    path: str,
    payload: dict[str, object] | None = None,
    credential: str | None = None,
) -> tuple[int, dict[str, object]]:
    headers = {"Accept": "application/json"}
    body = None
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":"))
        headers["Content-Type"] = "application/json"
    if credential:
        headers["Authorization"] = f"Bearer {credential}"

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
    finally:
        connection.close()
    value = json.loads(raw) if raw else {}
    assert isinstance(value, dict)
    return response.status, value


def sign(private_key: Ed25519PrivateKey, message: bytes) -> str:
    return base64.b64encode(private_key.sign(message)).decode("ascii")


def write_control_config(root: Path, key_dir: Path) -> None:
    identity.atomic_json(
        root / "config.json",
        {
            "config_version": 4,
            "wgshim_server": "127.0.0.1:24444",
            "wgshim_servers": ["127.0.0.1:24444"],
            "wgshim_listen": "127.0.0.1:24081",
            "wgshim_target": "127.0.0.1:51821",
            "padding_min": 0,
            "padding_max": 31,
            "wireguard_interface": "bpcag0",
            "wireguard_subnet": "10.253.0.0/24",
            "wireguard_server_address": "10.253.0.1/24",
            "wireguard_server_public_key": base64.b64encode(b"s" * 32).decode("ascii"),
            "wireguard_mtu": 1280,
            "wireguard_keepalive": 25,
            "wireguard_allowed_ips": ["10.253.0.0/24"],
            "wgshim_key_dir": str(key_dir),
            "update_channel": "stable",
        },
    )


def test_user_device_http_flow_login_register_refresh_revoke(
    tmp_path: Path,
    monkeypatch,
) -> None:
    key_dir = tmp_path / "wgshim-keys"
    key_dir.mkdir()
    write_control_config(tmp_path, key_dir)
    user = identity.create_user(tmp_path, "roman", "correct horse battery staple")
    assert user["username"] == "roman"

    monkeypatch.setattr(control_server, "run_wg", lambda *args: None)
    monkeypatch.setattr(identity.subprocess, "run", lambda *args, **kwargs: None)

    server = control_server.ControlServer(
        ("127.0.0.1", 0),
        control_server.ControlHandler,
    )
    server.state_dir = str(tmp_path)
    server.enroll_lock = threading.Lock()
    server.node_join_lock = threading.Lock()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    device_private = Ed25519PrivateKey.generate()
    public_raw = device_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_key = base64.b64encode(public_raw).decode("ascii")
    wireguard_public_key = base64.b64encode(b"w" * 32).decode("ascii")

    try:
        port = int(server.server_address[1])

        status, login = request_json(
            port,
            "POST",
            "/v1/auth/login",
            {"username": "roman", "password": "correct horse battery staple"},
        )
        assert status == 200
        login_access = str(login["access_token"])

        bad_status, _ = request_json(
            port,
            "POST",
            "/v1/auth/login",
            {"username": "roman", "password": "wrong password"},
        )
        assert bad_status == 401

        proof = sign(
            device_private,
            identity.registration_message(
                login_access,
                public_key,
                wireguard_public_key,
            ),
        )
        status, registered = request_json(
            port,
            "POST",
            "/v1/devices/register",
            {
                "name": "pc004",
                "public_key": public_key,
                "wireguard_public_key": wireguard_public_key,
                "version": "0.16.0",
                "proof": proof,
            },
            credential=login_access,
        )
        assert status == 200
        device_id = str(registered["device_id"])
        access = str(registered["access_token"])
        refresh = str(registered["refresh_token"])

        stored_device = identity.load_device(tmp_path, device_id)
        assert stored_device["user_id"] == user["id"]
        assert stored_device["public_key"] == public_key
        assert "private_key" not in stored_device
        assert (key_dir / f"{device_id}.key").is_file()

        status, config = request_json(
            port,
            "GET",
            "/v1/config",
            credential=access,
        )
        assert status == 200
        assert config["config_version"] == 4

        refresh_proof = sign(device_private, identity.refresh_message(refresh))
        status, rotated = request_json(
            port,
            "POST",
            "/v1/auth/refresh",
            {"refresh_token": refresh, "proof": refresh_proof},
        )
        assert status == 200
        rotated_access = str(rotated["access_token"])
        rotated_refresh = str(rotated["refresh_token"])
        assert rotated_access != access
        assert rotated_refresh != refresh

        replay_status, _ = request_json(
            port,
            "POST",
            "/v1/auth/refresh",
            {"refresh_token": refresh, "proof": refresh_proof},
        )
        assert replay_status == 401

        # Re-authenticate after the replay test. The registered device identity is
        # reused only after a fresh password login plus private-key proof.
        status, login2 = request_json(
            port,
            "POST",
            "/v1/auth/login",
            {"username": "roman", "password": "correct horse battery staple"},
        )
        assert status == 200
        login_access2 = str(login2["access_token"])
        proof2 = sign(
            device_private,
            identity.registration_message(
                login_access2,
                public_key,
                wireguard_public_key,
            ),
        )
        status, session2 = request_json(
            port,
            "POST",
            "/v1/devices/register",
            {
                "name": "pc004",
                "public_key": public_key,
                "wireguard_public_key": wireguard_public_key,
                "version": "0.16.0",
                "proof": proof2,
            },
            credential=login_access2,
        )
        assert status == 200
        final_access = str(session2["access_token"])
        final_refresh = str(session2["refresh_token"])

        status, devices = request_json(
            port,
            "GET",
            "/v1/devices",
            credential=final_access,
        )
        assert status == 200
        assert len(devices["devices"]) == 1

        status, revoked = request_json(
            port,
            "POST",
            "/v1/devices/revoke",
            {"device_id": device_id},
            credential=final_access,
        )
        assert status == 200
        assert revoked["ok"] is True
        assert not (key_dir / f"{device_id}.key").exists()

        denied_status, _ = request_json(
            port,
            "GET",
            "/v1/config",
            credential=final_access,
        )
        assert denied_status in {401, 403}

        final_refresh_proof = sign(
            device_private,
            identity.refresh_message(final_refresh),
        )
        denied_refresh_status, _ = request_json(
            port,
            "POST",
            "/v1/auth/refresh",
            {"refresh_token": final_refresh, "proof": final_refresh_proof},
        )
        assert denied_refresh_status in {401, 403}

        # A revoked device key cannot be silently registered again by logging in.
        status, login3 = request_json(
            port,
            "POST",
            "/v1/auth/login",
            {"username": "roman", "password": "correct horse battery staple"},
        )
        assert status == 200
        login_access3 = str(login3["access_token"])
        proof3 = sign(
            device_private,
            identity.registration_message(
                login_access3,
                public_key,
                wireguard_public_key,
            ),
        )
        denied_register_status, _ = request_json(
            port,
            "POST",
            "/v1/devices/register",
            {
                "name": "pc004",
                "public_key": public_key,
                "wireguard_public_key": wireguard_public_key,
                "version": "0.16.0",
                "proof": proof3,
            },
            credential=login_access3,
        )
        assert denied_register_status == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
