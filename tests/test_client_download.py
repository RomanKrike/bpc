from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.util
import json
import struct
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location(
    "network_installer", ROOT / "scripts/build-windows-network-installer.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def test_network_installer_contains_public_settings_not_access_credentials(tmp_path):
    agent = bytearray(256)
    agent[:2] = b"MZ"
    struct.pack_into("<I", agent, 0x3C, 128)
    agent[128:132] = b"PE\0\0"
    struct.pack_into("<H", agent, 220, 2)
    public = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    output = tmp_path / "site"
    builder.build(bytes(agent), b"MZ-test-driver", public,
                  ["https://a.example:8444", "https://b.example:8444"], "misya-pc", output)
    exe = (output / "BPC-Connect-Setup.exe").read_bytes()
    raw = exe.split(b"\nBPC_AGENT_BOOTSTRAP_V3\n")[1].split(b"\n")[0]
    config = json.loads(base64.b64decode(raw))
    assert set(config) == {"version", "device", "control_url", "control_urls", "update_public_key"}
    assert config["version"] == 3 and len(config["control_urls"]) == 2
    assert base64.b64decode(config["update_public_key"]) == public
    assert exe.startswith(agent) and exe.endswith(b"BPC_AGENT_WINTUN_END\n")
    assert hashlib.sha256(exe).hexdigest() in (output / "SHA256SUMS").read_text()
    with pytest.raises(FileExistsError):
        builder.build(bytes(agent), b"MZ-test-driver", public, config["control_urls"],
                      "misya-pc", output)


@pytest.mark.parametrize("url", ["http://a.example", "https://user:password@a.example",
                                 "https://a.example/path", "https://a.example?token=x"])
def test_installer_rejects_secret_or_non_origin_urls(url):
    with pytest.raises(ValueError):
        builder.control_url(url)


def test_installer_rejects_wrong_source_hash(tmp_path):
    path = tmp_path / "agent.exe"
    path.write_bytes(b"unverified")
    with pytest.raises(ValueError, match="checksum mismatch"):
        builder.verified(path, "0" * 64)


def test_download_http_allowlist_and_no_secret_files(tmp_path):
    from test_node_join_api import control_server

    directory = tmp_path / "client-download"
    directory.mkdir()
    (directory / "index.html").write_text("download page")
    (directory / "BPC-Connect-Setup.exe").write_bytes(b"MZ-verified-installer")
    (directory / "password.txt").write_text("must not be served")
    server = control_server.ControlServer(("127.0.0.1", 0), control_server.ControlHandler)
    server.state_dir = str(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for path, expected in [("/bpc", 200), ("/bpc/", 200),
                               ("/bpc/BPC-Connect-Setup.exe", 200),
                               ("/bpc/password.txt", 404), ("/bpc/../config.json", 404),
                               ("/bpc/%2e%2e/config.json", 404)]:
            connection = http.client.HTTPConnection(*server.server_address, timeout=3)
            connection.request("GET", path)
            response = connection.getresponse()
            data = response.read()
            assert response.status == expected
            assert b"must not be served" not in data
            if path == "/bpc/":
                assert "frame-ancestors 'none'" in response.getheader("Content-Security-Policy")
            if path.endswith(".exe"):
                assert data == b"MZ-verified-installer"
                assert "attachment" in response.getheader("Content-Disposition")
            connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
