#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import secrets
import ssl
import subprocess
import threading
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

MAX_JSON_BODY = 64 * 1024
MAX_UPDATE_SIZE = 128 * 1024 * 1024


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with tmp.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return value


def token_index(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(value, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def valid_wireguard_key(value: str) -> bool:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        return False
    return len(raw) == 32 and any(raw)


def run_wg(*args: str) -> None:
    completed = subprocess.run(
        ["wg", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(message or f"wg exited with {completed.returncode}")


def sync_wireguard_peers(state_dir: Path) -> None:
    config = read_json(state_dir / "config.json")
    interface = str(config["wireguard_interface"])
    completed = subprocess.run(
        ["wg", "show", interface, "peers"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or f"WireGuard interface {interface} unavailable"
        raise RuntimeError(message)
    for peer in completed.stdout.split():
        run_wg("set", interface, "peer", peer, "remove")
    for path in sorted((state_dir / "devices").glob("*.json")):
        try:
            device = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if bool(device.get("revoked", False)):
            continue
        public_key = str(device.get("wireguard_public_key", "")).strip()
        address = str(device.get("wireguard_address", "")).strip()
        if not valid_wireguard_key(public_key) or not address:
            continue
        run_wg("set", interface, "peer", public_key, "allowed-ips", address)


class ControlHandler(BaseHTTPRequestHandler):
    server_version = "BPCControl/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/v1/config":
            self._serve_config()
            return
        if self.path == "/v1/update/manifest":
            self._serve_update_manifest()
            return
        if self.path == "/v1/update/agent.exe":
            self._serve_update_binary()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/v1/enroll":
            self._enroll()
            return
        if self.path == "/v1/heartbeat":
            self._heartbeat()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def _root(self) -> Path:
        return Path(self.server.state_dir)  # type: ignore[attr-defined]

    def _read_body_json(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return None
        if length <= 0 or length > MAX_JSON_BODY:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return None
        try:
            body = self.rfile.read(length)
            value = json.loads(body)
        except (OSError, json.JSONDecodeError):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return None
        if not isinstance(value, dict):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return None
        return value

    def _send_json(self, status: HTTPStatus, value: dict[str, Any]) -> None:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _bearer(self) -> str | None:
        raw = self.headers.get("Authorization", "")
        if not raw.startswith("Bearer "):
            return None
        token = raw[7:].strip()
        if len(token) != 64:
            return None
        try:
            int(token, 16)
        except ValueError:
            return None
        return token

    def _authorized_device(self) -> tuple[Path, dict[str, Any]] | None:
        token = self._bearer()
        if token is None:
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return None
        index_path = self._root() / "tokens" / f"{token_index(token)}.json"
        if not index_path.is_file():
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return None
        try:
            index = read_json(index_path)
            device_id = str(index["device_id"])
            device_path = self._root() / "devices" / f"{device_id}.json"
            device = read_json(device_path)
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return None
        if not secrets.compare_digest(str(device.get("device_token", "")), token):
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return None
        return device_path, device

    def _global_config(self) -> dict[str, Any]:
        value = read_json(self._root() / "config.json")
        required = (
            "config_version",
            "wgshim_server",
            "wgshim_listen",
            "wgshim_target",
            "padding_min",
            "padding_max",
            "wireguard_interface",
            "wireguard_subnet",
            "wireguard_server_address",
            "wireguard_server_public_key",
            "wireguard_mtu",
            "wireguard_keepalive",
            "wireguard_allowed_ips",
            "wgshim_key_dir",
        )
        for name in required:
            if name not in value:
                raise ValueError(f"control config is missing {name}")
        return value

    def _config_for_device(self, device: dict[str, Any]) -> dict[str, Any]:
        global_config = self._global_config()
        config = {
            "config_version": int(global_config["config_version"]),
            "wgshim_server": str(global_config["wgshim_server"]),
            "wgshim_listen": str(global_config["wgshim_listen"]),
            "wgshim_target": str(global_config["wgshim_target"]),
            "wgshim_psk": str(device["wgshim_psk"]),
            "padding_min": int(global_config["padding_min"]),
            "padding_max": int(global_config["padding_max"]),
            "update_channel": str(global_config.get("update_channel", "stable")),
        }
        legacy = str(device.get("legacy_tunnel", "")).strip()
        if legacy:
            config["legacy_tunnel"] = legacy
        return config

    def _wireguard_profile_for_device(self, device: dict[str, Any]) -> dict[str, Any]:
        config = self._global_config()
        allowed_ips = config["wireguard_allowed_ips"]
        if not isinstance(allowed_ips, list) or not allowed_ips:
            raise ValueError("wireguard_allowed_ips must be a non-empty list")
        return {
            "address": str(device["wireguard_address"]),
            "mtu": int(config["wireguard_mtu"]),
            "peer_public_key": str(config["wireguard_server_public_key"]),
            "allowed_ips": [str(item) for item in allowed_ips],
            "persistent_keepalive": int(config["wireguard_keepalive"]),
        }

    def _allocate_wireguard_address(self) -> str:
        config = self._global_config()
        network = ipaddress.ip_network(str(config["wireguard_subnet"]), strict=False)
        if network.version != 4:
            raise ValueError("wireguard_subnet must be IPv4")
        server_ip = ipaddress.ip_interface(str(config["wireguard_server_address"])).ip
        used: set[ipaddress.IPv4Address] = set()
        for path in (self._root() / "devices").glob("*.json"):
            try:
                device = read_json(path)
                if bool(device.get("revoked", False)):
                    continue
                raw = str(device.get("wireguard_address", "")).strip()
                if raw:
                    used.add(ipaddress.ip_interface(raw).ip)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
        for candidate in network.hosts():
            if candidate == server_ip or candidate in used:
                continue
            return f"{candidate}/32"
        raise RuntimeError("BPC Agent WireGuard address pool is exhausted")

    def _install_wireguard_peer(self, public_key: str, address: str) -> None:
        config = self._global_config()
        run_wg(
            "set",
            str(config["wireguard_interface"]),
            "peer",
            public_key,
            "allowed-ips",
            address,
        )

    def _remove_wireguard_peer(self, public_key: str) -> None:
        if not public_key:
            return
        try:
            config = self._global_config()
            run_wg("set", str(config["wireguard_interface"]), "peer", public_key, "remove")
        except (OSError, KeyError, ValueError, RuntimeError):
            pass

    def _enroll(self) -> None:
        body = self._read_body_json()
        if body is None:
            return
        token = str(body.get("token", "")).strip()
        device_name = str(body.get("device", "")).strip()
        public_key = str(body.get("public_key", "")).strip()
        wireguard_public_key = str(body.get("wireguard_public_key", "")).strip()
        agent_version = str(body.get("version", "")).strip()

        if len(token) != 64 or not device_name or len(device_name) > 64:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        try:
            int(token, 16)
            public_raw = base64.b64decode(public_key, validate=True)
        except (ValueError, base64.binascii.Error):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if len(public_raw) != 32 or not valid_wireguard_key(wireguard_public_key):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return

        enroll_path = self._root() / "enroll" / f"{token}.json"
        if not enroll_path.is_file():
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        try:
            enrollment = read_json(enroll_path)
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        if str(enrollment.get("device", "")) != device_name:
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        expires = int(enrollment.get("expires", 0))
        if expires <= int(time.time()):
            enroll_path.unlink(missing_ok=True)
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return

        enroll_lock: threading.Lock = self.server.enroll_lock  # type: ignore[attr-defined]
        with enroll_lock:
            if not enroll_path.is_file():
                self.send_error(HTTPStatus.UNAUTHORIZED)
                return
            device_id = uuid.uuid4().hex
            device_token = secrets.token_hex(32)
            wgshim_psk = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            now = int(time.time())
            try:
                wireguard_address = self._allocate_wireguard_address()
                global_config = self._global_config()
                key_path = Path(str(global_config["wgshim_key_dir"])) / f"{device_id}.key"
                device_path = self._root() / "devices" / f"{device_id}.json"
                token_path = self._root() / "tokens" / f"{token_index(device_token)}.json"
                device = {
                    "device_id": device_id,
                    "device": device_name,
                    "device_token": device_token,
                    "public_key": public_key,
                    "wireguard_public_key": wireguard_public_key,
                    "wireguard_address": wireguard_address,
                    "wgshim_psk": wgshim_psk,
                    "legacy_tunnel": str(enrollment.get("legacy_tunnel", "")),
                    "created": now,
                    "last_seen": now,
                    "last_version": agent_version,
                    "revoked": False,
                }
                atomic_json(device_path, device)
                atomic_json(token_path, {"device_id": device_id})
                atomic_text(key_path, wgshim_psk + "\n")
                self._install_wireguard_peer(wireguard_public_key, wireguard_address)
                enroll_path.unlink()
                config = self._config_for_device(device)
                wireguard = self._wireguard_profile_for_device(device)
            except (OSError, ValueError, KeyError, RuntimeError):
                self._remove_wireguard_peer(wireguard_public_key)
                for rollback in (
                    self._root() / "devices" / f"{device_id}.json",
                    self._root() / "tokens" / f"{token_index(device_token)}.json",
                ):
                    rollback.unlink(missing_ok=True)
                try:
                    global_config = self._global_config()
                    (Path(str(global_config["wgshim_key_dir"])) / f"{device_id}.key").unlink(
                        missing_ok=True
                    )
                except (OSError, ValueError, KeyError, json.JSONDecodeError):
                    pass
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
                return

        self._send_json(
            HTTPStatus.OK,
            {
                "device_id": device_id,
                "device_token": device_token,
                "config": config,
                "wireguard": wireguard,
            },
        )

    def _serve_config(self) -> None:
        authenticated = self._authorized_device()
        if authenticated is None:
            return
        _, device = authenticated
        if bool(device.get("revoked", False)):
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        try:
            config = self._config_for_device(device)
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._send_json(HTTPStatus.OK, config)

    def _heartbeat(self) -> None:
        authenticated = self._authorized_device()
        if authenticated is None:
            return
        device_path, device = authenticated
        if bool(device.get("revoked", False)):
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        body = self._read_body_json()
        if body is None:
            return
        device["last_seen"] = int(time.time())
        device["last_version"] = str(body.get("version", ""))[:32]
        device["last_transport"] = str(body.get("transport", ""))[:32]
        device["last_status"] = str(body.get("status", ""))[:64]
        try:
            atomic_json(device_path, device)
        except OSError:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._send_json(HTTPStatus.OK, {"ok": True})

    def _serve_update_manifest(self) -> None:
        authenticated = self._authorized_device()
        if authenticated is None:
            return
        _, device = authenticated
        if bool(device.get("revoked", False)):
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        manifest_path = self._root() / "update" / "manifest.json"
        if not manifest_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            manifest = read_json(manifest_path)
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._send_json(HTTPStatus.OK, manifest)

    def _serve_update_binary(self) -> None:
        authenticated = self._authorized_device()
        if authenticated is None:
            return
        _, device = authenticated
        if bool(device.get("revoked", False)):
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        binary_path = self._root() / "update" / "bpc-agent.exe"
        if not binary_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        size = binary_path.stat().st_size
        if size <= 0 or size > MAX_UPDATE_SIZE:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/vnd.microsoft.portable-executable")
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Disposition", 'attachment; filename="bpc-agent.exe"')
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with binary_path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                self.wfile.write(chunk)

    def log_message(self, format: str, *args: object) -> None:
        # Paths and authorization failures can contain security-relevant metadata.
        return


class ControlServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BPC Agent control plane")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--cert-file", required=True)
    parser.add_argument("--key-file", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1024 <= args.port <= 65535:
        raise SystemExit("port must be between 1024 and 65535")
    state_dir = Path(args.state_dir)
    for path in (Path(args.cert_file), Path(args.key_file), state_dir / "config.json"):
        if not path.is_file():
            raise SystemExit(f"required file is missing: {path}")

    sync_wireguard_peers(state_dir)

    server = ControlServer((args.listen, args.port), ControlHandler)
    server.state_dir = str(state_dir)
    server.enroll_lock = threading.Lock()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=args.cert_file, keyfile=args.key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
