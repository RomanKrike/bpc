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

from bpc_identity import (
    IdentityError,
    authenticate_local_user,
    authorize_access_credential,
    credential_index as identity_credential_index,
    deactivate_device,
    device_is_active,
    find_device_by_public_key,
    issue_access_credential,
    issue_device_session,
    list_devices as identity_list_devices,
    load_device as identity_load_device,
    logout_session,
    refresh_device_session,
    registration_message,
    verify_device_proof,
)

from bpc_node_enrollment import (
    EnrollmentError,
    enroll_node,
    leave_node,
    node_heartbeat,
)

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


def active_wireguard_devices(state_dir: Path) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    for path in sorted((state_dir / "devices").glob("*.json")):
        try:
            device = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if bool(device.get("revoked", False)) or not bool(device.get("enabled", True)):
            continue
        public_key = str(device.get("wireguard_public_key", "")).strip()
        address = str(device.get("wireguard_address", "")).strip()
        if not valid_wireguard_key(public_key) or not address:
            continue
        devices.append(device)
    return devices


def gateway_routes(devices: list[dict[str, Any]]) -> dict[str, str]:
    owners: dict[str, str] = {}
    networks: list[tuple[ipaddress.IPv4Network, str]] = []
    for device in devices:
        if str(device.get("role", "")) != "gateway":
            continue
        owner = str(device.get("device", device.get("device_id", "gateway")))
        advertised = device.get("advertised_routes", [])
        if not isinstance(advertised, list):
            raise RuntimeError(f"BP Gateway {owner} has invalid advertised_routes")
        for raw in advertised:
            try:
                network = ipaddress.ip_network(str(raw), strict=False)
            except ValueError as exc:
                raise RuntimeError(f"BP Gateway {owner} has invalid route {raw!r}") from exc
            if network.version != 4 or network.prefixlen == 0:
                raise RuntimeError(f"BP Gateway {owner} has unsupported route {network}")
            for existing, existing_owner in networks:
                if network.overlaps(existing):
                    raise RuntimeError(
                        f"BP Gateway route {network} owned by {owner} overlaps "
                        f"{existing} owned by {existing_owner}"
                    )
            canonical = str(network)
            networks.append((network, owner))
            owners[canonical] = owner
    return owners


def sync_wireguard_peers(state_dir: Path) -> None:
    config = read_json(state_dir / "config.json")
    interface = str(config["wireguard_interface"])
    devices = active_wireguard_devices(state_dir)
    gateway_routes(devices)

    completed = subprocess.run(
        ["wg", "show", interface, "peers"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or f"WireGuard interface {interface} unavailable"
        raise RuntimeError(message)
    for peer in completed.stdout.split():
        run_wg("set", interface, "peer", peer, "remove")

    for device in devices:
        public_key = str(device["wireguard_public_key"]).strip()
        address = str(device["wireguard_address"]).strip()
        allowed = [address]
        if str(device.get("role", "")) == "gateway":
            allowed.extend(str(route) for route in device.get("advertised_routes", []))
        run_wg(
            "set",
            interface,
            "peer",
            public_key,
            "allowed-ips",
            ",".join(allowed),
        )


def sync_gateway_routes(state_dir: Path) -> None:
    config = read_json(state_dir / "config.json")
    interface = str(config["wireguard_interface"])
    routes = sorted(gateway_routes(active_wireguard_devices(state_dir)))
    state_path = state_dir / "gateway-routes.json"

    previous_routes: list[str] = []
    previous_interface = interface
    if state_path.is_file():
        try:
            previous = read_json(state_path)
            previous_interface = str(previous.get("interface", interface))
            value = previous.get("routes", [])
            if isinstance(value, list):
                previous_routes = [str(route) for route in value]
        except (OSError, ValueError, json.JSONDecodeError):
            previous_routes = []

    for route in previous_routes:
        if route in routes and previous_interface == interface:
            continue
        subprocess.run(
            ["ip", "route", "del", route, "dev", previous_interface],
            check=False,
            capture_output=True,
            text=True,
        )

    for route in routes:
        completed = subprocess.run(
            ["ip", "route", "replace", route, "dev", interface, "proto", "static", "metric", "50"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip()
            raise RuntimeError(message or f"failed to install BP Gateway route {route}")

    atomic_json(state_path, {"interface": interface, "routes": routes})


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
        if self.path.startswith("/v1/bootstrap/"):
            self._serve_bootstrap_binary()
            return
        if self.path == "/v1/devices":
            self._serve_devices()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/v1/auth/login":
            self._auth_login()
            return
        if self.path == "/v1/auth/refresh":
            self._auth_refresh()
            return
        if self.path == "/v1/auth/logout":
            self._auth_logout()
            return
        if self.path == "/v1/devices/register":
            self._device_register()
            return
        if self.path == "/v1/devices/revoke":
            self._device_revoke()
            return
        if self.path == "/v1/enroll":
            self._enroll()
            return
        if self.path == "/v1/heartbeat":
            self._heartbeat()
            return
        if self.path == "/v1/nodes/join":
            self._node_join()
            return
        if self.path == "/v1/nodes/heartbeat":
            self._node_heartbeat()
            return
        if self.path == "/v1/nodes/leave":
            self._node_leave()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def _root(self) -> Path:
        return Path(self.server.state_dir)  # type: ignore[attr-defined]

    def _delete_bootstrap_download(self, token: str) -> None:
        if len(token) != 64:
            return
        try:
            int(token, 16)
        except ValueError:
            return
        downloads = self._root() / "downloads"
        (downloads / f"{token}.json").unlink(missing_ok=True)
        (downloads / f"{token}.exe").unlink(missing_ok=True)

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

        identity_error: IdentityError | None = None
        try:
            _, device, _ = authorize_access_credential(
                self._root(),
                token,
                require_device=True,
            )
            if device is None:
                raise IdentityError("device credential required", 403)
            device_id = str(device.get("id", device.get("device_id", "")))
            return self._root() / "devices" / f"{device_id}.json", device
        except IdentityError as exc:
            identity_error = exc

        # Compatibility path for devices enrolled before Stage 3. New devices
        # never receive a static device_token.
        index_path = self._root() / "tokens" / f"{token_index(token)}.json"
        if not index_path.is_file():
            if identity_error is not None:
                self._send_json(
                    HTTPStatus(identity_error.status),
                    {"error": str(identity_error)},
                )
            else:
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
        if not bool(device.get("enabled", True)) or bool(device.get("revoked", False)):
            self.send_error(HTTPStatus.FORBIDDEN)
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
            "wgshim_servers": [
                str(item)
                for item in global_config.get(
                    "wgshim_servers",
                    [global_config["wgshim_server"]],
                )
            ],
            "wgshim_listen": str(global_config["wgshim_listen"]),
            "wgshim_target": str(global_config["wgshim_target"]),
            "wgshim_psk": str(device["wgshim_psk"]),
            "padding_min": int(global_config["padding_min"]),
            "padding_max": int(global_config["padding_max"]),
            "update_channel": str(global_config.get("update_channel", "stable")),
            "wireguard": self._wireguard_profile_for_device(device),
        }
        legacy = str(device.get("legacy_tunnel", "")).strip()
        if legacy:
            config["legacy_tunnel"] = legacy
        return config

    def _wireguard_profile_for_device(self, device: dict[str, Any]) -> dict[str, Any]:
        config = self._global_config()
        base_allowed = config["wireguard_allowed_ips"]
        if not isinstance(base_allowed, list) or not base_allowed:
            raise ValueError("wireguard_allowed_ips must be a non-empty list")

        managed = device.get("managed_routes", [])
        if not isinstance(managed, list):
            raise ValueError("device managed_routes must be a list")

        overlay = ipaddress.ip_network(str(config["wireguard_subnet"]), strict=False)
        allowed_ips: list[str] = []
        seen: set[str] = set()

        for raw in base_allowed:
            network = ipaddress.ip_network(str(raw).strip(), strict=False)
            if network.version != 4 or network.prefixlen == 0:
                raise ValueError("invalid base Agent allowed IP")
            canonical = str(network)
            if canonical not in seen:
                seen.add(canonical)
                allowed_ips.append(canonical)

        for raw in managed:
            network = ipaddress.ip_network(str(raw).strip(), strict=False)
            if network.version != 4:
                raise ValueError("Agent managed routes currently support IPv4 only")
            if network.prefixlen == 0:
                raise ValueError("Agent managed routes cannot install a default route")
            if network.overlaps(overlay):
                raise ValueError("Agent managed route overlaps the overlay subnet")
            canonical = str(network)
            if canonical not in seen:
                seen.add(canonical)
                allowed_ips.append(canonical)

        return {
            "address": str(device["wireguard_address"]),
            "mtu": int(config["wireguard_mtu"]),
            "peer_public_key": str(config["wireguard_server_public_key"]),
            "allowed_ips": allowed_ips,
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

    def _auth_login(self) -> None:
        body = self._read_body_json()
        if body is None:
            return
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        if not username or len(password) > 1024:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid username or password"})
            return
        try:
            user = authenticate_local_user(self._root(), username, password)
            access_token, expires_at = issue_access_credential(
                self._root(),
                user_id=str(user["id"]),
                device_id=None,
                scope="login",
            )
        except IdentityError as exc:
            self._send_json(HTTPStatus(exc.status), {"error": str(exc)})
            return
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "access_token": access_token,
                "access_expires_at": expires_at,
                "user": {
                    "id": str(user["id"]),
                    "username": str(user["username"]),
                },
            },
        )

    def _auth_refresh(self) -> None:
        body = self._read_body_json()
        if body is None:
            return
        refresh_token = str(body.get("refresh_token", "")).strip()
        proof = str(body.get("proof", "")).strip()
        try:
            response = refresh_device_session(
                self._root(),
                refresh_token,
                proof,
            )
        except IdentityError as exc:
            self._send_json(HTTPStatus(exc.status), {"error": str(exc)})
            return
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._send_json(HTTPStatus.OK, response)

    def _auth_logout(self) -> None:
        access_token = self._bearer()
        if access_token is None:
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        body = self._read_body_json()
        if body is None:
            return
        refresh_token = str(body.get("refresh_token", "")).strip() or None
        try:
            logout_session(self._root(), access_token, refresh_token)
        except IdentityError as exc:
            self._send_json(HTTPStatus(exc.status), {"error": str(exc)})
            return
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._send_json(HTTPStatus.OK, {"ok": True})

    def _device_register(self) -> None:
        access_token = self._bearer()
        if access_token is None:
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        body = self._read_body_json()
        if body is None:
            return
        device_name = str(body.get("name", body.get("device", ""))).strip()
        public_key = str(body.get("public_key", "")).strip()
        wireguard_public_key = str(body.get("wireguard_public_key", "")).strip()
        proof = str(body.get("proof", "")).strip()
        agent_version = str(body.get("version", "")).strip()[:32]

        if not device_name or len(device_name) > 64:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        try:
            public_raw = base64.b64decode(public_key, validate=True)
        except (ValueError, base64.binascii.Error):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if len(public_raw) != 32 or not valid_wireguard_key(wireguard_public_key):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return

        try:
            user, existing_access_device, _ = authorize_access_credential(
                self._root(),
                access_token,
                required_scope="login",
            )
            if existing_access_device is not None:
                raise IdentityError("login credential cannot be device-bound", 403)
            verify_device_proof(
                public_key,
                proof,
                registration_message(access_token, public_key, wireguard_public_key),
            )
        except IdentityError as exc:
            self._send_json(HTTPStatus(exc.status), {"error": str(exc)})
            return

        enroll_lock: threading.Lock = self.server.enroll_lock  # type: ignore[attr-defined]
        with enroll_lock:
            existing = find_device_by_public_key(self._root(), public_key)
            if existing is not None:
                if str(existing.get("user_id", "")) != str(user["id"]):
                    self._send_json(HTTPStatus.CONFLICT, {"error": "device identity is already owned"})
                    return
                if not device_is_active(existing):
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "device identity was revoked"})
                    return
                if not secrets.compare_digest(
                    str(existing.get("wireguard_public_key", "")),
                    wireguard_public_key,
                ):
                    self._send_json(
                        HTTPStatus.CONFLICT,
                        {"error": "device WireGuard identity does not match registered device"},
                    )
                    return
                device = existing
                device_id = str(device.get("id", device.get("device_id", "")))
                device["last_seen"] = int(time.time())
                device["last_version"] = agent_version
                try:
                    atomic_json(self._root() / "devices" / f"{device_id}.json", device)
                except OSError:
                    self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
                    return
            else:
                device_id = uuid.uuid4().hex
                wgshim_psk = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
                now = int(time.time())
                try:
                    wireguard_address = self._allocate_wireguard_address()
                    global_config = self._global_config()
                    key_path = Path(str(global_config["wgshim_key_dir"])) / f"{device_id}.key"
                    device_path = self._root() / "devices" / f"{device_id}.json"
                    device = {
                        "id": device_id,
                        "device_id": device_id,
                        "user_id": str(user["id"]),
                        "name": device_name,
                        "device": device_name,
                        "public_key": public_key,
                        "wireguard_public_key": wireguard_public_key,
                        "wireguard_address": wireguard_address,
                        "wgshim_psk": wgshim_psk,
                        "managed_routes": [],
                        "legacy_tunnel": "",
                        "created_at": now,
                        "created": now,
                        "last_seen": now,
                        "last_version": agent_version,
                        "enabled": True,
                        "revoked_at": None,
                        "revoked": False,
                    }
                    atomic_json(device_path, device)
                    atomic_text(key_path, wgshim_psk + "\n")
                    self._install_wireguard_peer(wireguard_public_key, wireguard_address)
                except (OSError, ValueError, KeyError, RuntimeError):
                    self._remove_wireguard_peer(wireguard_public_key)
                    (self._root() / "devices" / f"{device_id}.json").unlink(missing_ok=True)
                    try:
                        global_config = self._global_config()
                        (Path(str(global_config["wgshim_key_dir"])) / f"{device_id}.key").unlink(
                            missing_ok=True
                        )
                    except (OSError, ValueError, KeyError, json.JSONDecodeError):
                        pass
                    self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
                    return

            try:
                session = issue_device_session(
                    self._root(),
                    user_id=str(user["id"]),
                    device_id=device_id,
                )
                config = self._config_for_device(device)
                wireguard = self._wireguard_profile_for_device(device)
                (
                    self._root()
                    / "identity"
                    / "access"
                    / f"{identity_credential_index(access_token)}.json"
                ).unlink(missing_ok=True)
            except (IdentityError, OSError, ValueError, KeyError, json.JSONDecodeError):
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
                return

        self._send_json(
            HTTPStatus.OK,
            {
                "device_id": device_id,
                **session,
                "config": config,
                "wireguard": wireguard,
            },
        )

    def _serve_devices(self) -> None:
        access_token = self._bearer()
        if access_token is None:
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        try:
            user, _, _ = authorize_access_credential(
                self._root(),
                access_token,
                require_device=True,
            )
        except IdentityError as exc:
            self._send_json(HTTPStatus(exc.status), {"error": str(exc)})
            return
        values: list[dict[str, Any]] = []
        for device in identity_list_devices(self._root(), str(user["id"])):
            values.append(
                {
                    "id": str(device.get("id", device.get("device_id", ""))),
                    "name": str(device.get("name", device.get("device", ""))),
                    "created_at": int(device.get("created_at", device.get("created", 0)) or 0),
                    "last_seen": int(device.get("last_seen", 0) or 0),
                    "enabled": bool(device.get("enabled", True)),
                    "revoked_at": device.get("revoked_at"),
                }
            )
        self._send_json(HTTPStatus.OK, {"devices": values})

    def _device_revoke(self) -> None:
        access_token = self._bearer()
        if access_token is None:
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        body = self._read_body_json()
        if body is None:
            return
        target_id = str(body.get("device_id", "")).strip()
        try:
            user, _, _ = authorize_access_credential(
                self._root(),
                access_token,
                require_device=True,
            )
            target = identity_load_device(self._root(), target_id)
            if str(target.get("user_id", "")) != str(user["id"]):
                raise IdentityError("device not found", 404)
            deactivate_device(self._root(), target_id, revoked=True)
        except IdentityError as exc:
            self._send_json(HTTPStatus(exc.status), {"error": str(exc)})
            return
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self._send_json(HTTPStatus.OK, {"ok": True, "device_id": target_id})

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
            self._delete_bootstrap_download(str(enrollment.get("download_token", "")).strip())
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
                    "managed_routes": [],
                    "legacy_tunnel": str(enrollment.get("legacy_tunnel", "")),
                    "created": now,
                    "created_at": now,
                    "last_seen": now,
                    "last_version": agent_version,
                    "enabled": True,
                    "revoked_at": None,
                    "revoked": False,
                }
                atomic_json(device_path, device)
                atomic_json(token_path, {"device_id": device_id})
                atomic_text(key_path, wgshim_psk + "\n")
                self._install_wireguard_peer(wireguard_public_key, wireguard_address)
                download_token = str(enrollment.get("download_token", "")).strip()
                self._delete_bootstrap_download(download_token)
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

    def _node_join(self) -> None:
        body = self._read_body_json()
        if body is None:
            return
        token = str(body.get("token", "")).strip()
        public_key = str(body.get("public_key", "")).strip()
        name = str(body.get("name", "")).strip()
        node_join_lock: threading.Lock = self.server.node_join_lock  # type: ignore[attr-defined]
        try:
            with node_join_lock:
                response = enroll_node(
                    self._root(),
                    token=token,
                    public_key=public_key,
                    presented_name=name,
                )
        except EnrollmentError as exc:
            self._send_json(HTTPStatus(exc.status), {"error": str(exc)})
            return
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._send_json(HTTPStatus.OK, response)

    def _node_heartbeat(self) -> None:
        credential = self._bearer()
        if credential is None:
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        body = self._read_body_json()
        if body is None:
            return
        try:
            response = node_heartbeat(
                self._root(),
                credential=credential,
                payload=body,
            )
        except EnrollmentError as exc:
            self._send_json(HTTPStatus(exc.status), {"error": str(exc)})
            return
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._send_json(HTTPStatus.OK, response)

    def _node_leave(self) -> None:
        credential = self._bearer()
        if credential is None:
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        body = self._read_body_json()
        if body is None:
            return
        try:
            response = leave_node(self._root(), credential=credential)
        except EnrollmentError as exc:
            self._send_json(HTTPStatus(exc.status), {"error": str(exc)})
            return
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._send_json(HTTPStatus.OK, response)

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

    def _send_binary(self, binary_path: Path, filename: str) -> None:
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
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with binary_path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                self.wfile.write(chunk)

    def _serve_bootstrap_binary(self) -> None:
        clean_path = self.path.split("?", 1)[0]
        parts = clean_path.split("/")
        if len(parts) != 5 or parts[1:3] != ["v1", "bootstrap"]:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        token = parts[3]
        requested_name = parts[4]
        if len(token) != 64 or not requested_name.lower().endswith(".exe"):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            int(token, 16)
        except ValueError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        downloads = self._root() / "downloads"
        metadata_path = downloads / f"{token}.json"
        binary_path = downloads / f"{token}.exe"
        if not metadata_path.is_file() or not binary_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            metadata = read_json(metadata_path)
            expires = int(metadata.get("expires", 0))
            filename = str(metadata.get("filename", ""))
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if expires <= int(time.time()):
            self._delete_bootstrap_download(token)
            self.send_error(HTTPStatus.GONE)
            return
        if not filename or not secrets.compare_digest(filename, requested_name):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self._send_binary(binary_path, filename)

    def _serve_update_binary(self) -> None:
        authenticated = self._authorized_device()
        if authenticated is None:
            return
        _, device = authenticated
        if bool(device.get("revoked", False)):
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        binary_path = self._root() / "update" / "bpc-agent.exe"
        self._send_binary(binary_path, "bpc-agent.exe")

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
    sync_gateway_routes(state_dir)

    server = ControlServer((args.listen, args.port), ControlHandler)
    server.state_dir = str(state_dir)
    server.enroll_lock = threading.Lock()
    server.node_join_lock = threading.Lock()

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
