from __future__ import annotations

from typing import Any

from .errors import BPCConfigError


def validate_short_id(value: str) -> str:
    if len(value) > 16 or len(value) % 2:
        raise BPCConfigError(
            "REALITY short_id must contain an even number of hex characters (max 16)"
        )
    if value and any(ch not in "0123456789abcdefABCDEF" for ch in value):
        raise BPCConfigError("REALITY short_id must be hexadecimal")
    return value.lower()


def render_xray_server(
    *,
    listen_port: int,
    private_key: str,
    short_id: str,
    server_name: str,
    client_uuid: str,
    dest_port: int = 443,
) -> dict[str, Any]:
    """Render a minimal VLESS + REALITY Xray server configuration."""
    if not 1 <= int(listen_port) <= 65535:
        raise BPCConfigError("Xray listen port must be between 1 and 65535")
    if not 1 <= int(dest_port) <= 65535:
        raise BPCConfigError("REALITY destination port must be between 1 and 65535")
    if not private_key:
        raise BPCConfigError("REALITY private key is required")
    if not server_name or "." not in server_name:
        raise BPCConfigError("REALITY server_name must be a hostname")
    if not client_uuid:
        raise BPCConfigError("VLESS client UUID is required")

    short_id = validate_short_id(short_id)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "0.0.0.0",
                "port": int(listen_port),
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": client_uuid, "flow": "xtls-rprx-vision"}],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": f"{server_name}:{int(dest_port)}",
                        "xver": 0,
                        "serverNames": [server_name],
                        "privateKey": private_key,
                        "shortIds": [short_id],
                    },
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                },
            }
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "blocked"},
        ],
    }
