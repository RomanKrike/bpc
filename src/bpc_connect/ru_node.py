from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .xray import render_xray_server


@dataclass(frozen=True)
class RuNodeCredentials:
    host: str
    port: int
    uuid: str
    server_name: str
    reality_private_key: str
    reality_public_key: str
    short_id: str


def render_ru_node(credentials: RuNodeCredentials) -> dict[str, Any]:
    return render_xray_server(
        listen_port=credentials.port,
        private_key=credentials.reality_private_key,
        short_id=credentials.short_id,
        server_name=credentials.server_name,
        client_uuid=credentials.uuid,
    )


def render_gateway_transport(
    credentials: RuNodeCredentials, *, priority: int = 10
) -> dict[str, Any]:
    return {
        "name": "RU-VLESS-01",
        "type": "vless-reality",
        "enabled": True,
        "priority": int(priority),
        "settings": {
            "server": credentials.host,
            "port": credentials.port,
            "uuid": credentials.uuid,
            "servername": credentials.server_name,
            "reality_public_key": credentials.reality_public_key,
            "short_id": credentials.short_id,
            "flow": "xtls-rprx-vision",
            "network": "tcp",
        },
    }
