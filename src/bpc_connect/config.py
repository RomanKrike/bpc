from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from typing import Any

import yaml

from .errors import BPCConfigError

SUPPORTED_TRANSPORTS = {"vless-reality", "amneziawg", "tailscale"}


@dataclass(frozen=True)
class Transport:
    name: str
    kind: str
    enabled: bool
    priority: int
    settings: dict[str, Any]


@dataclass(frozen=True)
class GatewayConfig:
    name: str
    tun_name: str
    tun_address: str
    mtu: int
    api_listen: str
    api_secret: str
    health_url: str
    health_interval: int
    transports: tuple[Transport, ...]
    home_cidrs: tuple[str, ...]

    @property
    def enabled_transports(self) -> tuple[Transport, ...]:
        return tuple(sorted((t for t in self.transports if t.enabled), key=lambda t: t.priority))


def _require(mapping: dict[str, Any], key: str, ctx: str) -> Any:
    if key not in mapping:
        raise BPCConfigError(f"Missing required key '{key}' in {ctx}")
    return mapping[key]


def load_gateway_config(path: str | Path) -> GatewayConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise BPCConfigError("Top-level config must be a mapping")

    gateway = _require(raw, "gateway", "root")
    if not isinstance(gateway, dict):
        raise BPCConfigError("gateway must be a mapping")

    tun = gateway.get("tun", {})
    api = gateway.get("api", {})
    health = gateway.get("health", {})

    transports_raw = _require(raw, "transports", "root")
    if not isinstance(transports_raw, list) or not transports_raw:
        raise BPCConfigError("transports must be a non-empty list")

    transports: list[Transport] = []
    names: set[str] = set()
    priorities: set[int] = set()
    for idx, item in enumerate(transports_raw):
        if not isinstance(item, dict):
            raise BPCConfigError(f"transports[{idx}] must be a mapping")
        name = str(_require(item, "name", f"transports[{idx}]"))
        kind = str(_require(item, "type", f"transports[{idx}]"))
        enabled = bool(item.get("enabled", True))
        priority = int(_require(item, "priority", f"transports[{idx}]"))
        settings = item.get("settings", {})
        if kind not in SUPPORTED_TRANSPORTS:
            raise BPCConfigError(f"Unsupported transport type: {kind}")
        if name in names:
            raise BPCConfigError(f"Duplicate transport name: {name}")
        if priority in priorities:
            raise BPCConfigError(f"Duplicate transport priority: {priority}")
        if not isinstance(settings, dict):
            raise BPCConfigError(f"settings for transport {name} must be a mapping")
        names.add(name)
        priorities.add(priority)
        transports.append(Transport(name, kind, enabled, priority, settings))

    if not any(t.enabled for t in transports):
        raise BPCConfigError("At least one transport must be enabled")

    home_cidrs_raw = raw.get("home_cidrs", [])
    if not isinstance(home_cidrs_raw, list):
        raise BPCConfigError("home_cidrs must be a list")
    home_cidrs: list[str] = []
    for cidr in home_cidrs_raw:
        try:
            ip_network(str(cidr), strict=False)
        except ValueError as exc:
            raise BPCConfigError(f"Invalid home CIDR: {cidr}") from exc
        home_cidrs.append(str(cidr))

    mtu = int(tun.get("mtu", 1380))
    if not 1200 <= mtu <= 1500:
        raise BPCConfigError("TUN MTU must be between 1200 and 1500")

    interval = int(health.get("interval", 15))
    if interval < 5:
        raise BPCConfigError("health.interval must be at least 5 seconds")

    return GatewayConfig(
        name=str(gateway.get("name", "bpc-ge-gateway")),
        tun_name=str(tun.get("name", "bpc0")),
        tun_address=str(tun.get("address", "172.31.255.1/30")),
        mtu=mtu,
        api_listen=str(api.get("listen", "127.0.0.1:9090")),
        api_secret=str(_require(api, "secret", "gateway.api")),
        health_url=str(health.get("url", "https://cp.cloudflare.com/generate_204")),
        health_interval=interval,
        transports=tuple(transports),
        home_cidrs=tuple(home_cidrs),
    )
