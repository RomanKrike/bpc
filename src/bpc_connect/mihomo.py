from __future__ import annotations

from typing import Any

from .config import GatewayConfig, Transport
from .errors import BPCConfigError


def _vless(transport: Transport) -> dict[str, Any]:
    s = transport.settings
    required = ("server", "port", "uuid", "servername", "reality_public_key", "short_id")
    missing = [key for key in required if not s.get(key)]
    if missing:
        raise BPCConfigError(f"{transport.name}: missing VLESS settings: {', '.join(missing)}")
    return {
        "name": transport.name,
        "type": "vless",
        "server": s["server"],
        "port": int(s["port"]),
        "uuid": s["uuid"],
        "flow": s.get("flow", "xtls-rprx-vision"),
        "udp": True,
        "packet-encoding": "xudp",
        "tls": True,
        "servername": s["servername"],
        "client-fingerprint": s.get("client_fingerprint", "chrome"),
        "reality-opts": {
            "public-key": s["reality_public_key"],
            "short-id": s["short_id"],
        },
        "network": s.get("network", "tcp"),
    }


def _amneziawg(transport: Transport) -> dict[str, Any]:
    s = transport.settings
    required = ("server", "port", "private_key", "public_key", "client_ip")
    missing = [key for key in required if not s.get(key)]
    if missing:
        raise BPCConfigError(f"{transport.name}: missing AWG settings: {', '.join(missing)}")

    awg = s.get("awg", {})
    version = int(awg.get("version", 2))
    if version not in (1, 2, 3):
        raise BPCConfigError(f"{transport.name}: unsupported AWG version {version}")

    awg_opts: dict[str, Any] = {"version": version}
    for key in (
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
        "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
        "header-protection-key", "content-padding-addition", "rekey-after-time",
        "rekey-timeout", "reject-after-time", "keepalive-timeout",
        "max-handshake-attempts", "random-trailers", "disable-cookies",
    ):
        if key in awg:
            awg_opts[key] = awg[key]

    return {
        "name": transport.name,
        "type": "wireguard",
        "server": s["server"],
        "port": int(s["port"]),
        "private-key": s["private_key"],
        "public-key": s["public_key"],
        "ip": s["client_ip"],
        "allowed-ips": ["0.0.0.0/0"],
        "persistent-keepalive": int(s.get("persistent_keepalive", 25)),
        "udp": True,
        "mtu": int(s.get("mtu", 1380)),
        "amnezia-wg-option": awg_opts,
    }


def _tailscale(transport: Transport) -> dict[str, Any]:
    s = transport.settings
    if not s.get("exit_node"):
        raise BPCConfigError(f"{transport.name}: tailscale exit_node is required")
    result: dict[str, Any] = {
        "name": transport.name,
        "type": "tailscale",
        "hostname": s.get("hostname", "bpc-ge-gateway"),
        "control-url": s.get("control_url", "https://controlplane.tailscale.com"),
        "state-dir": s.get("state_dir", "/var/lib/mihomo/tailscale"),
        "ephemeral": bool(s.get("ephemeral", False)),
        "udp": True,
        "accept-routes": True,
        "exit-node": s["exit_node"],
        "exit-node-allow-lan-access": bool(s.get("allow_lan", True)),
        "ip-version": s.get("ip_version", "ipv4-prefer"),
    }
    if s.get("auth_key"):
        result["auth-key"] = s["auth_key"]
    return result


def render_mihomo(config: GatewayConfig) -> dict[str, Any]:
    proxies: list[dict[str, Any]] = []
    for transport in config.enabled_transports:
        if transport.kind == "vless-reality":
            proxies.append(_vless(transport))
        elif transport.kind == "amneziawg":
            proxies.append(_amneziawg(transport))
        elif transport.kind == "tailscale":
            proxies.append(_tailscale(transport))
        else:  # pragma: no cover - protected by parser validation
            raise BPCConfigError(f"Unsupported transport: {transport.kind}")

    names = [p["name"] for p in proxies]
    if not names:
        raise BPCConfigError("No enabled transports")

    # No DIRECT route exists by design. If all transports fail, traffic fails closed.
    result: dict[str, Any] = {
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "allow-lan": True,
        "external-controller": config.api_listen,
        "secret": config.api_secret,
        "unified-delay": True,
        "profile": {"store-selected": True, "store-fake-ip": True},
        "tun": {
            "enable": True,
            "stack": "mixed",
            "device": config.tun_name,
            "auto-route": True,
            "auto-redirect": True,
            "strict-route": True,
            "dns-hijack": ["any:53"],
            "mtu": config.mtu,
        },
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "nameserver": ["1.1.1.1", "8.8.8.8"],
        },
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "BPC-RUSSIA",
                "type": "fallback",
                "proxies": names,
                "url": config.health_url,
                "interval": config.health_interval,
                "lazy": False,
            }
        ],
        "rules": ["MATCH,BPC-RUSSIA"],
    }
    return result


def assert_fail_closed(document: dict[str, Any]) -> None:
    rules = document.get("rules", [])
    if any(str(rule).endswith(",DIRECT") or str(rule) == "DIRECT" for rule in rules):
        raise BPCConfigError("Unsafe configuration: DIRECT route is forbidden on work gateway")
    groups = document.get("proxy-groups", [])
    for group in groups:
        if "DIRECT" in group.get("proxies", []):
            raise BPCConfigError("Unsafe configuration: DIRECT is forbidden in fallback groups")
