from pathlib import Path

import pytest
import yaml

from bpc_connect.config import load_gateway_config
from bpc_connect.errors import BPCConfigError
from bpc_connect.mihomo import assert_fail_closed, render_mihomo

EXAMPLE = Path(__file__).parents[1] / "config" / "gateway.example.yaml"


def test_example_config_loads() -> None:
    config = load_gateway_config(EXAMPLE)
    assert config.name == "bpc-ge-gateway"
    assert [t.name for t in config.enabled_transports] == [
        "RU-VLESS-01",
        "RU-AWG-01",
        "RU-WG-01",
    ]


def test_render_is_strict_and_fail_closed() -> None:
    doc = render_mihomo(load_gateway_config(EXAMPLE))
    assert doc["tun"]["strict-route"] is True
    assert doc["tun"]["auto-route"] is True
    assert doc["rules"] == ["MATCH,BPC-RUSSIA"]
    assert "DIRECT" not in yaml.safe_dump(doc)
    assert_fail_closed(doc)


def test_fallback_order_uses_priority() -> None:
    doc = render_mihomo(load_gateway_config(EXAMPLE))
    group = doc["proxy-groups"][0]
    assert group["type"] == "fallback"
    assert group["proxies"] == ["RU-VLESS-01", "RU-AWG-01", "RU-WG-01"]


def test_vless_enables_xudp() -> None:
    doc = render_mihomo(load_gateway_config(EXAMPLE))
    node = next(p for p in doc["proxies"] if p["name"] == "RU-VLESS-01")
    assert node["packet-encoding"] == "xudp"
    assert node["reality-opts"]["public-key"]


def test_awg_version_is_rendered() -> None:
    doc = render_mihomo(load_gateway_config(EXAMPLE))
    node = next(p for p in doc["proxies"] if p["name"] == "RU-AWG-01")
    assert node["amnezia-wg-option"]["version"] == 2


def test_wireguard_is_rendered_without_awg_options() -> None:
    doc = render_mihomo(load_gateway_config(EXAMPLE))
    node = next(p for p in doc["proxies"] if p["name"] == "RU-WG-01")
    assert node["type"] == "wireguard"
    assert node["port"] == 51820
    assert node["ip"] == "10.252.0.2"
    assert node["pre-shared-key"]
    assert "amnezia-wg-option" not in node


def test_direct_route_is_rejected() -> None:
    doc = render_mihomo(load_gateway_config(EXAMPLE))
    doc["rules"].append("MATCH,DIRECT")
    with pytest.raises(BPCConfigError, match="DIRECT"):
        assert_fail_closed(doc)
