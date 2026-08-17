import pytest

from bpc_connect.errors import BPCConfigError
from bpc_connect.ru_node import RuNodeCredentials, render_gateway_transport, render_ru_node
from bpc_connect.xray import validate_short_id


def credentials() -> RuNodeCredentials:
    return RuNodeCredentials(
        host="203.0.113.10",
        port=443,
        uuid="11111111-1111-4111-8111-111111111111",
        server_name="www.example.com",
        reality_private_key="private",
        reality_public_key="public",
        short_id="a1b2c3d4e5f60708",
    )


def test_ru_node_renders_reality_server() -> None:
    document = render_ru_node(credentials())
    inbound = document["inbounds"][0]
    reality = inbound["streamSettings"]["realitySettings"]
    assert inbound["port"] == 443
    assert inbound["protocol"] == "vless"
    assert reality["dest"] == "www.example.com:443"
    assert reality["shortIds"] == ["a1b2c3d4e5f60708"]
    assert document["outbounds"][0]["protocol"] == "freedom"


def test_ru_node_generates_matching_gateway_transport() -> None:
    transport = render_gateway_transport(credentials())
    assert transport["type"] == "vless-reality"
    assert transport["settings"]["server"] == "203.0.113.10"
    assert transport["settings"]["reality_public_key"] == "public"
    assert transport["settings"]["short_id"] == "a1b2c3d4e5f60708"


def test_short_id_validation() -> None:
    assert validate_short_id("AABB") == "aabb"
    with pytest.raises(BPCConfigError, match="even"):
        validate_short_id("abc")
    with pytest.raises(BPCConfigError, match="hexadecimal"):
        validate_short_id("zz")
    with pytest.raises(BPCConfigError, match="max 16"):
        validate_short_id("aa" * 9)
