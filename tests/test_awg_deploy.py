import pathlib

SCRIPT = pathlib.Path("deploy/bpc-enable-awg.sh").read_text(encoding="utf-8")


def test_awg_runtime_is_pinned() -> None:
    assert "amneziavpn/amneziawg-go:2.0.0@sha256:" in SCRIPT
    assert "amneziavpn/amneziawg-go:latest" not in SCRIPT


def test_awg_uses_udp_443_and_isolated_subnet_by_default() -> None:
    assert 'AWG_PORT="${AWG_PORT:-443}"' in SCRIPT
    assert 'AWG_SUBNET="${AWG_SUBNET:-10.251.0.0/24}"' in SCRIPT
    assert 'AWG_INTERFACE="awg0"' in SCRIPT


def test_awg_container_has_required_network_capabilities() -> None:
    assert "--network host" in SCRIPT
    assert "--cap-add NET_ADMIN" in SCRIPT
    assert "--device /dev/net/tun:/dev/net/tun" in SCRIPT


def test_clash_profile_is_proxy_only_awg2() -> None:
    assert "mixed-port: 7897" in SCRIPT
    assert "allow-lan: false" in SCRIPT
    assert "type: wireguard" in SCRIPT
    assert "version: 2" in SCRIPT
    assert "BPC-RU-AWG-01" in SCRIPT


def test_first_awg_profile_avoids_cps_signatures() -> None:
    assert "      i1:" not in SCRIPT.lower()
    assert "      i2:" not in SCRIPT.lower()
    assert "      i3:" not in SCRIPT.lower()
    assert "      i4:" not in SCRIPT.lower()
    assert "      i5:" not in SCRIPT.lower()
