import pathlib

SCRIPT = pathlib.Path("deploy/bpc-enable-wg.sh").read_text(encoding="utf-8")


def test_wireguard_uses_native_kernel_stack() -> None:
    assert "wireguard-tools" in SCRIPT
    assert "ip link add dev" in SCRIPT
    assert "type wireguard" in SCRIPT
    assert "docker" not in SCRIPT


def test_wireguard_defaults_are_isolated_from_awg() -> None:
    assert 'WG_PORT="${WG_PORT:-51820}"' in SCRIPT
    assert 'WG_INTERFACE="${WG_INTERFACE:-bpcwg0}"' in SCRIPT
    assert 'WG_SUBNET="${WG_SUBNET:-10.252.0.0/24}"' in SCRIPT
    assert 'WG_CLIENT_ADDRESS="${WG_CLIENT_ADDRESS:-10.252.0.2/32}"' in SCRIPT


def test_wireguard_generates_native_and_clash_clients() -> None:
    assert '"${WG_DIR}/client.conf"' in SCRIPT
    assert '"${WG_DIR}/clash-verge.yaml"' in SCRIPT
    assert "BPC-RU-WG-01" in SCRIPT
    assert "type: wireguard" in SCRIPT
    assert "AllowedIPs = 0.0.0.0/0" in SCRIPT
    assert "PersistentKeepalive" in SCRIPT


def test_wireguard_is_persistent_and_nat_enabled() -> None:
    assert 'wg-quick@${WG_INTERFACE}.service' in SCRIPT
    assert "bpc-wg-firewall.service" in SCRIPT
    assert "net.ipv4.ip_forward=1" in SCRIPT
    assert "MASQUERADE" in SCRIPT


def test_wireguard_credentials_are_root_only() -> None:
    assert "chmod 0600" in SCRIPT
    assert '"${WG_DIR}/server.key"' in SCRIPT
    assert '"${WG_DIR}/client.key"' in SCRIPT
    assert '"${WG_DIR}/preshared.key"' in SCRIPT
