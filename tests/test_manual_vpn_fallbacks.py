import pathlib

HEALTH = pathlib.Path("deploy/bpc-healthcheck.sh").read_text(encoding="utf-8")
IKE = pathlib.Path("deploy/bpc-enable-ikev2.sh").read_text(encoding="utf-8")
INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
OPENVPN = pathlib.Path("deploy/bpc-enable-openvpn.sh").read_text(encoding="utf-8")
RENDER = pathlib.Path("deploy/bpc-render-clash.sh").read_text(encoding="utf-8")
STATUS = pathlib.Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_openvpn_supports_udp_and_tcp_without_tcp_exit_notify() -> None:
    assert 'BPC_OPENVPN_PROTO:-udp' in OPENVPN
    assert 'server_proto="tcp-server"' in OPENVPN
    assert 'client_proto="tcp-client"' in OPENVPN
    assert 'if [[ "${OVPN_PROTO}" == "udp" ]]; then' in OPENVPN
    assert "explicit-exit-notify 1" in OPENVPN
    assert "reneg-sec 0" in OPENVPN


def test_openvpn_generates_native_and_mihomo_clients() -> None:
    assert "client.ovpn" in OPENVPN
    assert "BPC-RU-OPENVPN-01" in OPENVPN
    assert "type: openvpn" in OPENVPN
    assert "tls-crypt:" in OPENVPN
    assert "openvpn-server@bpc.service" in OPENVPN
    assert "bpc-openvpn-firewall.service" in OPENVPN
    assert "BPC-RU-OPENVPN-01" in RENDER
    assert "check_openvpn" in HEALTH
    assert "OpenVPN fallback:" in STATUS


def test_ikev2_is_native_manual_fallback_with_eap_mschapv2() -> None:
    assert "strongswan-swanctl" in IKE
    assert "charon-systemd" in IKE
    assert "auth = eap-mschapv2" in IKE
    assert "eap_id = %any" in IKE
    assert "local_ts = 0.0.0.0/0" in IKE
    assert "UDP/500" in IKE
    assert "UDP/4500" in IKE
    assert "not part of the Clash subscription" in IKE
    assert "BPC-RU-IKE" not in RENDER


def test_ikev2_installs_leaf_chain_and_private_key_separately() -> None:
    assert "/cert.pem" in IKE
    assert "/chain.pem" in IKE
    assert "/privkey.pem" in IKE
    assert "/etc/swanctl/x509/bpc-ikev2-cert.pem" in IKE
    assert "/etc/swanctl/x509ca/bpc-ikev2-chain.pem" in IKE
    assert "/etc/swanctl/private/bpc-ikev2-key.pem" in IKE
    assert "swanctl --load-all" in IKE
    assert "strongswan.service" in IKE
    assert "check_ikev2" in HEALTH
    assert "IKEv2 fallback:" in STATUS


def test_manual_vpn_commands_are_reconciled_everywhere() -> None:
    for command in (
        '"bpc-enable-openvpn:bpc-enable-openvpn.sh"',
        '"bpc-enable-ikev2:bpc-enable-ikev2.sh"',
    ):
        assert command in INSTALL
        assert command in MIGRATE
        assert command in UPDATE
