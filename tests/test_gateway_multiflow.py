import pathlib

INSTALLER = pathlib.Path("deploy/bp-gateway-install.sh.tpl").read_text(encoding="utf-8")
UPGRADE = pathlib.Path("deploy/bp-gateway-upgrade.sh").read_text(encoding="utf-8")


def test_gateway_auto_transport_uses_multiflow_pool() -> None:
    assert "client-flow-auto" in INSTALLER
    assert 'UDP_FLOWS="${BP_GATEWAY_UDP_FLOWS:-6}"' in INSTALLER
    assert 'TCP_FLOWS="${BP_GATEWAY_TCP_FLOWS:-2}"' in INSTALLER
    assert "--udp-flows ${UDP_FLOWS}" in INSTALLER
    assert "--tcp-flows ${TCP_FLOWS}" in INSTALLER


def test_gateway_upgrade_migrates_existing_auto_transport_to_multiflow() -> None:
    assert "client-flow-auto" in UPGRADE
    assert 'udp_flows="${udp_flows:-6}"' in UPGRADE
    assert 'tcp_flows="${tcp_flows:-2}"' in UPGRADE
    assert '"BP_GATEWAY_UDP_FLOWS": sys.argv[5]' in UPGRADE
    assert '"BP_GATEWAY_TCP_FLOWS": sys.argv[6]' in UPGRADE
