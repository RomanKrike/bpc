import pathlib

BOOTSTRAP = pathlib.Path("deploy/bootstrap-ru-node.sh").read_text(encoding="utf-8")
DNS = pathlib.Path("deploy/bpc-ensure-dns.sh").read_text(encoding="utf-8")
HEALTH = pathlib.Path("deploy/bpc-healthcheck.sh").read_text(encoding="utf-8")
INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
STATUS = pathlib.Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")
AWG = pathlib.Path("deploy/bpc-enable-awg.sh").read_text(encoding="utf-8")
WG = pathlib.Path("deploy/bpc-enable-wg.sh").read_text(encoding="utf-8")


def test_dns_repair_has_resolved_and_static_fallbacks() -> None:
    assert "systemd-resolved.service" in DNS
    assert "/run/systemd/resolve/resolv.conf" in DNS
    assert "/etc/resolv.conf.bpc-backup" in DNS
    assert "BPC_DNS_SERVERS" in DNS


def test_dns_command_is_exposed_and_reconciled() -> None:
    assert "/usr/local/sbin/bpc-ensure-dns" in INSTALL
    assert '"bpc-ensure-dns:bpc-ensure-dns.sh"' in UPDATE
    assert '"bpc-ensure-dns:bpc-ensure-dns.sh"' in MIGRATE


def test_network_sensitive_deploy_scripts_run_dns_preflight() -> None:
    assert "bpc-ensure-dns.sh" in BOOTSTRAP
    assert "bpc-ensure-dns.sh" in AWG
    assert "bpc-ensure-dns.sh" in WG
    assert "bpc-ensure-dns.sh" in UPDATE


def test_public_host_detection_does_not_fallback_to_hostname() -> None:
    assert "ip -4 route get 1.1.1.1" in BOOTSTRAP
    assert "Unable to determine a public IPv4 address" in BOOTSTRAP
    assert "hostname -f" not in BOOTSTRAP


def test_status_reports_dns_and_peer_handshakes() -> None:
    assert "DNS: OK" in STATUS
    assert "DNS: FAILED" in STATUS
    assert 'print_peer_line "AWG"' in STATUS
    assert 'print_peer_line "WG"' in STATUS
    assert "latest-handshakes" in STATUS
    assert "transfer" in STATUS


def test_healthcheck_reports_specific_component_failures() -> None:
    assert "Health check FAILED:" in HEALTH
    assert "xray.service is not active" in HEALTH
    assert "AmneziaWG container" in HEALTH
    assert "bpc-awg-firewall.service is not active" in HEALTH
    assert "wg-quick@${interface}.service is not active" in HEALTH
    assert "bpc-wg-firewall.service is not active" in HEALTH
