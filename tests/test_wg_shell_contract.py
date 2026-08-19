import pathlib

HEALTH = pathlib.Path("deploy/bpc-healthcheck.sh").read_text(encoding="utf-8")
INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
STATUS = pathlib.Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_install_exposes_wireguard_switch_and_command() -> None:
    assert "--with-wg" in INSTALL
    assert "--wg-port PORT" in INSTALL
    assert "/usr/local/sbin/bpc-enable-wg" in INSTALL


def test_update_reconciles_wireguard_command() -> None:
    assert '"bpc-enable-wg:bpc-enable-wg.sh"' in UPDATE


def test_migration_exposes_wireguard_for_older_updaters() -> None:
    assert '"bpc-enable-wg:bpc-enable-wg.sh"' in MIGRATE
    assert '"/usr/local/sbin/${name}"' in MIGRATE


def test_healthcheck_only_requires_wireguard_after_enable_marker() -> None:
    assert '[[ -f "${wg_dir}/enabled" ]] || return 0' in HEALTH
    assert 'wg show "${interface}"' in HEALTH
    assert "bpc-wg-firewall.service" in HEALTH


def test_status_reports_disabled_or_active_wireguard() -> None:
    assert "WireGuard: disabled" in STATUS
    assert "WG endpoint:" in STATUS
