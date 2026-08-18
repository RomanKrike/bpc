from pathlib import Path


INSTALL = Path("install.sh").read_text(encoding="utf-8")
HEALTH = Path("deploy/bpc-healthcheck.sh").read_text(encoding="utf-8")
STATUS = Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
UPDATE = Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_install_exposes_awg_switch_and_command() -> None:
    assert "--with-awg" in INSTALL
    assert "--awg-port PORT" in INSTALL
    assert "/usr/local/sbin/bpc-enable-awg" in INSTALL


def test_update_preserves_awg_command() -> None:
    assert "/usr/local/sbin/bpc-enable-awg" in UPDATE


def test_healthcheck_only_requires_awg_after_enable_marker() -> None:
    assert '[[ -f "${awg_dir}/enabled" ]] || return 0' in HEALTH
    assert 'docker exec "${container}" awg show "${interface}"' in HEALTH
    assert "bpc-awg-firewall.service" in HEALTH


def test_status_reports_disabled_or_active_awg() -> None:
    assert "AmneziaWG: disabled" in STATUS
    assert "AWG endpoint:" in STATUS
