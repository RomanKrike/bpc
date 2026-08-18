import pathlib

INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
HEALTH = pathlib.Path("deploy/bpc-healthcheck.sh").read_text(encoding="utf-8")
STATUS = pathlib.Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_install_exposes_awg_switch_and_command() -> None:
    assert "--with-awg" in INSTALL
    assert "--awg-port PORT" in INSTALL
    assert "/usr/local/sbin/bpc-enable-awg" in INSTALL


def test_update_reconciles_command_links_before_same_version_exit() -> None:
    assert "reconcile_command_links" in UPDATE
    assert "/usr/local/sbin/${name}" in UPDATE
    reconcile_pos = UPDATE.index('reconcile_command_links "${BPC_ROOT}/current"')
    same_version_pos = UPDATE.index('if [[ "${latest_version}" == "${current_version}" ]]')
    assert reconcile_pos < same_version_pos


def test_healthcheck_only_requires_awg_after_enable_marker() -> None:
    assert '[[ -f "${awg_dir}/enabled" ]] || return 0' in HEALTH
    assert 'docker exec "${container}" awg show "${interface}"' in HEALTH
    assert "bpc-awg-firewall.service" in HEALTH


def test_status_reports_disabled_or_active_awg() -> None:
    assert "AmneziaWG: disabled" in STATUS
    assert "AWG endpoint:" in STATUS
