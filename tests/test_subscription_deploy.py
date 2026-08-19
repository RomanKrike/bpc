import pathlib

ENABLE = pathlib.Path("deploy/bpc-enable-subscription.sh").read_text(encoding="utf-8")
HEALTH = pathlib.Path("deploy/bpc-healthcheck.sh").read_text(encoding="utf-8")
INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
SERVER = pathlib.Path("deploy/bpc-subscription-server.py").read_text(encoding="utf-8")
STATUS = pathlib.Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_subscription_commands_are_exposed() -> None:
    assert "bpc-enable-subscription" in INSTALL
    assert "bpc-subscription-url" in INSTALL
    assert "bpc-enable-subscription:bpc-enable-subscription.sh" in UPDATE
    assert "bpc-subscription-url:bpc-subscription-url.sh" in MIGRATE


def test_subscription_uses_https_and_random_path() -> None:
    assert "certbot" in ENABLE
    assert "openssl rand -hex 32" in ENABLE
    assert "ssl.PROTOCOL_TLS_SERVER" in SERVER
    assert "clash.yaml" in SERVER
    assert "send_error(404)" in SERVER


def test_status_redacts_subscription_path() -> None:
    assert "<hidden>/clash.yaml" in STATUS


def test_subscription_is_health_checked_and_restarted_on_migration() -> None:
    assert "check_subscription" in HEALTH
    assert "bpc-subscription.service" in HEALTH
    assert "systemctl restart bpc-subscription.service" in MIGRATE


def test_server_suppresses_request_path_logging() -> None:
    assert "def log_message" in SERVER
