import pathlib

ENABLE = pathlib.Path("deploy/bpc-enable-mihomo-transports.sh").read_text(encoding="utf-8")
HEALTH = pathlib.Path("deploy/bpc-healthcheck.sh").read_text(encoding="utf-8")
INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
PYPROJECT = pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
RENDER = pathlib.Path("deploy/bpc-render-clash.sh").read_text(encoding="utf-8")
SSH = pathlib.Path("deploy/bpc-enable-ssh-rescue.sh").read_text(encoding="utf-8")
STATUS = pathlib.Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_release_version_is_060() -> None:
    assert 'version = "0.6.0"' in PYPROJECT


def test_mihomo_transport_pack_is_pinned_and_digest_verified() -> None:
    assert 'MIHOMO_VERSION="${BPC_MIHOMO_VERSION:-v1.19.29}"' in ENABLE
    assert "api.github.com/repos/MetaCubeX/mihomo/releases/tags" in ENABLE
    assert 'digest.startswith("sha256:")' in ENABLE
    assert 'sha256sum "${asset_path}"' in ENABLE
    assert '"${actual}" != "${expected}"' in ENABLE


def test_server_pack_contains_all_supported_listeners() -> None:
    for listener_type in (
        "type: hysteria2",
        "type: tuic",
        "type: anytls",
        "type: shadowsocks",
        "type: trojan",
        "type: mieru",
        "type: trusttunnel",
    ):
        assert listener_type in ENABLE
    assert "obfs: salamander" in ENABLE
    assert "2022-blake3-aes-256-gcm" in ENABLE
    assert "shadow-tls:" in ENABLE
    assert "version: 2" in ENABLE
    assert 'network: [tcp, udp]' in ENABLE


def test_client_pack_contains_all_proxy_types_and_names() -> None:
    expected = {
        "BPC-RU-HY2-01": "type: hysteria2",
        "BPC-RU-TUIC-01": "type: tuic",
        "BPC-RU-ANYTLS-01": "type: anytls",
        "BPC-RU-SHADOWTLS-01": "type: ss",
        "BPC-RU-TROJAN-01": "type: trojan",
        "BPC-RU-MIERU-01": "type: mieru",
        "BPC-RU-TRUST-01": "type: trusttunnel",
    }
    for name, proxy_type in expected.items():
        assert name in ENABLE
        assert proxy_type in ENABLE
        assert name in RENDER


def test_transport_pack_is_secret_safe_and_health_checked() -> None:
    assert 'chmod 0600 "${state_env}"' in ENABLE
    assert 'chmod 0600 "${server_config}"' in ENABLE
    assert "Credentials are stored root-only" in ENABLE
    assert "check_mihomo_transports" in HEALTH
    assert "bpc-mihomo-transports.service" in HEALTH
    assert "Mihomo transport pack:" in STATUS


def test_new_commands_are_reconciled_everywhere() -> None:
    for command in (
        '"bpc-enable-mihomo-transports:bpc-enable-mihomo-transports.sh"',
        '"bpc-enable-ssh-rescue:bpc-enable-ssh-rescue.sh"',
    ):
        assert command in INSTALL
        assert command in MIGRATE
        assert command in UPDATE


def test_ssh_rescue_is_key_only_and_forwarding_only() -> None:
    assert "ssh-keygen -q -t ed25519" in SSH
    assert "restrict,port-forwarding" in SSH
    assert "PasswordAuthentication no" in SSH
    assert "KbdInteractiveAuthentication no" in SSH
    assert "AllowTcpForwarding yes" in SSH
    assert "AllowAgentForwarding no" in SSH
    assert "X11Forwarding no" in SSH
    assert "PermitTTY no" in SSH
    assert "GatewayPorts no" in SSH
    assert "sshd -t" in SSH
    assert "systemctl reload" in SSH
    assert "BPC-RU-SSH-RESCUE" in SSH
    assert "check_ssh_rescue" in HEALTH
    assert "SSH rescue:" in STATUS
