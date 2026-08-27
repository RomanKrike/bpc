import pathlib

ENABLE = pathlib.Path("deploy/bpc-enable-mihomo-transports.sh").read_text(encoding="utf-8")
ENABLE_CORE = pathlib.Path("deploy/bpc-enable-mihomo-transports-core.sh").read_text(
    encoding="utf-8"
)
HEALTH = pathlib.Path("deploy/bpc-healthcheck.sh").read_text(encoding="utf-8")
INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
LISTENER_CHECK = pathlib.Path("deploy/bpc-check-mihomo-listeners.sh").read_text(
    encoding="utf-8"
)
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
PYPROJECT = pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
RENDER = pathlib.Path("deploy/bpc-render-clash.sh").read_text(encoding="utf-8")
SSH = pathlib.Path("deploy/bpc-enable-ssh-rescue.sh").read_text(encoding="utf-8")
STATUS = pathlib.Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
TLS_FIX = pathlib.Path("deploy/bpc-fix-mihomo-tls.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_release_version_is_073() -> None:
    assert 'version = "0.7.3"' in PYPROJECT


def test_mihomo_transport_pack_is_pinned_and_digest_verified() -> None:
    assert 'MIHOMO_VERSION="${BPC_MIHOMO_VERSION:-v1.19.29}"' in ENABLE_CORE
    assert "api.github.com/repos/MetaCubeX/mihomo/releases/tags" in ENABLE_CORE
    assert 'digest.startswith("sha256:")' in ENABLE_CORE
    assert 'sha256sum "${asset_path}"' in ENABLE_CORE
    assert '"${actual}" != "${expected}"' in ENABLE_CORE


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
        assert listener_type in ENABLE_CORE
    assert "obfs: salamander" in ENABLE_CORE
    assert "2022-blake3-aes-256-gcm" in ENABLE_CORE
    assert "shadow-tls:" in ENABLE_CORE
    assert "version: 2" in ENABLE_CORE
    assert 'network: [tcp, udp]' in ENABLE_CORE


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
        assert name in ENABLE_CORE
        assert proxy_type in ENABLE_CORE
        assert name in RENDER


def test_client_profile_credentials_are_normalized_and_repaired() -> None:
    assert "SS2022 then fails Base64 decoding at byte 0" in ENABLE_CORE
    assert "sed 's/\\\\\"/\"/g'" in ENABLE_CORE
    assert "for transport in hy2 tuic anytls shadowtls trojan mieru trusttunnel" in MIGRATE
    assert "grep -Fq '\\\"'" in MIGRATE
    assert "sed -i 's/\\\\\"/\"/g'" in MIGRATE


def test_transport_enable_wrapper_applies_tls_repair() -> None:
    assert '"${SCRIPT_DIR}/bpc-enable-mihomo-transports-core.sh" "$@"' in ENABLE
    assert '"${SCRIPT_DIR}/bpc-fix-mihomo-tls.sh"' in ENABLE


def test_tls_certificates_are_staged_inside_mihomo_home() -> None:
    assert 'TLS_DIR="${SERVER_DIR}/home/tls"' in TLS_FIX
    assert 'STAGED_CERT="${TLS_DIR}/fullchain.pem"' in TLS_FIX
    assert 'STAGED_KEY="${TLS_DIR}/privkey.pem"' in TLS_FIX
    assert "broadening SAFE_PATHS to /etc/letsencrypt" in TLS_FIX
    assert 'install -m 0644 "${TLS_CERT}" "${STAGED_CERT}.new"' in TLS_FIX
    assert 'install -m 0600 "${TLS_KEY}" "${STAGED_KEY}.new"' in TLS_FIX
    assert "bpc-mihomo-transports.service.d/20-bpc-listener-check.conf" in TLS_FIX
    assert "ExecStartPost=${SCRIPT_DIR}/bpc-check-mihomo-listeners.sh" in TLS_FIX
    assert "/etc/letsencrypt/renewal-hooks/deploy/bpc-mihomo-transports" in TLS_FIX
    assert '"${mihomo_tls_fix}"' in MIGRATE


def test_listener_checker_covers_every_expected_socket() -> None:
    expected = (
        'check_socket udp "${HY2_PORT}" "Hysteria2"',
        'check_socket udp "${TUIC_PORT}" "TUIC"',
        'check_socket tcp "${ANYTLS_PORT}" "AnyTLS"',
        'check_socket tcp "${SHADOWTLS_PORT}" "ShadowTLS"',
        'check_socket udp "${SHADOWTLS_PORT}" "Shadowsocks UDP"',
        'check_socket tcp "${TROJAN_PORT}" "Trojan"',
        'check_socket tcp "${MIERU_PORT}" "Mieru"',
        'check_socket tcp "${TRUSTTUNNEL_PORT}" "TrustTunnel"',
        'check_socket udp "${TRUSTTUNNEL_PORT}" "TrustTunnel"',
    )
    for check in expected:
        assert check in LISTENER_CHECK
    assert "grep -Fq 'bpc-mihomo'" in LISTENER_CHECK


def test_update_recovery_is_release_safe_and_repairs_firewalls() -> None:
    assert 'repair_firewall_service "${ru_dir}/awg/enabled" "bpc-awg-firewall.service"' in MIGRATE
    assert 'repair_firewall_service "${ru_dir}/wg/enabled" "bpc-wg-firewall.service"' in MIGRATE
    assert '"${BPC_ROOT}/current/deploy/bpc-migrate.sh" || true' in UPDATE
    assert '"${new_target}/deploy/bpc-migrate.sh" || true' not in UPDATE
    assert 'if ! "${BPC_ROOT}/current/deploy/bpc-migrate.sh"; then' in UPDATE
    assert "Update migration failed." in UPDATE


def test_transport_pack_is_secret_safe_and_health_checked() -> None:
    assert 'chmod 0600 "${state_env}"' in ENABLE_CORE
    assert 'chmod 0600 "${server_config}"' in ENABLE_CORE
    assert "Credentials are stored root-only" in ENABLE_CORE
    assert "check_mihomo_transports" in HEALTH
    assert "bpc-mihomo-transports.service" in HEALTH
    assert "aggregate Clash profile validation failed" in HEALTH
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
