import pathlib

AGENT = pathlib.Path("cmd/bpc-agent/main.go").read_text(encoding="utf-8")
AGENTCTL = pathlib.Path("internal/agentctl/control.go").read_text(encoding="utf-8")
BUILD = pathlib.Path("scripts/build-release.sh").read_text(encoding="utf-8")
CI = pathlib.Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
CONTROL = pathlib.Path("deploy/bpc-control-server.py").read_text(encoding="utf-8")
ENABLE_CONTROL = pathlib.Path("deploy/bpc-enable-control.sh").read_text(encoding="utf-8")
HEALTH = pathlib.Path("deploy/bpc-healthcheck.sh").read_text(encoding="utf-8")
INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
SERVER = pathlib.Path("deploy/bpc-agent.sh").read_text(encoding="utf-8")
STATUS = pathlib.Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_release_builds_windows_agent() -> None:
    assert "bpc-agent-windows-amd64.exe" in BUILD
    assert "./cmd/bpc-agent" in BUILD
    assert "go build ./cmd/bpc-agent" in CI


def test_agent_server_commands_are_reconciled() -> None:
    for command in (
        '"bpc-agent:bpc-agent.sh"',
        '"bpc-enable-control:bpc-enable-control.sh"',
    ):
        assert command in INSTALL
        assert command in MIGRATE
        assert command in UPDATE


def test_prepared_executable_uses_one_time_control_plane_bootstrap() -> None:
    assert "BPC_AGENT_BOOTSTRAP_V2" in SERVER
    assert "BPC_AGENT_BOOTSTRAP_END" in SERVER
    assert "openssl rand -hex 32" in SERVER
    assert "Enrollment token lifetime" in SERVER
    assert "update-signing-public.pem" in SERVER
    bootstrap_block = SERVER.split("local json", 1)[1].split("local encoded", 1)[0]
    assert "wgshim_psk" not in bootstrap_block
    assert 'chmod 0600 "\${tmp}"' in SERVER


def test_control_plane_has_enrollment_config_heartbeat_and_update_api() -> None:
    for path in (
        "/v1/enroll",
        "/v1/config",
        "/v1/heartbeat",
        "/v1/update/manifest",
        "/v1/update/agent.exe",
    ):
        assert path in CONTROL
    assert "secrets.compare_digest" in CONTROL
    assert "token_index" in CONTROL
    assert "revoked" in CONTROL


def test_control_plane_is_tls_provisioned_and_health_checked() -> None:
    assert "update-signing-key.pem" in ENABLE_CONTROL
    assert "openssl genpkey -algorithm ED25519" in ENABLE_CONTROL
    assert "bpc-control.service" in ENABLE_CONTROL
    assert "SUBSCRIPTION_CERT" in ENABLE_CONTROL
    assert "check_control" in HEALTH
    assert "bpc-control.service" in HEALTH
    assert "Agent control plane:" in STATUS
    assert "systemctl restart bpc-control.service" in MIGRATE


def test_agent_enrolls_syncs_and_reports_heartbeat() -> None:
    assert "agentctl.GenerateIdentity" in AGENT
    assert "client.Enroll" in AGENT
    assert "control.FetchConfig" in AGENT
    assert "control.Heartbeat" in AGENT
    assert "agentctl.SaveState" in AGENT
    assert "state.json" in AGENT


def test_agent_signed_auto_update_is_fail_closed() -> None:
    assert "agentctl.VerifyUpdateManifest" in AGENT
    assert "agentctl.VerifyFileSHA256" in AGENT
    assert "agentctl.IsNewerVersion" in AGENT
    assert "bpc-agent.next.exe" in AGENT
    assert "update-signing-key.pem" in SERVER
    assert "openssl pkeyutl -sign -rawin" in SERVER
    assert "ed25519.Verify" in AGENTCTL
    assert "control URL must be HTTPS" in AGENTCTL


def test_legacy_wireguard_is_optional_not_required_by_bootstrap() -> None:
    assert "--legacy-tunnel" in SERVER
    assert "LegacyTunnel" in AGENT
    assert "self-contained tunnel backend is not enabled yet" in AGENT
    assert "WireGuardTunnel$" in AGENT
    assert '"/SC", "ONSTART"' in AGENT
    assert '"SYSTEM"' in AGENT
    assert "ProgramData" in AGENT
