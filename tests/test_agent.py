import pathlib

AGENT = pathlib.Path("cmd/bpc-agent/main.go").read_text(encoding="utf-8")
AGENTCTL = pathlib.Path("internal/agentctl/control.go").read_text(encoding="utf-8")
BUILD = pathlib.Path("scripts/build-release.sh").read_text(encoding="utf-8")
CI = pathlib.Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
CONTROL = pathlib.Path("deploy/bpc-control-server.py").read_text(encoding="utf-8")
DATAPLANE = pathlib.Path("deploy/bpc-enable-agent-dataplane.sh").read_text(encoding="utf-8")
ENABLE_CONTROL = pathlib.Path("deploy/bpc-enable-control.sh").read_text(encoding="utf-8")
HEALTH = pathlib.Path("deploy/bpc-healthcheck.sh").read_text(encoding="utf-8")
INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
SERVER = pathlib.Path("deploy/bpc-agent.sh").read_text(encoding="utf-8")
SERVICE = pathlib.Path("cmd/bpc-agent/service_windows.go").read_text(encoding="utf-8")
STATUS = pathlib.Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
TUNNEL = pathlib.Path("cmd/bpc-agent/tunnel_windows.go").read_text(encoding="utf-8")
WGPROFILE = pathlib.Path("internal/agentctl/wireguard.go").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_release_builds_windows_agent() -> None:
    assert "bpc-agent-windows-amd64.exe" in BUILD
    assert "./cmd/bpc-agent" in BUILD
    assert "bpc-agent-relay-linux-amd64" in BUILD
    assert "bpc-agent-relay-linux-arm64" in BUILD
    assert "go build ./cmd/bpc-agent" in CI
    assert "go build ./cmd/bpc-agent-relay" in CI


def test_agent_server_commands_are_reconciled() -> None:
    for command in (
        '"bpc-agent:bpc-agent.sh"',
        '"bpc-enable-control:bpc-enable-control.sh"',
        '"bpc-enable-agent-dataplane:bpc-enable-agent-dataplane.sh"',
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
    assert 'chmod 0600 "${tmp}"' in SERVER


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
    assert "wireguard_public_key" in CONTROL
    assert "_allocate_wireguard_address" in CONTROL
    assert "wgshim_psk" in CONTROL
    assert '"wireguard": wireguard' in CONTROL
    assert "revoked" in CONTROL


def test_control_plane_is_tls_provisioned_and_health_checked() -> None:
    assert "update-signing-key.pem" in ENABLE_CONTROL
    assert "openssl genpkey -algorithm ED25519" in ENABLE_CONTROL
    assert "bpc-control.service" in ENABLE_CONTROL
    assert "bpc-enable-agent-dataplane.sh" in ENABLE_CONTROL
    assert "SUBSCRIPTION_CERT" in ENABLE_CONTROL
    assert "bpc-agent-relay.service" in DATAPLANE
    assert "wg-quick@" in DATAPLANE
    assert "AGENT_WGSHIM_KEY_DIR" in DATAPLANE
    assert "check_control" in HEALTH
    assert "bpc-control.service" in HEALTH
    assert "Agent control plane:" in STATUS
    assert "bpc-enable-control.sh" in MIGRATE


def test_agent_enrolls_syncs_and_reports_heartbeat() -> None:
    assert "agentctl.GenerateIdentity" in AGENT
    assert "agentctl.GenerateWireGuardKeypair" in AGENT
    assert "WireGuardPublicKey" in AGENT
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


def test_agent_runs_as_native_windows_service() -> None:
    assert "svc.Run" in SERVICE
    assert "manager.CreateService" in SERVICE
    assert "mgr.StartAutomatic" in SERVICE
    assert "configureServiceRecovery" in SERVICE
    assert "run-service" in SERVICE
    assert "installWindowsService" in AGENT
    assert "startWindowsService" in AGENT


def test_legacy_wireguard_is_optional_migration_compatibility() -> None:
    assert "--legacy-tunnel" in SERVER
    assert "LegacyTunnel" in AGENT
    assert "captureLegacyWireGuardProfile" in AGENT
    assert "runEmbeddedWireGuard" in AGENT
    assert "WireGuardTunnel$" in AGENT
    assert "ProgramData" in AGENT


def test_prepared_agent_bundles_wintun_runtime() -> None:
    assert "wintun-windows-amd64.dll" in SERVER
    assert "BPC_AGENT_WINTUN_V1" in SERVER
    assert "BPC_AGENT_WINTUN_END" in SERVER
    assert "installWintunPayload" in AGENT


def test_agent_contains_embedded_userspace_wireguard_backend() -> None:
    assert 'golang.zx2c4.com/wireguard/device' in TUNNEL
    assert 'golang.zx2c4.com/wireguard/tun' in TUNNEL
    assert "tun.CreateTUN" in TUNNEL
    assert "device.NewDevice" in TUNNEL
    assert "wgDevice.IpcSet" in TUNNEL
    assert "wgDevice.Up" in TUNNEL
    assert "runEmbeddedWireGuard" in AGENT
    assert "profile.Complete()" in AGENT


def test_agent_can_migrate_existing_wireguard_profile() -> None:
    assert "ParseWireGuardShowConf" in WGPROFILE
    assert "GenerateWireGuardKeypair" in WGPROFILE
    assert "WireGuardProfile" in WGPROFILE
    assert "captureLegacyWireGuardProfile" in AGENT


def test_self_contained_agent_gets_per_device_wireguard_and_relay_credentials() -> None:
    assert 'WireGuardPublicKey string `json:"wireguard_public_key"`' in AGENTCTL
    assert 'WireGuard   WireGuardProfile `json:"wireguard"`' in AGENTCTL
    assert "wireGuardProfile := response.WireGuard" in AGENT
    assert "wireGuardProfile.PrivateKey = wireGuardPrivate" in AGENT
    assert "wgshim-keys" in DATAPLANE
    assert "wireguard_address" in CONTROL
    assert 'run_wg("set"' in CONTROL or '"set",' in CONTROL


def test_embedded_tunnel_pins_relay_outside_full_tunnel_route() -> None:
    assert "resolveWGShimServerIPv4" in TUNNEL
    assert "Find-NetRoute -RemoteIPAddress" in TUNNEL
    assert "No physical route to BPC relay" in TUNNEL
    assert "DestinationPrefix '%s/32'" in TUNNEL


def test_agent_runtime_avoids_legacy_relay_collision_and_stages_control_server() -> None:
    assert "WGSHIM_PORT_EXPLICIT" in DATAPLANE
    assert "24444 24544" in DATAPLANE
    assert "occupied by another service" in DATAPLANE
    assert "bpc-agent-relay" in DATAPLANE
    assert 'control_server="${CONTROL_DIR}/bpc-control-server.py"' in ENABLE_CONTROL
    assert 'install -m 0700 "${BPC_ROOT}/current/deploy/bpc-control-server.py"' in ENABLE_CONTROL
    assert "ExecStart=/usr/bin/python3 ${control_server}" in ENABLE_CONTROL


def test_update_migration_repairs_partial_agent_and_control_runtime() -> None:
    assert '[[ -f "${ru_dir}/agent/enabled" ]]' in MIGRATE
    assert '"${BPC_ROOT}/current/deploy/bpc-enable-agent-dataplane.sh"' in MIGRATE
    assert 'control_should_reconcile="false"' in MIGRATE
    assert 'systemctl --quiet is-enabled bpc-control.service' in MIGRATE
    assert '"${BPC_ROOT}/current/deploy/bpc-enable-control.sh"' in MIGRATE


def test_agent_services_reset_systemd_start_limits_and_health_checks_owner() -> None:
    assert "systemctl reset-failed bpc-agent-relay.service" in DATAPLANE
    assert "systemctl reset-failed bpc-control.service" in ENABLE_CONTROL
    assert "service_owns_udp_port" in HEALTH
    assert 'systemctl show -p MainPID --value' in HEALTH
    assert 'pid=${pid},' in HEALTH
    assert "runtime expects" in STATUS


def test_agent_relay_uses_bounded_readiness_probe() -> None:
    assert 'relay_ready="false"' in DATAPLANE
    assert "sleep 0.25" in DATAPLANE
    assert 'systemctl show -p MainPID --value bpc-agent-relay.service' in DATAPLANE
    assert 'grep -Fq "pid=${relay_pid},"' in DATAPLANE
    assert "did not become ready on UDP/" in DATAPLANE
