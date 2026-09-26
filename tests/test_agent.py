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
UI = pathlib.Path("cmd/bpc-agent/ui_windows.go").read_text(encoding="utf-8")
WGPROFILE = pathlib.Path("internal/agentctl/wireguard.go").read_text(encoding="utf-8")
WGSHIM_CODEC = pathlib.Path("internal/wgshim/codec.go").read_text(encoding="utf-8")
WGSHIM_RELAY = pathlib.Path("internal/wgshim/relay.go").read_text(encoding="utf-8")
AGENT_RELAY = pathlib.Path("cmd/bpc-agent-relay/main.go").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")
NODE = pathlib.Path("deploy/bpc-node.sh").read_text(encoding="utf-8")
GATEWAY_TEMPLATE = pathlib.Path("deploy/bp-gateway-install.sh.tpl").read_text(encoding="utf-8")
GATEWAY_UPGRADE = pathlib.Path("deploy/bp-gateway-upgrade.sh").read_text(encoding="utf-8")
WGSHIM_TCP = pathlib.Path("internal/wgshim/tcp.go").read_text(encoding="utf-8")
WGSHIM_TRANSPORT = pathlib.Path("internal/wgshim/transport.go").read_text(encoding="utf-8")


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
        '"bpc-node:bpc-node.sh"',
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


def test_agent_runtime_avoids_legacy_relay_collision_and_stages_control_runtime() -> None:
    assert "WGSHIM_PORT_EXPLICIT" in DATAPLANE
    assert "24444 24544" in DATAPLANE
    assert "port_available_for_agent" in DATAPLANE
    assert "bpc-agent-relay" in DATAPLANE
    assert 'runtime_version_dir="${CONTROL_DIR}/runtime-${release_version}"' in ENABLE_CONTROL
    assert 'control_server="${CONTROL_DIR}/runtime/bpc-control-server.py"' in ENABLE_CONTROL
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
    assert "udp-pool=" in STATUS


def test_agent_relay_uses_bounded_readiness_probe() -> None:
    assert 'relay_ready="false"' in DATAPLANE
    assert "sleep 0.25" in DATAPLANE
    assert 'systemctl show -p MainPID --value bpc-agent-relay.service' in DATAPLANE
    assert 'grep -Fq "pid=${relay_pid},"' in DATAPLANE
    assert "did not become ready on UDP pool" in DATAPLANE


def test_prepared_agent_has_expiring_https_download_link() -> None:
    assert "/v1/bootstrap/" in CONTROL
    assert "_serve_bootstrap_binary" in CONTROL
    assert 'downloads = self._root() / "downloads"' in CONTROL
    assert "HTTPStatus.GONE" in CONTROL
    assert "download_token" in SERVER
    assert '"${CONTROL_DIR}/downloads"' in SERVER
    assert 'Download URL:' in SERVER
    assert '${control_url}/v1/bootstrap/${download_token}/${download_name}' in SERVER
    assert '"download_token": sys.argv[5]' in SERVER
    assert 'downloads / f"{token}.exe"' in CONTROL
    assert '"${CONTROL_DIR}/downloads"' in ENABLE_CONTROL


def test_bootstrap_download_is_repeatable_until_enrollment() -> None:
    bootstrap_method = CONTROL.split("def _serve_bootstrap_binary", 1)[1]
    bootstrap_method = bootstrap_method.split("def _serve_update_binary", 1)[0]
    assert "expires <= int(time.time())" in bootstrap_method
    assert "self._delete_bootstrap_download(token)" in bootstrap_method
    enrollment_block = CONTROL.split("def _enroll", 1)[1]
    enrollment_block = enrollment_block.split("def _serve_config", 1)[0]
    assert "self._delete_bootstrap_download(download_token)" in enrollment_block
    assert "_delete_bootstrap_download" in CONTROL



def test_agent_defaults_to_split_tunnel_and_hot_syncs_routes() -> None:
    assert 'WG_ALLOWED_IPS="${BPC_AGENT_ALLOWED_IPS:-${WG_SUBNET}}"' in DATAPLANE
    assert '"config_version": 4' in ENABLE_CONTROL
    assert '"wireguard": self._wireguard_profile_for_device(device)' in CONTROL
    assert 'WireGuard     *WireGuardProfile `json:"wireguard,omitempty"`' in AGENTCTL
    assert "ValidateWireGuardServerProfile" in AGENTCTL
    assert "syncRuntimeState(ctx, control, state, statePath)" in AGENT
    startup_sync = AGENT.index("syncRuntimeState(ctx, control, state, statePath)")
    startup_apply = AGENT.index("supervisor.apply(ctx, state.Config, state.WireGuard, logger)")
    assert startup_sync < startup_apply
    assert "profile.PrivateKey = state.WireGuard.PrivateKey" in AGENT
    assert "state.WireGuard = profile" in AGENT
    assert 'Tunnel routes: %s' in AGENT


def test_agent_has_wireguard_style_tray_ui() -> None:
    assert '"status-json"' in AGENT
    assert '"connect"' in AGENT
    assert '"disconnect"' in AGENT
    assert '"ui"' in AGENT
    assert '"install-ui"' in AGENT
    assert "installWindowsUI" in AGENT
    assert "startWindowsUI" in AGENT
    assert "BPC Agent UI" in UI
    assert "System.Windows.Forms.NotifyIcon" in UI
    assert "Connect" in UI
    assert "Disconnect" in UI
    assert "& $exe connect" in UI
    assert "& $exe disconnect" in UI
    assert "setWindowsServiceAutomatic(true)" in AGENT
    assert "setWindowsServiceAutomatic(false)" in AGENT
    assert "CurrentVersion\\Run" in UI
    assert "schtasks.exe" in UI


def test_agent_ui_uses_bp_connect_branding() -> None:
    assert "$form.Text = 'BP Connect'" in UI
    assert "$title.Text = 'Connect'" in UI
    assert "__BPC_LOGO_PNG__" in UI
    assert "bpcConnectLogoPNGBase64" in UI
    assert "System.Windows.Forms.PictureBox" in UI
    assert "$tray.Text = 'BP Connect'" in UI
    assert "Open BP Connect" in UI
    assert "BPC Agent - Connected" not in UI


def test_manual_update_migrates_existing_install_to_tray_ui() -> None:
    assert "scheduleReplacement(exePath, nextPath, installUI)" in AGENT
    assert "checkAndStageUpdate(context.Background(), control, state, logger, true)" in AGENT
    assert "install-ui" in AGENT


def test_agent_ui_runs_in_interactive_session_without_secret_state_access() -> None:
    assert "Local\\BPCAgentUI" in UI
    assert "ui-status.json" in UI
    assert "Get-Service -Name BPCAgent" in UI
    assert "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in UI
    launch_block = UI.split("func launchWindowsUI() error", 1)[1]
    assert 'elevate("ui")' not in launch_block
    assert "powershell.exe" in launch_block
    assert "writeUIStatus" in AGENT
    assert "uiStatus struct" in AGENT
    assert "DeviceToken" not in AGENT.split("type uiStatus struct", 1)[1].split("}", 1)[0]
    assert "PrivateKey" not in AGENT.split("type uiStatus struct", 1)[1].split("}", 1)[0]
    assert "*S-1-5-32-545:RX" in AGENT


def test_agent_overlay_allows_server_health_ping() -> None:
    assert '-i "${AGENT_WG_INTERFACE}" -s "${AGENT_WG_SUBNET}"' in DATAPLANE
    assert "--icmp-type echo-request -j ACCEPT" in DATAPLANE
    down_block = DATAPLANE.split("  down)", 1)[1].split("  *)", 1)[0]
    assert "--icmp-type echo-request -j ACCEPT" in down_block


def test_agent_managed_routes_are_per_device_and_remain_split_tunnel() -> None:
    assert "bpc-agent routes NAME [CIDR ... | --clear]" in SERVER
    assert '\"managed_routes\": []' in CONTROL
    assert 'device.get(\"managed_routes\", [])' in CONTROL
    assert "0.0.0.0/0 is not allowed for managed Agent routes" in SERVER
    assert "next config sync (up to 30 seconds)" in SERVER
    assert "profile.AllowedIPs" in TUNNEL
    assert '! -d \"${AGENT_WG_SUBNET}\" -j MASQUERADE' in DATAPLANE


def test_agent_ui_uses_real_wireguard_handshake_and_transfer_telemetry() -> None:
    assert "wgDevice.IpcGet()" in TUNNEL
    assert '\"last_handshake_time_sec\"' in TUNNEL
    assert '\"rx_bytes\"' in TUNNEL
    assert '\"tx_bytes\"' in TUNNEL
    assert "ui-runtime.json" in AGENT
    assert "writeUIRuntimeStatus" in AGENT
    assert "handshake_at" in UI
    assert "Connecting..." in UI
    assert "Last handshake" in UI
    assert "Traffic" in UI
    assert "RX $(Format-Bytes" in UI
    assert "handshakeAge -le 180" in UI


def test_agent_ui_is_rendered_from_current_exe_and_self_refreshes() -> None:
    assert "os.UserCacheDir()" in UI
    assert "__BPC_UI_VERSION__" in UI
    assert "strings.ReplaceAll(windowsUIScript" in UI
    assert "Restart-BpcUI" in UI
    assert "Start-Process -FilePath $exe -ArgumentList 'ui'" in UI


def test_agent_has_persistent_randomized_udp_port_pool() -> None:
    assert "AGENT_WGSHIM_PORTS" in DATAPLANE
    assert 'shuf -i 20000-59999 -n 256' in DATAPLANE
    assert 'WGSHIM_PORTS="$(IFS=,; echo "${wgshim_ports[*]}")"' in DATAPLANE
    assert '--listen ${relay_listeners}' in DATAPLANE
    assert '"wgshim_servers": [f"{host}:{port}" for port in ports]' in ENABLE_CONTROL
    assert '"wgshim_servers": [' in CONTROL
    assert 'WGShimServers []string' in AGENTCTL
    assert "service_owns_udp_port bpc-agent-relay.service" in HEALTH
    assert "udp-pool=" in STATUS


def test_agent_adaptive_port_selection_uses_authenticated_rtt_probes() -> None:
    assert "packetProbe" in WGSHIM_CODEC
    assert "packetProbeReply" in WGSHIM_CODEC
    assert "SealProbe" in WGSHIM_CODEC
    assert "SealProbeReply" in WGSHIM_CODEC
    assert "OpenTyped" in WGSHIM_CODEC
    assert "RunAdaptiveClient" in WGSHIM_RELAY
    assert "ProbeTimeout" in WGSHIM_RELAY
    assert "SwitchThreshold" in WGSHIM_RELAY
    assert "30*time.Second" in WGSHIM_RELAY
    assert "60*time.Second" in WGSHIM_RELAY
    assert "15*time.Minute" in WGSHIM_RELAY
    assert "45*time.Minute" in WGSHIM_RELAY
    assert "splitListeners" in AGENT_RELAY
    assert "wgshim.RunAdaptiveClient" in AGENT


def test_agent_ui_shows_selected_udp_endpoint_and_port_rtt() -> None:
    assert "ui-transport.json" in AGENT
    assert "writeUITransportStatus" in AGENT
    assert "OnEndpointReport" in AGENT
    assert "UDP endpoint" in UI
    assert "LATENCY" in UI
    assert "ports" in UI
    assert "reachable" in UI
    assert "rtt_ms" in AGENT


def test_bp_gateway_routes_home_subnets_through_overlay() -> None:
    assert "advertised_routes" in CONTROL
    assert "gateway_routes" in CONTROL
    assert "sync_gateway_routes" in CONTROL
    assert '"ip", "route", "replace"' in CONTROL
    assert '"allowed-ips"' in CONTROL
    assert "gateway create NAME --route CIDR" in NODE
    assert "gateway grant NAME DEVICE" in NODE
    assert "managed_routes" in NODE
    assert "wireguard_server_public_key" in NODE
    assert "bp-gateway-wgshim.service" in GATEWAY_TEMPLATE
    assert "net.ipv4.ip_forward=1" in GATEWAY_TEMPLATE
    assert "MASQUERADE" in GATEWAY_TEMPLATE


def test_windows_client_uses_bp_connect_branding() -> None:
    assert "$form.Text = 'BP Connect'" in UI
    assert "$tray.Text = 'BP Connect'" in UI
    assert "Open BP Connect" in UI


def test_bp_gateway_firewall_uses_valid_lan_interface() -> None:
    assert "BP_GATEWAY_LAN_INTEFACE" not in GATEWAY_TEMPLATE
    assert 'iptables -C FORWARD -i "${BP_GATEWAY_LAN_INTERFACE}"' in GATEWAY_TEMPLATE
    assert 'iptables -I FORWARD 1 -i "${BP_GATEWAY_LAN_INTERFACE}"' in GATEWAY_TEMPLATE


def test_agent_relay_exposes_tcp_alongside_udp_pool() -> None:
    assert "AGENT_WGSHIM_TCP_PORT" in DATAPLANE
    assert "--listen-tcp 0.0.0.0:${WGSHIM_TCP_PORT}" in DATAPLANE
    assert "service_owns_tcp_port" in HEALTH
    assert "tcp=%s" in STATUS
    assert '"wgshim_tcp_server"' in ENABLE_CONTROL
    assert "RunTCPMultiServer" in AGENT_RELAY


def test_bp_gateway_defaults_to_adaptive_udp_tcp_transport() -> None:
    assert 'TRANSPORT="${BP_GATEWAY_TRANSPORT:-auto}"' in GATEWAY_TEMPLATE
    assert "client-auto" in GATEWAY_TEMPLATE
    assert "--udp-server ${RELAY}" in GATEWAY_TEMPLATE
    assert "--tcp-server ${TCP_RELAY}" in GATEWAY_TEMPLATE
    assert '"TCP_RELAY"' in NODE
    assert '"BP_GATEWAY_TRANSPORT": "auto"' in GATEWAY_UPGRADE
    assert "journalctl -u bp-gateway-wgshim.service" in GATEWAY_UPGRADE


def test_wgshim_tcp_transport_is_framed_persistent_and_adaptive() -> None:
    assert "SetNoDelay(true)" in WGSHIM_TCP
    assert "writeTCPFrame" in WGSHIM_TCP
    assert "readTCPFrame" in WGSHIM_TCP
    assert "RunTCPClient" in WGSHIM_TCP
    assert "RunAdaptiveTransportClient" in WGSHIM_TRANSPORT
    assert "TransportUDP" in WGSHIM_TRANSPORT
    assert "TransportTCP" in WGSHIM_TRANSPORT
    assert "SwitchThreshold" in WGSHIM_TRANSPORT
    assert "SealProbe" in WGSHIM_TRANSPORT


def test_gateway_upgrade_supports_local_wgshim_binary() -> None:
    assert 'LOCAL_WGSHIM_BINARY="${BPC_WGSHIM_BINARY:-}"' in GATEWAY_UPGRADE
    assert 'install -m 0755 "${LOCAL_WGSHIM_BINARY}" /usr/local/bin/bpc-wgshim' in GATEWAY_UPGRADE


def test_status_parses_udp_local_address_column() -> None:
    assert 'addr=$4' in STATUS


def test_gateway_upgrade_reconciles_forwarding_and_nat() -> None:
    assert 'cat > /usr/local/sbin/bp-gateway-firewall' in GATEWAY_UPGRADE
    assert 'iptables -I FORWARD 1 -i "${BP_GATEWAY_LAN_INTERFACE}"' in GATEWAY_UPGRADE
    assert '-o "${BP_GATEWAY_LAN_INTERFACE}" -j MASQUERADE' in GATEWAY_UPGRADE
    assert "systemctl restart bp-gateway-firewall.service" in GATEWAY_UPGRADE
    assert "systemctl --quiet is-active bp-gateway-firewall.service" in GATEWAY_UPGRADE
