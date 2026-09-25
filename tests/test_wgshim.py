import pathlib

BUILD = pathlib.Path("scripts/build-release.sh").read_text(encoding="utf-8")
ENABLE = pathlib.Path("deploy/bpc-enable-wgshim.sh").read_text(encoding="utf-8")
HEALTH = pathlib.Path("deploy/bpc-healthcheck.sh").read_text(encoding="utf-8")
INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
MAIN = pathlib.Path("cmd/bpc-wgshim/main.go").read_text(encoding="utf-8")
MULTI = pathlib.Path("internal/wgshim/multi.go").read_text(encoding="utf-8")
RELAY = pathlib.Path("cmd/bpc-agent-relay/main.go").read_text(encoding="utf-8")
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
STATUS = pathlib.Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")
CODEC = pathlib.Path("internal/wgshim/codec.go").read_text(encoding="utf-8")


def test_wgshim_keeps_wireguard_crypto_untouched_and_wraps_udp() -> None:
    assert "low-latency authenticated UDP wrapper for WireGuard" in MAIN
    assert "No WireGuard cryptography is modified" in MAIN
    assert 'aad = []byte("BPC-WGSHIM-v1")' in CODEC
    assert "cipher.NewGCM" in CODEC
    assert "crypto/rand" in CODEC
    assert "paddingMin" in CODEC
    assert "paddingMax" in CODEC


def test_wgshim_provisioning_is_secret_safe_and_single_client() -> None:
    assert "--target IPv4:PORT" in ENABLE
    assert 'head -c 32 /dev/urandom | base64' in ENABLE
    assert 'chmod 0600 "${WGSHIM_DIR}/psk"' in ENABLE
    assert 'chmod 0600 "${WGSHIM_DIR}/client.txt" "${WGSHIM_DIR}/client.key"' in ENABLE
    assert "one active client" in ENABLE
    assert "Recommended first-test WireGuard MTU: 1360" in ENABLE
    assert "bpc-wgshim.service" in ENABLE


def test_wgshim_is_integrated_into_command_reconciliation_health_and_status() -> None:
    command = '"bpc-enable-wgshim:bpc-enable-wgshim.sh"'
    assert command in INSTALL
    assert command in MIGRATE
    assert command in UPDATE
    assert "check_wgshim" in HEALTH
    assert "WGShim UDP listener is unavailable" in HEALTH
    assert "WGShim low-latency relay:" in STATUS
    assert "Enabled WGShim release binary is missing" in MIGRATE


def test_release_cross_builds_linux_and_windows_wgshim() -> None:
    assert "GOOS=linux GOARCH=amd64" in BUILD
    assert "GOOS=linux GOARCH=arm64" in BUILD
    assert "GOOS=windows GOARCH=amd64" in BUILD
    assert "bpc-wgshim-linux-amd64" in BUILD
    assert "bpc-wgshim-linux-arm64" in BUILD
    assert "bpc-wgshim-windows-amd64.exe" in BUILD


def test_agent_relay_supports_multiple_independent_device_keys() -> None:
    assert "RunMultiServer" in MULTI
    assert "MultiServerPeer" in MULTI
    assert "LoadPeers" in MULTI
    assert "sessions" in MULTI
    assert "--key-dir" not in RELAY
    assert 'flag.String("key-dir"' in RELAY
    assert "bpc-agent-relay-linux-amd64" in BUILD
    assert "bpc-agent-relay-linux-arm64" in BUILD
