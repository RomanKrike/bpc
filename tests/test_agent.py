import pathlib

AGENT = pathlib.Path("cmd/bpc-agent/main.go").read_text(encoding="utf-8")
BUILD = pathlib.Path("scripts/build-release.sh").read_text(encoding="utf-8")
CI = pathlib.Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
SERVER = pathlib.Path("deploy/bpc-agent.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_release_builds_windows_agent() -> None:
    assert "bpc-agent-windows-amd64.exe" in BUILD
    assert "./cmd/bpc-agent" in BUILD
    assert "go build ./cmd/bpc-agent" in CI


def test_agent_server_command_is_reconciled() -> None:
    command = '"bpc-agent:bpc-agent.sh"'
    assert command in INSTALL
    assert command in MIGRATE
    assert command in UPDATE


def test_prepared_executable_contains_embedded_bootstrap() -> None:
    assert "BPC_AGENT_BOOTSTRAP_V1" in SERVER
    assert "BPC_AGENT_BOOTSTRAP_END" in SERVER
    assert 'chmod 0600 "${prepared}"' in SERVER
    assert "WGSHIM_TARGET_HOST" in SERVER
    assert "WGSHIM_TARGET_PORT" in SERVER


def test_windows_agent_runs_wgshim_and_reconciles_wireguard() -> None:
    assert "wgshim.RunClient" in AGENT
    assert '"WireGuardTunnel$"+cfg.Tunnel' in AGENT
    assert '"endpoint", local' in AGENT
    assert '"schtasks.exe"' in AGENT
    assert '"/SC", "ONSTART"' in AGENT
    assert '"SYSTEM"' in AGENT
    assert "ProgramData" in AGENT
