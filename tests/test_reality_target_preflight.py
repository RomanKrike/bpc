import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy" / "bpc-check-reality-target.sh"
BOOTSTRAP = ROOT / "deploy" / "bootstrap-ru-node.sh"
MIGRATE = ROOT / "deploy" / "bpc-migrate.sh"


def test_bootstrap_defaults_to_bing_and_runs_preflight_before_xray_install() -> None:
    text = BOOTSTRAP.read_text(encoding="utf-8")
    assert 'REALITY_SERVER_NAME="${REALITY_SERVER_NAME:-www.bing.com}"' in text
    preflight = '"${SCRIPT_DIR}/bpc-check-reality-target.sh" "${REALITY_SERVER_NAME}"'
    assert preflight in text
    assert text.index(preflight) < text.index('bash "${installer}" install --version')


def test_known_microsoft_target_is_rejected_without_network_probe() -> None:
    result = subprocess.run(
        ["bash", str(HELPER), "www.microsoft.com", "443"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 4
    assert "8192-byte REALITY parser limit" in result.stderr
    assert "XTLS/Xray-core#6356" in result.stderr
    assert "www.bing.com" in result.stderr


def test_preflight_checks_certificate_handshake_size() -> None:
    text = HELPER.read_text(encoding="utf-8")
    assert 'MAX_CERT_HANDSHAKE="${BPC_REALITY_MAX_CERT_HANDSHAKE:-8192}"' in text
    assert "-status" in text
    assert "cert_len > MAX_CERT_HANDSHAKE" in text


def test_migration_reconciles_generated_gateway_servername() -> None:
    text = MIGRATE.read_text(encoding="utf-8")
    assert "BPC_REALITY_SERVER_NAME=" in text
    assert "servername: ${reality_server_name}" in text
    assert "known incompatible REALITY target for Xray 26.3.27" in text
