import pathlib

INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
RENDER = pathlib.Path("deploy/bpc-render-clash.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_renderer_prefers_obfuscated_udp_then_wg_then_tcp() -> None:
    assert 'TRANSPORT_ORDER="${BPC_CLASH_TRANSPORT_ORDER:-awg wg vless}"' in RENDER
    assert "BPC-RU-AWG-01" in RENDER
    assert "BPC-RU-WG-01" in RENDER
    assert "BPC-RU-VLESS-01" in RENDER


def test_renderer_uses_mihomo_health_checked_fallback() -> None:
    assert "name: BPC-AUTO" in RENDER
    assert "type: fallback" in RENDER
    assert "url: ${HEALTH_URL}" in RENDER
    assert "interval: ${HEALTH_INTERVAL}" in RENDER
    assert "lazy: false" in RENDER
    assert "timeout: ${HEALTH_TIMEOUT}" in RENDER
    assert "max-failed-times: ${MAX_FAILED_TIMES}" in RENDER
    assert "expected-status: 204" in RENDER
    assert "MATCH,BPC-AUTO" in RENDER
    assert "DIRECT" not in RENDER


def test_renderer_is_exposed_and_migrated() -> None:
    assert "/usr/local/sbin/bpc-render-clash" in INSTALL
    assert '"bpc-render-clash:bpc-render-clash.sh"' in UPDATE
    assert '"bpc-render-clash:bpc-render-clash.sh"' in MIGRATE
    assert '"${BPC_ROOT}/current/deploy/bpc-render-clash.sh"' in MIGRATE


def test_aggregate_profile_is_root_only() -> None:
    assert 'chmod 0600 "${tmp}"' in RENDER
    assert 'clash-verge-auto.yaml' in RENDER
