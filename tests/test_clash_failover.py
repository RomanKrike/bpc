import pathlib

INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
RENDER = pathlib.Path("deploy/bpc-render-clash.sh").read_text(encoding="utf-8")
STATUS = pathlib.Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_renderer_prefers_primary_udp_then_diverse_tcp_transports() -> None:
    assert (
        'TRANSPORT_ORDER="${BPC_CLASH_TRANSPORT_ORDER:-awg wg hy2 tuic vless '
        'anytls shadowtls trojan mieru trusttunnel}"'
    ) in RENDER
    for name in (
        "BPC-RU-AWG-01",
        "BPC-RU-WG-01",
        "BPC-RU-HY2-01",
        "BPC-RU-TUIC-01",
        "BPC-RU-VLESS-01",
        "BPC-RU-ANYTLS-01",
        "BPC-RU-SHADOWTLS-01",
        "BPC-RU-TROJAN-01",
        "BPC-RU-MIERU-01",
        "BPC-RU-TRUST-01",
    ):
        assert name in RENDER


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
    assert "MATCH,DIRECT" not in RENDER
    assert "      - DIRECT" not in RENDER


def test_ssh_rescue_is_manual_and_not_part_of_default_fallback_order() -> None:
    order = RENDER.split('TRANSPORT_ORDER="', 1)[1].split('"', 1)[0]
    assert "ssh" not in order
    assert "BPC-RU-SSH-RESCUE" in RENDER
    assert "name: BPC-ROUTE" in RENDER
    assert "type: select" in RENDER
    assert "MATCH,BPC-ROUTE" in RENDER


def test_renderer_is_exposed_and_migrated() -> None:
    assert '"bpc-render-clash:bpc-render-clash.sh"' in INSTALL
    assert '"bpc-render-clash:bpc-render-clash.sh"' in UPDATE
    assert '"bpc-render-clash:bpc-render-clash.sh"' in MIGRATE
    assert '"${BPC_ROOT}/current/deploy/bpc-render-clash.sh"' in MIGRATE


def test_aggregate_profile_is_root_only_and_reported() -> None:
    assert 'chmod 0600 "${tmp}"' in RENDER
    assert "clash-verge-auto.yaml" in RENDER
    assert "Clash auto profile: ready" in STATUS


def test_renderer_never_changes_live_ru_node_directory_permissions() -> None:
    assert 'install -d -m 0700 "${RU_DIR}"' not in RENDER
    assert 'chmod 0700 "${RU_DIR}"' not in RENDER
    assert "Never chmod or" in RENDER
