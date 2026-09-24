import pathlib

INSTALL = pathlib.Path("install.sh").read_text(encoding="utf-8")
MIGRATE = pathlib.Path("deploy/bpc-migrate.sh").read_text(encoding="utf-8")
RENDER = pathlib.Path("deploy/bpc-render-clash.sh").read_text(encoding="utf-8")
ROUTE_TARGET = pathlib.Path("deploy/bpc-route-target.sh").read_text(encoding="utf-8")
STATUS = pathlib.Path("deploy/bpc-status.sh").read_text(encoding="utf-8")
UPDATE = pathlib.Path("deploy/bpc-update.sh").read_text(encoding="utf-8")


def test_renderer_prefers_censorship_resistant_transports_before_wg() -> None:
    assert (
        'TRANSPORT_ORDER="${BPC_CLASH_TRANSPORT_ORDER:-vless anytls shadowtls trojan '
        'hy2 tuic mieru trusttunnel awg wg}"'
    ) in RENDER
    for name in (
        "BPC-RU-VLESS-01",
        "BPC-RU-ANYTLS-01",
        "BPC-RU-SHADOWTLS-01",
        "BPC-RU-TROJAN-01",
        "BPC-RU-HY2-01",
        "BPC-RU-TUIC-01",
        "BPC-RU-MIERU-01",
        "BPC-RU-TRUST-01",
        "BPC-RU-AWG-01",
        "BPC-RU-WG-01",
    ):
        assert name in RENDER


def test_renderer_uses_mihomo_health_checked_fallback_and_manual_selector() -> None:
    assert "name: BPC-AUTO" in RENDER
    assert "type: fallback" in RENDER
    assert "url: ${HEALTH_URL}" in RENDER
    assert "interval: ${HEALTH_INTERVAL}" in RENDER
    assert "lazy: false" in RENDER
    assert "timeout: ${HEALTH_TIMEOUT}" in RENDER
    assert "max-failed-times: ${MAX_FAILED_TIMES}" in RENDER
    assert "expected-status: 204" in RENDER
    assert "name: BPC-MANUAL" in RENDER
    assert "name: BPC-ROUTE" in RENDER
    assert "type: select" in RENDER


def test_selective_underlay_routes_only_configured_targets_through_bpc() -> None:
    assert 'ROUTE_TARGETS_FILE="${BPC_ROUTE_TARGETS_FILE:-${RU_DIR}/route-targets.txt}"' in RENDER
    assert "IP-CIDR,%s/32,BPC-ROUTE,no-resolve" in RENDER
    assert "MATCH,DIRECT" in RENDER
    assert "MATCH,BPC-ROUTE" in RENDER
    assert "selective underlay" in RENDER
    assert "Target traffic remains fail-closed through BPC-ROUTE" in RENDER


def test_manual_fallbacks_are_not_part_of_default_auto_order() -> None:
    order = RENDER.split('TRANSPORT_ORDER="', 1)[1].split('"', 1)[0]
    assert "ssh" not in order
    assert "openvpn" not in order
    assert "BPC-RU-OPENVPN-01" in RENDER
    assert "BPC-RU-SSH-RESCUE" in RENDER
    assert "BPC-RU-OPENVPN-01" in RENDER
    assert "BPC-RU-SSH-RESCUE" in RENDER


def test_route_target_command_is_exposed_and_migrated() -> None:
    command = '"bpc-route-target:bpc-route-target.sh"'
    assert command in INSTALL
    assert command in UPDATE
    assert command in MIGRATE
    assert "bpc-route-target add IPv4" in ROUTE_TARGET
    assert "bpc-route-target remove IPv4" in ROUTE_TARGET
    assert "bpc-route-target list" in ROUTE_TARGET
    assert "bpc-route-target clear" in ROUTE_TARGET
    assert "Refusing to route the BPC RU endpoint through itself" in ROUTE_TARGET


def test_renderer_is_exposed_and_migrated() -> None:
    assert '"bpc-render-clash:bpc-render-clash.sh"' in INSTALL
    assert '"bpc-render-clash:bpc-render-clash.sh"' in UPDATE
    assert '"bpc-render-clash:bpc-render-clash.sh"' in MIGRATE
    assert '"${BPC_ROOT}/current/deploy/bpc-render-clash.sh"' in MIGRATE


def test_aggregate_profile_is_root_only_and_reported() -> None:
    assert 'chmod 0600 "${tmp}"' in RENDER
    assert "clash-verge-auto.yaml" in RENDER
    assert "Clash auto profile: ready" in STATUS
    assert "Client routing: selective underlay" in STATUS
    assert "Client routing: full-tunnel fail-closed" in STATUS


def test_renderer_never_changes_live_ru_node_directory_permissions() -> None:
    assert 'install -d -m 0700 "${RU_DIR}"' not in RENDER
    assert 'chmod 0700 "${RU_DIR}"' not in RENDER
    assert "Never chmod or" in RENDER
