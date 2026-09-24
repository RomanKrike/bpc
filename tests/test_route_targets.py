import pathlib

ROUTE = pathlib.Path("deploy/bpc-route-target.sh").read_text(encoding="utf-8")
RENDER = pathlib.Path("deploy/bpc-render-clash.sh").read_text(encoding="utf-8")


def test_route_target_command_validates_exact_ipv4_endpoints() -> None:
    assert "is_valid_ipv4()" in ROUTE
    assert "Invalid IPv4 route target" in ROUTE
    assert "10#${octet} <= 255" in ROUTE
    assert "Refusing to route the BPC RU endpoint through itself" in ROUTE


def test_route_target_state_is_root_only_and_rerenders_profile() -> None:
    assert 'TARGETS_FILE="${BPC_ROUTE_TARGETS_FILE:-${RU_DIR}/route-targets.txt}"' in ROUTE
    assert 'chmod 0600 "${tmp}"' in ROUTE
    assert '"${RENDERER}"' in ROUTE
    assert "sort -u" in ROUTE


def test_renderer_rejects_corrupt_or_looping_route_target_state() -> None:
    assert "Invalid IPv4 address in ${ROUTE_TARGETS_FILE}" in RENDER
    assert "BPC route target would create a loop through the RU endpoint" in RENDER


def test_selective_mode_keeps_only_target_endpoints_on_bpc() -> None:
    assert "IP-CIDR,%s/32,BPC-ROUTE,no-resolve" in RENDER
    assert "MATCH,DIRECT" in RENDER
    assert "Routing mode: selective underlay" in RENDER
