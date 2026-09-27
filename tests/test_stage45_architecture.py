from pathlib import Path

ROOT = Path(__file__).parents[1]

CORE_FILES = (
    ROOT / "deploy" / "bpc-control-server.py",
    ROOT / "deploy" / "bpc.sh",
    ROOT / "deploy" / "bpc-node.sh",
    ROOT / "deploy" / "bpc-agent.sh",
    ROOT / "deploy" / "bpc_identity.py",
    ROOT / "deploy" / "bpc_access.py",
    ROOT / "deploy" / "bpc_node_enrollment.py",
    ROOT / "deploy" / "bpc_cluster.py",
    ROOT / "src" / "bpc_connect" / "node.py",
)

LEGACY_SCHEMA_TERMS = (
    "BPC_ROLE",
    "ru-node",
    "managed_routes",
    "device_token",
    "legacy_tunnel",
)


def test_core_architecture_does_not_read_legacy_schema_directly() -> None:
    violations: list[str] = []
    for path in CORE_FILES:
        text = path.read_text(encoding="utf-8")
        for term in LEGACY_SCHEMA_TERMS:
            if term in text:
                violations.append(f"{path.relative_to(ROOT)}: {term}")

    assert violations == []


def test_legacy_schema_is_confined_to_compatibility_package() -> None:
    compat = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "src" / "bpc_connect" / "compat").glob("*.py"))
    )

    for term in ("BPC_ROLE", "ru-node", "managed_routes", "device_token", "legacy_tunnel"):
        assert term in compat


def test_new_cli_does_not_reenable_legacy_gateway_writes() -> None:
    node_cli = (ROOT / "deploy" / "bpc-node.sh").read_text(encoding="utf-8")

    assert "Legacy BP Gateway write workflow is deprecated and disabled." in node_cli
    assert "gateway create NAME --route CIDR" not in node_cli
    assert "gateway grant NAME DEVICE" not in node_cli
