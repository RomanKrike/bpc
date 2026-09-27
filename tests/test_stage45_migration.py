from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from bpc_connect.compat.migration import migrate_canonical_state
from bpc_connect.ownership import Ownership, OwnershipEvidence, require_mutable


def fake_inventory_runner(
    command: list[str],
    *,
    check: bool = False,
    capture_output: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[str]:
    del check, capture_output, text
    key = tuple(command)
    stdout = {
        ("ip", "-details", "link"): "1: lo: <LOOPBACK>\n2: eth0: <UP>\n3: wg0: <POINTOPOINT>\n",
        ("ip", "route", "show", "table", "all"): (
            "default via 192.0.2.1 dev eth0\n"
            "192.168.88.0/24 dev wg0 proto static metric 10\n"
        ),
        ("ip", "rule"): "0: from all lookup local\n32766: from all lookup main\n",
        ("wg", "show", "all", "dump"): (
            "wg0\tPRIVATE\tPUBLIC\t51820\toff\n"
            "wg0\tPEER\tPSK\t198.51.100.10:51820\t10.0.0.0/8\t0\t0\t0\toff\n"
        ),
        ("wg", "show", "interfaces"): "wg0 bpcag0\n",
        ("iptables-save",): "*filter\n:FORWARD ACCEPT [0:0]\nCOMMIT\n",
        ("nft", "list", "ruleset"): "table inet external { chain forward { } }\n",
        (
            "systemctl",
            "list-units",
            "--all",
            "--no-pager",
            "--no-legend",
        ): "wg-quick@wg0.service loaded active exited\n",
    }.get(key, "")
    return subprocess.CompletedProcess(command, 0, stdout, "")


def seed_legacy_bpc_state(root: Path) -> None:
    control = root / "ru-node" / "control"
    control.mkdir(parents=True)
    (control / "config.json").write_text('{"config_version":4}', encoding="utf-8")
    (control / "enabled").touch()

    agent = root / "ru-node" / "agent"
    agent.mkdir(parents=True)
    (agent / "enabled").touch()
    (agent / "runtime.env").write_text(
        "AGENT_WG_INTERFACE=bpcag0\n",
        encoding="utf-8",
    )


def test_stage45_migration_preserves_external_network_and_is_idempotent(tmp_path: Path) -> None:
    seed_legacy_bpc_state(tmp_path)

    first = migrate_canonical_state(
        tmp_path,
        runner=fake_inventory_runner,
        now=1_000,
    )

    assert first.external_wireguard_objects_detected == ("wg0",)
    assert first.external_objects_modified == ()
    assert "2 route entries captured" in first.external_routes_detected
    assert first.external_firewall_state == "captured; migration does not mutate firewall"
    assert (tmp_path / "control" / "config.json").read_text(encoding="utf-8") == (
        '{"config_version":4}'
    )
    assert (tmp_path / "control" / ".bpc-state.json").is_file()
    assert (tmp_path / "compat" / "stage-4.5.json").is_file()

    backup = Path(first.backup_dir)
    assert (backup / "legacy-control" / "config.json").read_text(encoding="utf-8") == (
        '{"config_version":4}'
    )
    wg_snapshot = (backup / "inventory" / "wg-dump.txt").read_text(encoding="utf-8")
    assert "PRIVATE" not in wg_snapshot
    assert "PSK" not in wg_snapshot
    assert "<redacted-private-key>" in wg_snapshot
    assert "<redacted-preshared-key>" in wg_snapshot

    second = migrate_canonical_state(
        tmp_path,
        runner=fake_inventory_runner,
        now=2_000,
    )

    assert second == first
    assert sorted((tmp_path / "backups").iterdir()) == [backup]


def test_stage45_migration_refuses_to_overwrite_different_canonical_state(
    tmp_path: Path,
) -> None:
    seed_legacy_bpc_state(tmp_path)
    canonical = tmp_path / "control"
    canonical.mkdir()
    (canonical / "config.json").write_text('{"different":true}', encoding="utf-8")

    with pytest.raises(RuntimeError, match="differs from legacy state"):
        migrate_canonical_state(
            tmp_path,
            runner=fake_inventory_runner,
            now=3_000,
        )

    assert (canonical / "config.json").read_text(encoding="utf-8") == '{"different":true}'
    assert (tmp_path / "ru-node" / "control" / "config.json").read_text(
        encoding="utf-8"
    ) == '{"config_version":4}'


def test_unknown_or_external_ownership_is_fail_closed() -> None:
    with pytest.raises(PermissionError, match="ownership=EXTERNAL"):
        require_mutable(OwnershipEvidence(Ownership.EXTERNAL, "pre-existing wg0"))
    with pytest.raises(PermissionError, match="ownership=UNKNOWN"):
        require_mutable(OwnershipEvidence(Ownership.UNKNOWN, "unclassified route"))

    require_mutable(OwnershipEvidence(Ownership.OWNED_BY_BPC, "ownership marker"))
    require_mutable(OwnershipEvidence(Ownership.LEGACY_BPC, "legacy BPC marker"))


def test_migration_report_explicitly_records_no_external_mutation(tmp_path: Path) -> None:
    seed_legacy_bpc_state(tmp_path)

    report = migrate_canonical_state(
        tmp_path,
        runner=fake_inventory_runner,
        now=4_000,
    )
    marker = json.loads(
        (tmp_path / "compat" / "stage-4.5.json").read_text(encoding="utf-8")
    )

    assert marker["report"]["external_objects_modified"] == []
    assert report.external_objects_modified == ()
