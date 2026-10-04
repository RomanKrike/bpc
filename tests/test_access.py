from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "deploy"))

import bpc_access as access  # noqa: E402


def device(user_id: str = "u1", *, revoked: bool = False) -> dict[str, object]:
    return {
        "id": "d1",
        "device_id": "d1",
        "user_id": user_id,
        "name": "pc004",
        "wireguard_address": "10.253.0.2/32",
        "enabled": not revoked,
        "revoked": revoked,
        "revoked_at": 100 if revoked else None,
        "managed_routes": [],
    }


def test_allowed_subnet(tmp_path: Path) -> None:
    value = device()
    access.set_access(tmp_path, "user", "u1", "allow", ["192.168.88.0/24"], now=100)

    assert access.destination_allowed(tmp_path, value, "192.168.88.1")
    assert access.effective_routes(tmp_path, value) == ["192.168.88.0/24"]


def test_denied_subnet(tmp_path: Path) -> None:
    value = device()
    access.set_access(tmp_path, "user", "u1", "allow", ["192.168.0.0/16"], now=100)
    access.set_access(tmp_path, "user", "u1", "deny", ["192.168.88.0/24"], now=101)

    assert not access.destination_allowed(tmp_path, value, "192.168.88.10")
    assert access.destination_allowed(tmp_path, value, "192.168.87.10")


def test_overlapping_subnet_deny_has_priority(tmp_path: Path) -> None:
    value = device()
    access.set_access(tmp_path, "user", "u1", "allow", ["10.0.0.0/8"], now=100)
    access.set_access(tmp_path, "device", "d1", "allow", ["10.20.0.0/16"], now=101)
    access.set_access(tmp_path, "device", "d1", "deny", ["10.20.30.0/24"], now=102)

    assert access.destination_allowed(tmp_path, value, "10.20.29.1")
    assert not access.destination_allowed(tmp_path, value, "10.20.30.1")
    assert access.destination_allowed(tmp_path, value, "10.20.31.1")


def test_revoked_device_overrides_access_allow(tmp_path: Path) -> None:
    value = device(revoked=True)
    access.set_access(tmp_path, "user", "u1", "allow", ["192.168.88.0/24"], now=100)

    assert access.effective_routes(tmp_path, value) == []
    assert not access.destination_allowed(tmp_path, value, "192.168.88.1")


def test_unknown_route_is_denied_by_default(tmp_path: Path) -> None:
    value = device()
    access.set_access(tmp_path, "user", "u1", "allow", ["192.168.88.0/24"], now=100)

    assert not access.destination_allowed(tmp_path, value, "172.16.0.10")
    assert not access.destination_allowed(tmp_path, value, "10.253.0.99")


def test_user_access_is_isolated(tmp_path: Path) -> None:
    roman = device("roman-id")
    other = device("other-id")
    access.set_access(tmp_path, "user", "roman-id", "allow", ["192.168.88.0/24"], now=100)
    access.set_access(tmp_path, "user", "other-id", "deny", ["192.168.88.0/24"], now=101)

    assert access.destination_allowed(tmp_path, roman, "192.168.88.10")
    assert not access.destination_allowed(tmp_path, other, "192.168.88.10")


def test_legacy_managed_route_is_allowed_but_access_deny_still_wins(tmp_path: Path) -> None:
    value = device()
    value["managed_routes"] = ["192.168.88.0/24"]
    assert access.destination_allowed(tmp_path, value, "192.168.88.10")

    access.set_access(tmp_path, "user", "u1", "deny", ["192.168.88.128/25"], now=100)
    assert access.destination_allowed(tmp_path, value, "192.168.88.10")
    assert not access.destination_allowed(tmp_path, value, "192.168.88.200")


def test_sync_access_firewall_enforces_routes_on_node(
    tmp_path: Path,
    monkeypatch,
) -> None:
    key_dir = tmp_path / "agent" / "wgshim-keys"
    access.atomic_json(
        tmp_path / "config.json",
        {"wireguard_interface": "bpcag0", "wgshim_key_dir": str(key_dir)},
    )
    access.atomic_json(
        key_dir.parent / "ownership.json",
        {
            "owner": "bpc",
            "kind": "wireguard-interface",
            "name": "bpcag0",
            "config": "/etc/wireguard/bpcag0.conf",
        },
    )
    access.atomic_json(tmp_path / "devices" / "d1.json", device())
    access.set_access(tmp_path, "user", "u1", "allow", ["192.168.88.0/24"], now=100)

    commands: list[list[str]] = []

    def fake_run(command: list[str], *, check: bool = True):
        commands.append(command)
        if command[:3] == ["iptables", "-nL", access.CHAIN_NAME]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if command[:3] == ["iptables", "-C", "FORWARD"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(access, "_run", fake_run)
    monkeypatch.setattr(access, "_replace_firewall_chain",
                        lambda table, chain, rules: commands.extend(
                            [["iptables", "-A", chain, *rule] for rule in rules]))
    access.sync_access_firewall(tmp_path)

    assert ["iptables", "-N", access.CHAIN_NAME] in commands
    assert [
        "iptables",
        "-A",
        access.CHAIN_NAME,
        "-s",
        "10.253.0.2/32",
        "-d",
        "192.168.88.0/24",
        "-j",
        "ACCEPT",
    ] in commands
    assert [
        "iptables",
        "-A",
        access.CHAIN_NAME,
        "-s",
        "10.253.0.2/32",
        "-j",
        "DROP",
    ] in commands
    assert [
        "iptables",
        "-I",
        "FORWARD",
        "1",
        "-i",
        "bpcag0",
        "-m", "comment", "--comment", "bpc-access-a",
        "-j",
        access.CHAIN_NAME,
    ] in commands


def test_existing_access_chain_without_bpc_marker_is_not_flushed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    key_dir = tmp_path / "agent" / "wgshim-keys"
    access.atomic_json(
        tmp_path / "config.json",
        {"wireguard_interface": "bpcag0", "wgshim_key_dir": str(key_dir)},
    )
    access.atomic_json(
        key_dir.parent / "ownership.json",
        {
            "owner": "bpc",
            "kind": "wireguard-interface",
            "name": "bpcag0",
            "config": "/etc/wireguard/bpcag0.conf",
        },
    )

    commands: list[list[str]] = []

    def fake_run(command: list[str], *, check: bool = True):
        del check
        commands.append(command)
        if command[:3] == ["iptables", "-nL", access.CHAIN_NAME]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(access, "_run", fake_run)

    with pytest.raises(access.AccessError, match="ownership is not proven for chain"):
        access.sync_access_firewall(tmp_path)

    assert ["iptables", "-F", access.CHAIN_NAME] not in commands


def test_grant_replaces_exact_deny_without_removing_broader_deny(tmp_path: Path) -> None:
    access.set_access(tmp_path, "user", "u1", "deny", ["192.168.88.0/24"], now=100)
    record = access.set_access(
        tmp_path,
        "user",
        "u1",
        "allow",
        ["192.168.88.0/24"],
        now=101,
    )
    assert record["allow"] == ["192.168.88.0/24"]
    assert record["deny"] == []

    access.set_access(tmp_path, "user", "u1", "deny", ["192.168.0.0/16"], now=102)
    value = device()
    assert not access.destination_allowed(tmp_path, value, "192.168.88.1")


def ingress_fixture(tmp_path: Path, monkeypatch):
    root = tmp_path / "control"
    key_dir = tmp_path / "agent" / "wgshim-keys"
    access.atomic_json(root / "config.json", {
        "wireguard_interface": "bpcag0", "wgshim_key_dir": str(key_dir),
    })
    access.atomic_json(key_dir.parent / "ownership.json", {
        "owner": "bpc", "kind": "wireguard-interface", "name": "bpcag0",
    })
    access.atomic_json(root / "devices" / "d1.json", device())
    access.set_access(root, "device", "d1", "allow", ["192.168.88.0/24"])
    access.atomic_json(tmp_path / "enrollment.json", {"config": {"routing": {
        "version": 1, "local_public": True,
        "routes": [{"cidr": "192.168.88.0/24", "owner_node_id": "home"}],
    }}})
    commands, replacements = [], []
    chains = set()

    def run(command, *, check=True):
        commands.append(command)
        if "-nL" in command:
            found = command[-1] in chains
            return SimpleNamespace(returncode=0 if found else 1, stdout="", stderr="")
        if "-N" in command:
            chains.add(command[-1])
        if "-C" in command:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(access, "_run", run)
    monkeypatch.setattr(access, "_replace_firewall_chain",
                        lambda table, chain, rules: replacements.append((table, chain, rules)))
    return root, commands, replacements, chains


def test_mesh_ingress_preserves_source_and_blocks_legacy_fallback(tmp_path, monkeypatch):
    root, commands, replacements, _ = ingress_fixture(tmp_path, monkeypatch)
    access.sync_access_firewall(root)
    guard = next(rules for _, chain, rules in replacements if chain == "BPC-MESH-GUARD")
    assert guard == [["-s", "10.253.0.2/32", "-d", "192.168.88.0/24",
                      "!", "-o", "bpcrt0", "-j", "DROP"]]
    rules = next(rules for _, chain, rules in replacements if chain == access.CHAIN_NAME)
    assert rules[0] == ["-j", "BPC-MESH-GUARD"]
    assert rules.index(["-s", "10.253.0.2/32", "-j", "DROP"]) < len(rules) - 1
    assert any("PREROUTING" in command and "-I" in command for command in commands)
    assert not any("nat" in command or command[0] == "ip" for command in commands)


def test_withdrawn_route_and_revoked_device_remain_fail_closed(tmp_path, monkeypatch):
    root, _, replacements, _ = ingress_fixture(tmp_path, monkeypatch)
    access.sync_access_firewall(root)
    access.atomic_json(tmp_path / "enrollment.json", {"config": {"routing": {
        "version": 1, "local_public": True, "routes": [],
    }}})
    access.atomic_json(root / "devices" / "d1.json", device(revoked=True))
    replacements.clear()
    access.sync_access_firewall(root)
    guard = next(rules for _, chain, rules in replacements if chain == "BPC-MESH-GUARD")
    assert "192.168.88.0/24" in guard[0]
    rules = next(rules for _, chain, rules in replacements if chain == access.CHAIN_NAME)
    assert ["-s", "10.253.0.2/32", "-j", "DROP"] in rules
    assert not any("192.168.88.0/24" in rule and "ACCEPT" in rule for rule in rules)


def test_mesh_ingress_refuses_foreign_chain(tmp_path, monkeypatch):
    root, commands, _, chains = ingress_fixture(tmp_path, monkeypatch)
    chains.add("BPC-MESH-IN")
    with pytest.raises(access.AccessError, match="ownership is not proven"):
        access.sync_access_firewall(root)
    assert not any("-F" in command for command in commands)
    assert not (root / "mesh-ingress-firewall.json").exists()
