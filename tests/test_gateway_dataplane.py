from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "deploy"))

import bpc_gateway_dataplane as gateway  # noqa: E402


def write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def seed_runtime(tmp_path: Path) -> tuple[Path, Path]:
    state = tmp_path / "state"
    control = state / "control"
    key_dir = state / "ru-node" / "agent" / "wgshim-keys"
    key_dir.mkdir(parents=True)
    write_json(
        control / "config.json",
        {
            "wireguard_interface": "bpcag0",
            "wgshim_key_dir": str(key_dir),
        },
    )
    write_json(
        key_dir.parent / "ownership.json",
        {
            "owner": "bpc",
            "kind": "wireguard-interface",
            "name": "bpcag0",
        },
    )
    return state, key_dir


def psk(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


def test_reconcile_materializes_active_device_and_removes_only_owned_stale_peer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    state, key_dir = seed_runtime(tmp_path)
    control = state / "control"
    new_public = psk(4)
    write_json(
        control / "devices" / "new.json",
        {
            "id": "new",
            "wireguard_public_key": new_public,
            "wireguard_address": "10.253.0.2/32",
            "wgshim_psk": psk(1),
            "enabled": True,
            "revoked": False,
        },
    )
    write_json(
        state / "gateway-dataplane-managed.json",
        {
            "version": 1,
            "interface": "bpcag0",
            "devices": {
                "stale": {
                    "wireguard_public_key": "stale-public",
                    "wireguard_address": "10.253.0.9/32",
                }
            },
        },
    )
    (key_dir / "stale.key").write_text(psk(2) + "\n", encoding="ascii")

    calls: list[tuple[str, ...]] = []

    def run_wg(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(["wg", *args], 0, "", "")

    monkeypatch.setattr(gateway, "_run_wg", run_wg)

    result = gateway.reconcile_gateway_dataplane(state)

    assert result == {"active": 1, "removed": 1}
    assert (key_dir / "new.key").read_text(encoding="ascii") == psk(1) + "\n"
    assert not (key_dir / "stale.key").exists()
    assert (
        "set",
        "bpcag0",
        "peer",
        new_public,
        "allowed-ips",
        "10.253.0.2/32",
    ) in calls
    assert ("set", "bpcag0", "peer", "stale-public", "remove") in calls

    owned = json.loads(
        (state / "gateway-dataplane-managed.json").read_text(encoding="utf-8")
    )
    assert set(owned["devices"]) == {"new"}


def test_reconcile_skips_revoked_and_invalid_devices(tmp_path: Path, monkeypatch) -> None:
    state, key_dir = seed_runtime(tmp_path)
    control = state / "control"
    write_json(
        control / "devices" / "revoked.json",
        {
            "id": "revoked",
            "wireguard_public_key": "revoked-public",
            "wireguard_address": "10.253.0.3/32",
            "wgshim_psk": psk(3),
            "enabled": True,
            "revoked": True,
        },
    )
    write_json(
        control / "devices" / "invalid.json",
        {
            "id": "invalid",
            "wireguard_public_key": "invalid-public",
            "wireguard_address": "10.253.0.4/32",
            "wgshim_psk": "not-base64",
            "enabled": True,
            "revoked": False,
        },
    )

    calls: list[tuple[str, ...]] = []

    def run_wg(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(["wg", *args], 0, "", "")

    monkeypatch.setattr(gateway, "_run_wg", run_wg)
    result = gateway.reconcile_gateway_dataplane(state)

    assert result == {"active": 0, "removed": 0}
    assert not (key_dir / "revoked.key").exists()
    assert not (key_dir / "invalid.key").exists()
    assert all("peer" not in call for call in calls)


def test_gateway_dataplane_ownership_state_is_private(tmp_path: Path, monkeypatch) -> None:
    state, _ = seed_runtime(tmp_path)

    monkeypatch.setattr(
        gateway,
        "_run_wg",
        lambda *args, **kwargs: subprocess.CompletedProcess(["wg", *args], 0, "", ""),
    )
    gateway.reconcile_gateway_dataplane(state)

    mode = os.stat(state / "gateway-dataplane-managed.json").st_mode & 0o777
    assert mode == 0o600
