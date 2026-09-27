from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from bpc_connect.compat.legacy import legacy_control_dir, legacy_node_dir
from bpc_connect.ownership import Ownership
from bpc_connect.state import StateLayout

MIGRATION_SCHEMA = 1
MIGRATION_MARKER = "stage-4.5.json"
Run = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class MigrationReport:
    backup_dir: str
    bpc_owned_objects_modified: tuple[str, ...]
    legacy_bpc_objects_migrated: tuple[str, ...]
    external_wireguard_objects_detected: tuple[str, ...]
    external_routes_detected: str
    external_firewall_state: str
    external_objects_modified: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, object]:
        return asdict(self)


def _atomic_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _run_readonly(
    command: Sequence[str],
    *,
    runner: Run = subprocess.run,
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(
            list(command),
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(list(command), 127, "", "command unavailable")


def _write_snapshot(path: Path, completed: subprocess.CompletedProcess[str]) -> None:
    value = completed.stdout
    if completed.stderr:
        value += ("\n" if value else "") + "[stderr]\n" + completed.stderr
    path.write_text(value, encoding="utf-8")
    os.chmod(path, 0o600)


def _redact_wg_dump(raw: str) -> str:
    lines: list[str] = []
    for line in raw.splitlines():
        fields = line.split("\t")
        if len(fields) == 5:
            # interface, private-key, public-key, listen-port, fwmark
            fields[1] = "<redacted-private-key>"
        elif len(fields) >= 9:
            # interface, peer-public-key, preshared-key, endpoint, ...
            fields[2] = "<redacted-preshared-key>"
        lines.append("\t".join(fields))
    return "\n".join(lines) + ("\n" if raw.endswith("\n") else "")


def _known_bpc_wireguard_interfaces(root: Path) -> set[str]:
    result: set[str] = set()
    for runtime in (
        legacy_node_dir(root) / "agent" / "runtime.env",
        legacy_node_dir(root) / "wg" / "runtime.env",
        legacy_node_dir(root) / "wgshim" / "runtime.env",
    ):
        if not runtime.is_file():
            continue
        try:
            for line in runtime.read_text(encoding="utf-8").splitlines():
                key, sep, value = line.partition("=")
                if (
                    sep
                    and key in {"AGENT_WG_INTERFACE", "WG_INTERFACE", "WGSHIM_INTERFACE"}
                    and value.strip()
                ):
                    result.add(value.strip())
        except OSError:
            continue
    return result


def capture_preflight_inventory(
    state_dir: str | Path,
    *,
    runner: Run = subprocess.run,
    now: int | None = None,
) -> tuple[Path, tuple[str, ...], str, str]:
    root = Path(state_dir)
    timestamp = int(time.time()) if now is None else int(now)
    backup = root / "backups" / f"pre-4.5-{timestamp}"
    suffix = 0
    while backup.exists():
        suffix += 1
        backup = root / "backups" / f"pre-4.5-{timestamp}-{suffix}"
    inventory = backup / "inventory"
    inventory.mkdir(parents=True, exist_ok=False, mode=0o700)

    commands = (
        ("ip-link.txt", ["ip", "-details", "link"]),
        ("ip-route-all.txt", ["ip", "route", "show", "table", "all"]),
        ("ip-rule.txt", ["ip", "rule"]),
        ("wg-dump.txt", ["wg", "show", "all", "dump"]),
        ("iptables-save.txt", ["iptables-save"]),
        ("nft-ruleset.txt", ["nft", "list", "ruleset"]),
        (
            "systemd-units.txt",
            ["systemctl", "list-units", "--all", "--no-pager", "--no-legend"],
        ),
    )
    results: dict[str, subprocess.CompletedProcess[str]] = {}
    for filename, command in commands:
        completed = _run_readonly(command, runner=runner)
        results[filename] = completed
        if filename == "wg-dump.txt":
            completed = subprocess.CompletedProcess(
                completed.args,
                completed.returncode,
                _redact_wg_dump(completed.stdout),
                completed.stderr,
            )
        _write_snapshot(inventory / filename, completed)

    wg_interfaces = _run_readonly(["wg", "show", "interfaces"], runner=runner)
    known = _known_bpc_wireguard_interfaces(root)
    external_wg = tuple(
        sorted(
            interface
            for interface in wg_interfaces.stdout.split()
            if interface and interface not in known
        )
    )

    route_output = results["ip-route-all.txt"].stdout
    route_count = len([line for line in route_output.splitlines() if line.strip()])
    external_routes = f"{route_count} route entries captured; migration does not mutate routes"

    firewall_available = any(
        results[name].returncode == 0
        for name in ("iptables-save.txt", "nft-ruleset.txt")
    )
    firewall_state = (
        "captured; migration does not mutate firewall"
        if firewall_available
        else "inventory unavailable; migration still performs no firewall mutation"
    )
    return backup, external_wg, external_routes, firewall_state


def _tree_manifest(root: Path) -> dict[str, tuple[str, str]]:
    if not root.exists():
        return {}
    result: dict[str, tuple[str, str]] = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            result[rel] = ("symlink", os.readlink(path))
        elif path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result[rel] = ("file", digest)
        elif path.is_dir():
            result[rel] = ("dir", "")
    return result


def _control_payload_manifest(root: Path) -> dict[str, tuple[str, str]]:
    manifest = _tree_manifest(root)
    # The ownership marker is canonical metadata, not part of the historical
    # Controller payload. Ignoring it makes an interrupted migration resumable
    # if the process stops between the control marker and global migration marker.
    manifest.pop(".bpc-state.json", None)
    return manifest


def _copy_legacy_control(source: Path, target: Path, backup: Path) -> bool:
    if not source.is_dir():
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        return False

    source_manifest = _control_payload_manifest(source)
    backup_state = backup / "legacy-control"
    shutil.copytree(source, backup_state, symlinks=True)
    if source_manifest != _control_payload_manifest(backup_state):
        raise RuntimeError("legacy Controller backup verification failed")

    if target.exists():
        current = _control_payload_manifest(target)
        if current:
            if current != source_manifest:
                raise RuntimeError(
                    "canonical Controller state already exists and differs from legacy state; "
                    "refusing to overwrite either copy"
                )
            if _control_payload_manifest(source) != source_manifest:
                raise RuntimeError(
                    "legacy Controller state changed during migration; retry when state is stable"
                )
            return True
        target.rmdir()

    staged = target.with_name(f".{target.name}.stage45-{os.getpid()}")
    if staged.exists():
        shutil.rmtree(staged)
    shutil.copytree(source, staged, symlinks=True)
    if (
        _control_payload_manifest(source) != source_manifest
        or _control_payload_manifest(staged) != source_manifest
    ):
        shutil.rmtree(staged, ignore_errors=True)
        raise RuntimeError(
            "legacy Controller state changed during migration; no canonical state was activated"
        )
    os.replace(staged, target)
    return True


def migrate_canonical_state(
    state_dir: str | Path,
    *,
    runner: Run = subprocess.run,
    now: int | None = None,
) -> MigrationReport:
    state = StateLayout.from_root(state_dir)
    state.root.mkdir(parents=True, exist_ok=True, mode=0o700)
    state.compat_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = state.compat_dir / MIGRATION_MARKER
    if marker.is_file():
        control_marker = state.control_dir / ".bpc-state.json"
        if not control_marker.is_file():
            raise RuntimeError(
                "Stage 4.5 marker exists but canonical Controller ownership marker is missing"
            )
        value = json.loads(marker.read_text(encoding="utf-8"))
        report = value.get("report", {})
        if not isinstance(report, dict):
            raise RuntimeError("invalid Stage 4.5 migration marker")
        return MigrationReport(
            backup_dir=str(report.get("backup_dir", "")),
            bpc_owned_objects_modified=tuple(report.get("bpc_owned_objects_modified", [])),
            legacy_bpc_objects_migrated=tuple(report.get("legacy_bpc_objects_migrated", [])),
            external_wireguard_objects_detected=tuple(
                report.get("external_wireguard_objects_detected", [])
            ),
            external_routes_detected=str(report.get("external_routes_detected", "")),
            external_firewall_state=str(report.get("external_firewall_state", "")),
            external_objects_modified=tuple(report.get("external_objects_modified", [])),
        )

    backup, external_wg, external_routes, firewall_state = capture_preflight_inventory(
        state.root,
        runner=runner,
        now=now,
    )

    legacy_control = legacy_control_dir(state.root)
    # This path is a historical BPC-owned state root. Copy only; never delete
    # the source in Stage 4.5 so rollback/audit remains possible.
    source_ownership = (
        Ownership.LEGACY_BPC if legacy_control.is_dir() else Ownership.UNKNOWN
    )

    modified: list[str] = []
    migrated: list[str] = []
    if source_ownership is Ownership.LEGACY_BPC:
        if _copy_legacy_control(legacy_control, state.control_dir, backup):
            modified.append(str(state.control_dir))
            migrated.append(f"{legacy_control} -> {state.control_dir}")
    else:
        state.control_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        modified.append(str(state.control_dir))

    for path in (
        state.identity_dir,
        state.cluster_dir,
        state.runtime_dir,
        state.transport_dir,
        state.compat_dir,
    ):
        existed = path.exists()
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not existed:
            modified.append(str(path))

    control_marker = state.control_dir / ".bpc-state.json"
    if not control_marker.is_file():
        _atomic_json(
            control_marker,
            {
                "schema": 1,
                "owner": "bpc",
                "component": "control",
                "migrated_from": str(legacy_control) if legacy_control.is_dir() else None,
            },
        )
        modified.append(str(control_marker))

    report = MigrationReport(
        backup_dir=str(backup),
        bpc_owned_objects_modified=tuple(modified),
        legacy_bpc_objects_migrated=tuple(migrated),
        external_wireguard_objects_detected=external_wg,
        external_routes_detected=external_routes,
        external_firewall_state=firewall_state,
        external_objects_modified=(),
    )
    _atomic_json(
        marker,
        {
            "schema": MIGRATION_SCHEMA,
            "completed_at": int(time.time()) if now is None else int(now),
            "report": report.to_mapping(),
        },
    )
    return report


def format_report(report: MigrationReport) -> str:
    def block(values: tuple[str, ...], empty: str = "NONE") -> str:
        return "\n".join(values) if values else empty

    return "\n".join(
        (
            "BPC-owned objects modified:",
            block(report.bpc_owned_objects_modified),
            "",
            "Legacy BPC objects migrated:",
            block(report.legacy_bpc_objects_migrated),
            "",
            "External WireGuard objects detected:",
            block(report.external_wireguard_objects_detected),
            "",
            "External routes detected:",
            report.external_routes_detected or "NONE",
            "",
            "External firewall state:",
            report.external_firewall_state or "UNKNOWN",
            "",
            "External objects modified:",
            block(report.external_objects_modified),
        )
    )
