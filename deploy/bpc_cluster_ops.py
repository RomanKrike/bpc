#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

LOCAL_API = "http://127.0.0.1:9446"
MAX_RESPONSE = 128 * 1024 * 1024


class ClusterOpsError(RuntimeError):
    pass


def _read_token(state_dir: Path) -> str:
    path = state_dir / "cluster" / "local-api.token"
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ClusterOpsError(f"local Controller API token unavailable: {exc}") from exc
    if len(token) != 64:
        raise ClusterOpsError("invalid local Controller API token")
    try:
        int(token, 16)
    except ValueError as exc:
        raise ClusterOpsError("invalid local Controller API token") from exc
    return token


def _request(
    state_dir: Path,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
) -> bytes:
    data = None
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {_read_token(state_dir)}",
    }
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        LOCAL_API + path,
        data=data,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        detail = exc.read(8192).decode("utf-8", errors="replace")
        try:
            parsed = json.loads(detail)
            detail = str(parsed.get("error", detail))
        except (ValueError, json.JSONDecodeError):
            pass
        raise ClusterOpsError(f"Controller API HTTP {exc.code}: {detail}") from exc
    except OSError as exc:
        raise ClusterOpsError(f"distributed Controller unavailable: {exc}") from exc
    if len(raw) > MAX_RESPONSE:
        raise ClusterOpsError("Controller API response is too large")
    return raw


def _request_json(
    state_dir: Path,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    raw = _request(state_dir, method, path, body)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ClusterOpsError("Controller API returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ClusterOpsError("Controller API returned invalid response")
    return value


def cluster_status(state_dir: Path) -> dict[str, Any]:
    return _request_json(state_dir, "GET", "/v1/status")


def _status_body(status: dict[str, Any]) -> dict[str, Any]:
    value = status.get("status", {})
    if not isinstance(value, dict):
        raise ClusterOpsError("Controller status payload is malformed")
    return value


def cmd_status(args: argparse.Namespace) -> int:
    response = cluster_status(args.state_dir)
    status = _status_body(response)
    members = status.get("members", [])
    if not isinstance(members, list):
        members = []
    voters = int(status.get("voters", 0))
    quorum = int(status.get("quorum", 0))
    healthy = int(response.get("healthy_controller_count", 0))
    state = "healthy"
    if voters and healthy < quorum:
        state = "no-quorum"
    elif healthy < voters:
        state = "degraded"

    print(f"Cluster ID: {response.get('cluster_id', '-')}")
    print(f"State: {state}")
    print(f"Leader: {status.get('leader_id') or '-'}")
    print(f"Raft role: {status.get('raft_role', '-')}")
    print(f"Quorum: {healthy}/{voters} (required {quorum})")
    print(f"Term: {status.get('term', 0)}")
    print(f"Commit index: {status.get('commit_index', 0)}")
    print(f"Last applied: {status.get('last_applied', 0)}")
    print(f"Revision: {status.get('revision', 0)}")
    print(f"State schema: {status.get('state_schema_version', 0)}")
    print(f"Protocol: {status.get('protocol_version', 0)}")
    print(f"Snapshot index: {status.get('snapshot_index', 0)}")
    print(f"Replication lag: {status.get('replication_lag', 0)}")
    print("Controllers:")
    health_map = response.get("controller_health", {})
    if not isinstance(health_map, dict):
        health_map = {}
    for member in members:
        if not isinstance(member, dict):
            continue
        node_id = str(member.get("id", ""))
        peer = health_map.get(node_id, {})
        if not isinstance(peer, dict):
            peer = {}
        role = "leader" if node_id == status.get("leader_id") else "follower"
        online = (
            "online"
            if bool(peer.get("healthy", node_id == status.get("node_id")))
            else "offline"
        )
        print(
            f"  {node_id}\t{role}\t{online}\t"
            f"{member.get('suffrage', '-')}"
        )
    return 0


def cmd_members(args: argparse.Namespace) -> int:
    response = cluster_status(args.state_dir)
    status = _status_body(response)
    health = response.get("controller_health", {})
    if not isinstance(health, dict):
        health = {}
    for member in status.get("members", []):
        if not isinstance(member, dict):
            continue
        node_id = str(member.get("id", ""))
        peer = health.get(node_id, {})
        if not isinstance(peer, dict):
            peer = {}
        leader = node_id == status.get("leader_id")
        online = (
            "online"
            if bool(peer.get("healthy", node_id == status.get("node_id")))
            else "offline"
        )
        print(
            f"{node_id}\t"
            f"{'leader' if leader else 'follower'}\t"
            f"{online}\t"
            f"{member.get('suffrage', '-')}"
        )
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    response = cluster_status(args.state_dir)
    status = _status_body(response)
    target = args.node.strip()
    members = [
        item
        for item in status.get("members", [])
        if isinstance(item, dict)
        and (str(item.get("id", "")) == target or str(item.get("name", "")) == target)
    ]
    node_id = str(members[0].get("id", "")) if members else target
    voters = int(status.get("voters", 0))
    if voters <= 2 and not args.force:
        raise ClusterOpsError(
            "refusing to remove a Controller when the cluster has two or fewer voters; "
            "repeat with --force only for disaster recovery"
        )
    result = _request_json(
        args.state_dir,
        "POST",
        "/v1/members/remove",
        {"node_id": node_id, "force": bool(args.force)},
    )
    print(
        f"Controller removed: {node_id} "
        f"(revision {result.get('revision', '-')})"
    )
    return 0


def _tar_add_bytes(archive: tarfile.TarFile, name: str, raw: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(raw)
    info.mode = mode
    info.mtime = 0
    archive.addfile(info, io.BytesIO(raw))


def cmd_backup(args: argparse.Namespace) -> int:
    _request_json(args.state_dir, "POST", "/v1/snapshot", {})
    status_response = cluster_status(args.state_dir)
    status = _status_body(status_response)
    raw_snapshot = _request(args.state_dir, "GET", "/v1/export")
    digest = hashlib.sha256(raw_snapshot).hexdigest()
    cluster_id = str(status_response.get("cluster_id", "")).strip()
    if not cluster_id:
        raise ClusterOpsError("cluster_id is missing from Controller status")
    created_at = int(time.time())
    metadata = {
        "backup_version": 1,
        "cluster_id": cluster_id,
        "created_at": created_at,
        "revision": int(status.get("revision", 0)),
        "commit_index": int(status.get("commit_index", 0)),
        "state_schema_version": int(status.get("state_schema_version", 0)),
        "protocol_version": int(status.get("protocol_version", 0)),
        "snapshot_sha256": digest,
        "contains_private_node_identity": False,
    }

    output = args.output
    if output is None:
        output = (
            args.state_dir
            / "backups"
            / f"cluster-{created_at}-r{metadata['revision']}.tar.gz"
        )
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output.parent, 0o700)
    tmp = output.with_name(f".{output.name}.tmp")
    with tarfile.open(tmp, "w:gz") as archive:
        _tar_add_bytes(
            archive,
            "metadata.json",
            (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode("utf-8"),
            0o600,
        )
        _tar_add_bytes(archive, "canonical-snapshot.json", raw_snapshot, 0o600)
        ca_path = args.state_dir / "cluster" / "pki" / "cluster-ca.crt"
        if ca_path.is_file():
            _tar_add_bytes(archive, "cluster-ca.crt", ca_path.read_bytes(), 0o644)
    os.chmod(tmp, 0o600)
    os.replace(tmp, output)
    print(f"Cluster backup created: {output}")
    print(f"Cluster ID: {cluster_id}")
    print(f"Revision: {metadata['revision']}")
    print(f"SHA256: {digest}")
    print("Private Node identity keys included: NO")
    return 0


def _read_backup(path: Path) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    try:
        with tarfile.open(path, "r:gz") as archive:
            names = set(archive.getnames())
            if not {"metadata.json", "canonical-snapshot.json"} <= names:
                raise ClusterOpsError("cluster backup is incomplete")
            metadata_file = archive.extractfile("metadata.json")
            snapshot_file = archive.extractfile("canonical-snapshot.json")
            if metadata_file is None or snapshot_file is None:
                raise ClusterOpsError("cluster backup is incomplete")
            metadata_raw = metadata_file.read()
            snapshot_raw = snapshot_file.read()
    except (OSError, tarfile.TarError) as exc:
        raise ClusterOpsError(f"failed to open cluster backup: {exc}") from exc
    try:
        metadata = json.loads(metadata_raw)
        snapshot = json.loads(snapshot_raw)
    except json.JSONDecodeError as exc:
        raise ClusterOpsError("cluster backup contains invalid JSON") from exc
    if not isinstance(metadata, dict) or not isinstance(snapshot, dict):
        raise ClusterOpsError("cluster backup payload is invalid")
    expected = str(metadata.get("snapshot_sha256", "")).lower()
    actual = hashlib.sha256(snapshot_raw).hexdigest()
    if expected != actual:
        raise ClusterOpsError("cluster backup checksum mismatch")
    return metadata, snapshot, snapshot_raw


def cmd_restore(args: argparse.Namespace) -> int:
    metadata, snapshot, _ = _read_backup(Path(args.backup))
    cluster_id = str(metadata.get("cluster_id", "")).strip()
    if not cluster_id:
        raise ClusterOpsError("backup cluster_id is missing")
    if args.confirm != cluster_id:
        raise ClusterOpsError(
            "destructive restore confirmation mismatch; "
            f"repeat with --confirm {cluster_id}"
        )
    result = _request_json(
        args.state_dir,
        "POST",
        "/v1/restore",
        {
            "cluster_id": cluster_id,
            "snapshot": snapshot,
            "force": bool(args.force),
        },
    )
    print(f"Cluster restore committed: revision {result.get('revision', '-')}")
    print("Restart Controllers one at a time after verifying cluster health.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BPC distributed cluster operations")
    parser.add_argument("--state-dir", type=Path, default=Path("/etc/bpc-connect"))
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status")
    sub.add_parser("members")

    remove = sub.add_parser("remove")
    remove.add_argument("node")
    remove.add_argument("--force", action="store_true")

    backup = sub.add_parser("backup")
    backup.add_argument("--output", type=Path)

    restore = sub.add_parser("restore")
    restore.add_argument("backup", type=Path)
    restore.add_argument("--confirm", required=True)
    restore.add_argument("--force", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "status":
            return cmd_status(args)
        if args.command == "members":
            return cmd_members(args)
        if args.command == "remove":
            return cmd_remove(args)
        if args.command == "backup":
            return cmd_backup(args)
        if args.command == "restore":
            return cmd_restore(args)
    except (ClusterOpsError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
