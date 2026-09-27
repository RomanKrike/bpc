from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "deploy"))

import bpc_cluster_ops as ops  # noqa: E402


def test_cluster_backup_contains_no_private_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    pki = state / "cluster" / "pki"
    pki.mkdir(parents=True)
    (pki / "cluster-ca.crt").write_text("PUBLIC CERT", encoding="utf-8")
    (pki / "cluster-ca.key").write_text("PRIVATE CA KEY", encoding="utf-8")
    (pki / "controller.key").write_text("PRIVATE NODE KEY", encoding="utf-8")

    snapshot = {
        "version": 1,
        "schema_version": 1,
        "revision": 9,
        "entries": {},
        "checksum": "test",
    }
    raw_snapshot = json.dumps(snapshot, separators=(",", ":")).encode("utf-8")

    def fake_json(
        _state: Path,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
    ) -> dict[str, object]:
        del body
        if method == "POST" and path == "/v1/snapshot":
            return {"ok": True}
        if method == "GET" and path == "/v1/status":
            return {
                "cluster_id": "cluster-test",
                "status": {
                    "revision": 9,
                    "commit_index": 12,
                    "state_schema_version": 1,
                    "protocol_version": 1,
                },
            }
        raise AssertionError((method, path))

    def fake_request(
        _state: Path,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
    ) -> bytes:
        del body
        assert (method, path) == ("GET", "/v1/export")
        return raw_snapshot

    monkeypatch.setattr(ops, "_request_json", fake_json)
    monkeypatch.setattr(ops, "_request", fake_request)

    output = tmp_path / "backup.tar.gz"
    args = ops.argparse.Namespace(state_dir=state, output=output)
    assert ops.cmd_backup(args) == 0

    with tarfile.open(output, "r:gz") as archive:
        names = set(archive.getnames())
        assert names == {
            "metadata.json",
            "canonical-snapshot.json",
            "cluster-ca.crt",
        }
        payload = io.BytesIO()
        for name in names:
            handle = archive.extractfile(name)
            assert handle is not None
            payload.write(handle.read())
    raw = payload.getvalue()
    assert b"PRIVATE CA KEY" not in raw
    assert b"PRIVATE NODE KEY" not in raw


def test_restore_requires_exact_cluster_confirmation(tmp_path: Path) -> None:
    metadata = {
        "backup_version": 1,
        "cluster_id": "cluster-test",
    }
    snapshot = {
        "version": 1,
        "schema_version": 1,
        "revision": 1,
        "entries": {},
        "checksum": "x",
    }
    raw_snapshot = json.dumps(snapshot).encode("utf-8")
    import hashlib

    metadata["snapshot_sha256"] = hashlib.sha256(raw_snapshot).hexdigest()
    backup = tmp_path / "backup.tar.gz"
    with tarfile.open(backup, "w:gz") as archive:
        for name, raw in (
            ("metadata.json", json.dumps(metadata).encode("utf-8")),
            ("canonical-snapshot.json", raw_snapshot),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))

    args = ops.argparse.Namespace(
        state_dir=tmp_path / "state",
        backup=backup,
        confirm="wrong-cluster",
        force=False,
    )
    with pytest.raises(ops.ClusterOpsError, match="confirmation mismatch"):
        ops.cmd_restore(args)
