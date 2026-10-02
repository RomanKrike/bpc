import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "candidate", ROOT / "scripts/verify-mesh-candidate.py")
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


def bundle(tmp_path, sha="a" * 40, health=0, extra=None):
    version = f"0.20.2-mesh.{sha}"
    files = {"VERSION": (version + "\n").encode(),
             "deploy/bpc-migrate.sh": b"#!/bin/sh\nexit 0\n",
             "deploy/bpc-healthcheck.sh": f"#!/bin/sh\nexit {health}\n".encode()}
    for binary in ("bpc-controld", "bpc-routed-node", "bpc-wgshim", "bpc-agent-relay"):
        for arch in ("amd64", "arm64"):
            files[f"bin/{binary}-linux-{arch}"] = b"binary fixture"
    for name in ("bpc-agent-windows-amd64.exe", "bpc-wgshim-windows-amd64.exe",
                 "wintun-windows-amd64.dll"):
        files[f"bin/{name}"] = b"Windows fixture"
    manifest = {"schema": 1, "channel": "mesh-test", "source_sha": sha,
                "version": version, "go_toolchain": "test", "live_acceptance": "pending",
                "files": {name: hashlib.sha256(data).hexdigest()
                          for name, data in files.items()}}
    files["CANDIDATE.json"] = json.dumps(manifest).encode()
    path = tmp_path / f"{sha}-{health}.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo("./" + name)
            member.mode = 0o755
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if extra:
            archive.addfile(extra)
    return path, hashlib.sha256(path.read_bytes()).hexdigest(), version


def test_verified_extract_and_reject_wrong_checksum(tmp_path):
    path, sha, version = bundle(tmp_path)
    destination = tmp_path / "extracted"
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        candidate.verify(path, "0" * 64, destination)
    assert not destination.exists()
    assert candidate.verify(path, sha, destination)["version"] == version
    assert (destination / "bin/bpc-controld-linux-arm64").stat().st_mode & 0o111


@pytest.mark.parametrize("name,kind", [("../outside", tarfile.REGTYPE),
                                       ("/outside", tarfile.REGTYPE),
                                       ("C:/outside", tarfile.REGTYPE),
                                       ("VERSION:stream", tarfile.REGTYPE),
                                       ("VERSION.", tarfile.REGTYPE),
                                       ("CON", tarfile.REGTYPE),
                                       ("link", tarfile.SYMTYPE),
                                       ("hard", tarfile.LNKTYPE),
                                       ("VERSION", tarfile.REGTYPE)])
def test_archive_escape_links_duplicates_rejected_before_extraction(tmp_path, name, kind):
    extra = tarfile.TarInfo(name)
    extra.type = kind
    extra.linkname = "/etc/passwd"
    path, sha, _ = bundle(tmp_path, extra=extra)
    with pytest.raises(ValueError):
        candidate.verify(path, sha, tmp_path / "extract")
    assert not (tmp_path / "extract").exists()


def test_file_directory_conflict_rejected_before_extraction(tmp_path):
    extra = tarfile.TarInfo("VERSION/child")
    path, sha, _ = bundle(tmp_path, extra=extra)
    with pytest.raises(ValueError, match="conflicts with a directory"):
        candidate.verify(path, sha, tmp_path / "extract")
    assert not (tmp_path / "extract").exists()


def test_manifest_tampering_rejected(tmp_path):
    path, _, _ = bundle(tmp_path)
    with tarfile.open(path) as archive:
        entries = [(member, archive.extractfile(member).read())
                   for member in archive.getmembers()]
    with tarfile.open(path, "w:gz") as archive:
        for member, data in entries:
            if member.name == "./bin/bpc-controld-linux-amd64":
                data = b"tampered"
                member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    with pytest.raises(ValueError, match="manifest mismatch"):
        candidate.verify(path, hashlib.sha256(path.read_bytes()).hexdigest())


@pytest.fixture
def installation(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("Updater requires root; all paths in this test are temporary")
    root = tmp_path / "root"
    previous = root / "releases/previous"
    previous.mkdir(parents=True)
    (previous / "VERSION").write_text("0.20.2\n")
    (root / "current").symlink_to(previous)
    state = tmp_path / "state"
    state.mkdir()
    (state / "raft-and-gateway").write_bytes(b"current committed state")
    env = {**os.environ, "BPC_ROOT": str(root), "BPC_STATE_DIR": str(state),
           "BPC_BACKUP_DIR": str(tmp_path / "backups")}
    return root, state, env


def update(env, path=None, sha=None):
    args = ["bash", str(ROOT / "deploy/bpc-update.sh")]
    if path:
        args += ["--bundle", str(path), "--sha256", sha]
    return subprocess.run(args, env=env, capture_output=True, text=True, timeout=15)


def test_local_update_idempotence_and_pinned_rollback_keep_state(tmp_path, installation):
    root, state, env = installation
    first, first_sha, _ = bundle(tmp_path)
    second, second_sha, _ = bundle(tmp_path, sha="b" * 40)
    assert update(env, first, first_sha).returncode == 0
    assert update(env).returncode == 2  # no stable-channel fallback
    assert update(env, first, first_sha).returncode == 0
    assert update(env, second, second_sha).returncode == 0
    (state / "raft-and-gateway").write_bytes(b"newer committed state")
    assert update(env, first, first_sha).returncode == 0
    assert (state / "raft-and-gateway").read_bytes() == b"newer committed state"
    (root / "current/VERSION").write_text("unexpected mutation")
    assert update(env, first, first_sha).returncode == 3


def test_failed_candidate_keeps_live_state_and_reports_previous(tmp_path, installation):
    root, state, env = installation
    path, sha, version = bundle(tmp_path, health=1)
    result = update(env, path, sha)
    assert result.returncode == 5
    assert "Previous release:" in result.stderr
    assert update(env, path, sha).returncode == 5
    assert (root / "current/VERSION").read_text().strip() == version
    assert (state / "raft-and-gateway").read_bytes() == b"current committed state"


def test_rejected_bundle_never_switches_release(tmp_path, installation):
    root, _, env = installation
    path, _, _ = bundle(tmp_path)
    assert update(env, path, "0" * 64).returncode == 2
    assert (root / "current").resolve().name == "previous"
