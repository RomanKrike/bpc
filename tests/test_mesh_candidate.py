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


def bundle(tmp_path, sha="a" * 40, health=0, extra=None, *, p2p=False, missing=None,
           stable=None, compatibility="mesh-raft-v1-p2p-v1"):
    version = stable or f"0.20.2-mesh.{sha}"
    files = {"VERSION": (version + "\n").encode(),
             "deploy/bpc-migrate.sh": b"#!/bin/sh\nexit 0\n",
             "deploy/bpc-healthcheck.sh": (
                 '#!/bin/sh\nif [ -n "${BPC_TEST_NEW_STATE:-}" ]; then\n'
                 '  printf %s "$BPC_TEST_NEW_STATE" > "$BPC_STATE_DIR/raft-and-gateway"\n'
                 f'fi\nexit {health}\n').encode()}
    for binary in ("bpc-controld", "bpc-routed-node", "bpc-wgshim", "bpc-agent-relay"):
        for arch in ("amd64", "arm64"):
            files[f"bin/{binary}-linux-{arch}"] = b"binary fixture"
    for name in ("bpc-agent-windows-amd64.exe", "bpc-wgshim-windows-amd64.exe",
                 "wintun-windows-amd64.dll"):
        files[f"bin/{name}"] = b"Windows fixture"
    if stable:
        files["deploy/bpc_topology.py"] = b"# synthetic topology fixture\n"
    if p2p or stable:
        files["deploy/bpc_p2p.py"] = b"# synthetic authority fixture\n"
        for arch in ("amd64", "arm64"):
            files[f"bin/bpc-p2p-relay-linux-{arch}"] = b"relay fixture"
    if missing:
        files.pop(missing)
    manifest = {"schema": 1, "channel": "stable" if stable else "mesh-test", "source_sha": sha,
                "version": version, "go_toolchain": "test", "live_acceptance": "pending",
                "compatibility": compatibility,
                "files": {name: hashlib.sha256(data).hexdigest()
                          for name, data in files.items()}}
    files["RELEASE.json" if stable else "CANDIDATE.json"] = json.dumps(manifest).encode()
    path = tmp_path / f"{version}-{health}.tar.gz"
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
    binary = destination / "bin/bpc-controld-linux-arm64"
    assert binary.read_bytes() == b"binary fixture"
    if os.name == "posix":
        assert binary.stat().st_mode & 0o111


@pytest.mark.parametrize("missing", [None, "bin/bpc-p2p-relay-linux-amd64",
                                    "bin/bpc-p2p-relay-linux-arm64"])
def test_p2p_candidate_requires_both_relay_runtimes(tmp_path, missing):
    path, sha, _ = bundle(tmp_path, p2p=True, missing=missing)
    destination = tmp_path / "verified"
    if missing:
        with pytest.raises(ValueError, match="Incomplete candidate runtime"):
            candidate.verify(path, sha, destination)
        assert not destination.exists()
    else:
        candidate.verify(path, sha, destination)
        assert (destination / "bin/bpc-p2p-relay-linux-arm64").is_file()


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
    if os.name != "posix" or os.geteuid() != 0:
        pytest.skip("Updater requires POSIX root; all paths in this test are temporary")
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


def mock_download(tmp_path, env, path):
    """Exercise the network-update path entirely within the temporary fixture."""
    stub = tmp_path / "download-stubs"
    stub.mkdir(exist_ok=True)
    checksums = tmp_path / "SHA256SUMS"
    checksums.write_text(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
                        "bpc-connect-deploy.tar.gz\n")
    script = stub / "curl"
    script.write_text('''#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --*) shift ;;
    -o) output="$2"; shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  */SHA256SUMS) cp "$BPC_TEST_SUMS" "$output" ;;
  */bpc-connect-deploy.tar.gz) cp "$BPC_TEST_BUNDLE" "$output" ;;
  *) exit 91 ;;
esac
''')
    script.chmod(0o755)
    # A missing test dependency must fail the fixture, never install host packages.
    apt = stub / "apt-get"
    apt.write_text("#!/bin/sh\nexit 92\n")
    apt.chmod(0o755)
    env.update(PATH=str(stub) + os.pathsep + env["PATH"],
               BPC_TEST_SUMS=str(checksums), BPC_TEST_BUNDLE=str(path))


@pytest.mark.parametrize("current,target,compatibility,missing,ok", [
    ("0.20.2-mesh." + "a" * 40, "0.22.0", "mesh-raft-v1-p2p-v1", None, True),
    ("0.22.0-mesh." + "a" * 40, "0.22.0", "mesh-raft-v1-p2p-v1", None, True),
    ("0.22.0", "0.22.1", "mesh-raft-v1-p2p-v1", None, True),
    ("0.22.1", "0.22.0", "mesh-raft-v1-p2p-v1", None, False),
    ("0.20.2", "0.21.0", "mesh-raft-v1-p2p-v1", None, False),
    ("0.22.0", "0.22.1", "unknown", None, False),
    ("garbage", "0.22.0", "mesh-raft-v1-p2p-v1", None, False),
    ("0.22.0", "0.22.1", "mesh-raft-v1-p2p-v1", "bin/bpc-routed-node-linux-arm64", False),
    ("0.22.0", "0.22.1", "mesh-raft-v1-p2p-v1", "bin/bpc-p2p-relay-linux-amd64", False),
])
def test_stable_compatibility_and_downgrade_guard(tmp_path, current, target,
                                               compatibility, missing, ok):
    path, sha, _ = bundle(tmp_path, stable=target, compatibility=compatibility,
                          missing=missing)
    destination = tmp_path / "extract"
    if ok:
        assert candidate.verify(path, sha, destination, stable_from=current)["version"] == target
    else:
        with pytest.raises((ValueError, KeyError)):
            candidate.verify(path, sha, destination, stable_from=current)
        assert not destination.exists()


def test_bridge_then_bare_stable_updates_preserve_state(tmp_path, installation):
    root, state, env = installation
    bridge, bridge_sha, _ = bundle(tmp_path)
    assert update(env, bridge, bridge_sha).returncode == 0
    stable, _, _ = bundle(tmp_path, stable="0.22.0")
    mock_download(tmp_path, env, stable)
    result = update(env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (root / "current/VERSION").read_text().strip() == "0.22.0"
    assert (root / "current/RELEASE.json").is_file()
    assert not (root / "current/CANDIDATE.json").exists()
    assert update(env).returncode == 0
    # The stable updater will no longer accept a pinned old candidate either.
    assert update(env, bridge, bridge_sha).returncode == 2
    assert (state / "raft-and-gateway").read_bytes() == b"current committed state"
    with tarfile.open(next((tmp_path / "backups").glob("*0.20.2-mesh*"))) as backup:
        assert backup.extractfile("state/raft-and-gateway").read() == b"current committed state"
    newer, _, _ = bundle(tmp_path, stable="0.22.1", health=1)
    mock_download(tmp_path, env, newer)
    env["BPC_TEST_NEW_STATE"] = "new committed security state"
    result = update(env)
    assert result.returncode == 5, result.stdout + result.stderr
    assert "Previous release:" in result.stderr
    assert (root / "current/VERSION").read_text().strip() == "0.22.1"
    assert (state / "raft-and-gateway").read_bytes() == b"new committed security state"
    mock_download(tmp_path, env, stable)
    assert update(env).returncode == 2  # no DB or release rewind on a retry
    assert (root / "current/VERSION").read_text().strip() == "0.22.1"


@pytest.mark.parametrize("options", [
    {"stable": "0.21.0"},
    {"stable": "0.22.1", "compatibility": "unknown"},
    {"stable": "0.22.1", "missing": "bin/bpc-routed-node-linux-amd64"},
])
def test_rejected_network_release_does_not_activate(tmp_path, installation, options):
    root, state, env = installation
    (root / "current/VERSION").write_text("0.22.0\n")
    path, _, _ = bundle(tmp_path, **options)
    mock_download(tmp_path, env, path)
    result = update(env)
    assert result.returncode == 2, result.stdout + result.stderr
    assert (root / "current").resolve().name == "previous"
    assert (state / "raft-and-gateway").read_bytes() == b"current committed state"


def test_local_update_idempotence_and_pinned_rollback_keep_state(tmp_path, installation):
    root, state, env = installation
    first, first_sha, _ = bundle(tmp_path)
    second, second_sha, _ = bundle(tmp_path, sha="b" * 40)
    assert update(env, first, first_sha).returncode == 0
    # A network response lacking unified compatibility proof is still refused.
    mock_download(tmp_path, env, first)
    assert update(env).returncode == 2
    assert update(env, first, first_sha).returncode == 0
    assert update(env, second, second_sha).returncode == 0
    (state / "raft-and-gateway").write_bytes(b"newer committed state")
    assert update(env, first, first_sha).returncode == 0
    assert (state / "raft-and-gateway").read_bytes() == b"newer committed state"
    (root / "current/VERSION").write_text("unexpected mutation")
    assert update(env, first, first_sha).returncode == 3


def test_local_update_through_command_symlink(tmp_path, installation):
    root, state, env = installation
    command = tmp_path / "sbin/bpc-update"
    command.parent.mkdir()
    command.symlink_to(ROOT / "deploy/bpc-update.sh")
    path, sha, version = bundle(tmp_path)
    result = subprocess.run(
        ["bash", str(command), "--bundle", str(path), "--sha256", sha],
        env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (root / "current/VERSION").read_text().strip() == version
    assert (state / "raft-and-gateway").read_bytes() == b"current committed state"


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


def agent_update_environment(tmp_path, candidate_release):
    root = tmp_path / "root"
    current = root / "current"
    current.mkdir(parents=True)
    (current / "VERSION").write_text("0.20.2-mesh." + "a" * 40 if candidate_release
                                    else "0.20.2")
    if candidate_release:
        (current / "CANDIDATE.json").write_text('{"channel":"mesh-test"}')
    state = tmp_path / "state"
    control = state / "control"
    updates = control / "update"
    updates.mkdir(parents=True)
    (updates / "manifest.json").write_bytes(b"existing signed stable manifest")
    (updates / "bpc-agent.exe").write_bytes(b"existing stable executable")
    env = {**os.environ, "BPC_ROOT": str(root), "BPC_STATE_DIR": str(state)}
    return current, control, updates, env


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0,
                    reason="Agent command requires POSIX root")
@pytest.mark.parametrize("options,code", [
    (["--automatic"], 0),
    ([], 2),
    (["--version", "0.20.2", "--file", "/missing/agent.exe"], 2),
])
def test_candidate_agent_publication_preserves_stable_channel(tmp_path, options, code):
    _, _, updates, env = agent_update_environment(tmp_path, True)
    before = {p.name: p.read_bytes() for p in updates.iterdir()}
    result = subprocess.run(
        ["bash", str(ROOT / "deploy/bpc-agent.sh"), "publish-update", *options],
        env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == code, result.stderr
    assert "Mesh candidate:" in result.stdout + result.stderr
    assert {p.name: p.read_bytes() for p in updates.iterdir()} == before


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0,
                    reason="Agent command requires POSIX root")
@pytest.mark.parametrize("options", [[], ["--automatic"]])
def test_stable_agent_publication_still_signs_update(tmp_path, options):
    current, control, updates, env = agent_update_environment(tmp_path, False)
    (control / "enabled").touch()
    (control / "runtime.env").write_text("CONTROL_HOST=example.test\nCONTROL_PORT=8444\n")
    binaries = current / "bin"
    binaries.mkdir()
    executable = b"stable agent executable"
    (binaries / "bpc-agent-windows-amd64.exe").write_bytes(executable)
    stub = tmp_path / "stubs"
    stub.mkdir()
    (stub / "systemctl").write_text("#!/bin/sh\nexit 0\n")
    (stub / "systemctl").chmod(0o755)
    env["PATH"] = str(stub) + os.pathsep + env["PATH"]
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out",
                    str(control / "update-signing-key.pem")], check=True, capture_output=True)
    result = subprocess.run(
        ["bash", str(ROOT / "deploy/bpc-agent.sh"), "publish-update", *options],
        env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    manifest = json.loads((updates / "manifest.json").read_text())
    assert manifest["version"] == "0.20.2"
    assert manifest["sha256"] == hashlib.sha256(executable).hexdigest()
    assert manifest["signature"]
    assert (updates / "bpc-agent.exe").read_bytes() == executable
