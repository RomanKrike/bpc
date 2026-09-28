from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
TOKEN = "BPC-aHR0cHM6Ly9hLmI." + "a" * 64


def executable(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/bash\nset -eu\n" + content)
    path.chmod(0o755)


def run_isolated_bootstrap(env):
    command = ["bash", str(ROOT / "install.sh"), "join", TOKEN]
    if os.geteuid() != 0:
        # CI's runner is unprivileged. Elevate only this subprocess, whose
        # package/network/mutation commands are replaced by temporary stubs.
        command = ["sudo", "-n", "env",
                   *[f"{key}={env[key]}" for key in ("PATH", "BPC_ROOT", "BPC_STATE_DIR")],
                   *command]
    return subprocess.run(command, env=env, capture_output=True, text=True)


def test_bootstrap_repeat_preserves_release_and_resumes_join(tmp_path):
    current = tmp_path / "bpc" / "current"
    current.mkdir(parents=True)
    (current / "VERSION").write_text("0.18.4")
    executable(current / "deploy" / "bpc.sh", 'printf "%s\\n" "$@"\n')
    mockbin = tmp_path / "bin"
    for command in ("curl", "apt-get", "systemctl", "ln"):
        executable(mockbin / command, 'echo "unexpected mutation" >&2; exit 99\n')
    env = {**os.environ, "BPC_ROOT": str(current.parent),
           "BPC_STATE_DIR": str(tmp_path / "state"),
           "PATH": f'{mockbin}:{os.environ["PATH"]}'}
    result = run_isolated_bootstrap(env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["join", TOKEN]
    assert (current / "VERSION").read_text() == "0.18.4"


@pytest.mark.parametrize("token", ["BPC-bad", "", TOKEN + ";touch /tmp/never", TOKEN + "\n"])
def test_invalid_bootstrap_token_fails_before_install(token):
    result = subprocess.run(["bash", str(ROOT / "install.sh"), "join", token],
                            capture_output=True, text=True)
    assert result.returncode == 2
    assert "Usage:" in result.stderr


def test_bootstrap_rejects_corrupt_bundle_before_activation(tmp_path):
    mockbin = tmp_path / "bin"
    for command in ("apt-get", "getent"):
        executable(mockbin / command, "exit 0\n")
    executable(mockbin / "curl", '''
url=""; out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    https://*) url="$1"; shift ;;
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
case "$url" in
  */releases/latest) printf '{"tag_name":"v0.19.0"}' > "$out" ;;
  */v0.19.0/bpc-connect-deploy.tar.gz) printf corrupt > "$out" ;;
  */v0.19.0/SHA256SUMS) printf '%064d  bpc-connect-deploy.tar.gz\\n' 0 > "$out" ;;
  *) exit 98 ;;
esac
''')
    executable(mockbin / "tar", 'echo "unverified archive extracted" >&2; exit 99\n')
    target = tmp_path / "bpc"
    result = run_isolated_bootstrap({
        **os.environ, "BPC_ROOT": str(target), "BPC_STATE_DIR": str(tmp_path / "state"),
        "PATH": f'{mockbin}:{os.environ["PATH"]}',
    })
    assert result.returncode != 0
    assert "FAILED" in result.stdout
    assert "unverified archive extracted" not in result.stderr
    assert not target.exists()
