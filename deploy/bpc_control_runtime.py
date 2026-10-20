"""Prepare mutable API state outside versioned Node runtime directories."""
from __future__ import annotations

import argparse
import os
from pathlib import Path


def prepare_control_runtime(
    state_dir: Path, release_root: Path,
    *, systemd_dir: Path = Path("/etc/systemd/system"),
) -> None:
    telemetry = state_dir / "runtime-topology"
    telemetry.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(telemetry, 0o700)
    # Remove only the exact temporary repairs supplied for mesh-test-2.
    # The new installer stages topology itself and grants its stable directory.
    known = {
        "30-topology-runtime.conf": (
            f"[Service]\nReadWritePaths={state_dir}/runtime/topology\n"
        ),
        "40-topology-module.conf": (
            "[Service]\nExecStartPre=/usr/bin/install -m 0600 "
            f"{release_root}/current/deploy/bpc_topology.py "
            f"{state_dir}/control/runtime/bpc_topology.py\n"
        ),
    }
    for name, content in known.items():
        path = systemd_dir / "bpc-control.service.d" / name
        if path.is_file() and not path.is_symlink() and path.read_text() == content:
            path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--release-root", type=Path, required=True)
    args = parser.parse_args()
    prepare_control_runtime(args.state_dir, args.release_root)


if __name__ == "__main__":
    main()
