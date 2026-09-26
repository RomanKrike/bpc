#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bpc_connect.state import StateLayout  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve canonical BPC state paths")
    parser.add_argument("--state-dir", type=Path, default=Path("/etc/bpc-connect"))
    parser.add_argument(
        "key",
        choices=(
            "root",
            "node",
            "identity",
            "cluster",
            "control",
            "runtime",
            "transports",
            "compat",
            "backups",
        ),
    )
    args = parser.parse_args()
    state = StateLayout.from_root(args.state_dir)
    values = {
        "root": state.root,
        "node": state.node_config,
        "identity": state.identity_dir,
        "cluster": state.cluster_dir,
        "control": state.control_dir,
        "runtime": state.runtime_dir,
        "transports": state.transport_dir,
        "compat": state.compat_dir,
        "backups": state.backups_dir,
    }
    print(values[args.key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
