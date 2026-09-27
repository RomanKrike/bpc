#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bpc_connect.compat.migration import format_report, migrate_canonical_state  # noqa: E402
from bpc_connect.identity import ensure_node_identity  # noqa: E402
from bpc_connect.state import StateLayout  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate BPC-owned state to canonical layout")
    parser.add_argument("--state-dir", type=Path, default=Path("/etc/bpc-connect"))
    args = parser.parse_args()

    try:
        report = migrate_canonical_state(args.state_dir)
        state = StateLayout.from_root(args.state_dir)
        identity = ensure_node_identity(state.root) if state.node_config.is_file() else None
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(format_report(report))
    if identity is not None:
        status = "repaired" if identity.changed else "verified"
        print(f"Node identity: {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
