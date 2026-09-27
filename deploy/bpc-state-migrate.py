#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bpc_connect.compat.migration import format_report, migrate_canonical_state  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate BPC-owned state to canonical layout")
    parser.add_argument("--state-dir", type=Path, default=Path("/etc/bpc-connect"))
    args = parser.parse_args()
    report = migrate_canonical_state(args.state_dir)
    print(format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
