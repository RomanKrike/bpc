from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from .config import load_gateway_config
from .errors import BPCConfigError
from .mihomo import assert_fail_closed, render_mihomo


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bpc-connect")
    sub = parser.add_subparsers(dest="command", required=True)

    render = sub.add_parser("render", help="Render a Mihomo gateway configuration")
    render.add_argument("config", type=Path)
    render.add_argument("--output", "-o", type=Path)

    validate = sub.add_parser("validate", help="Validate BPC source configuration")
    validate.add_argument("config", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        config = load_gateway_config(args.config)
        document = render_mihomo(config)
        assert_fail_closed(document)
        if args.command == "validate":
            print("OK: configuration is valid and fail-closed")
            return 0
        text = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
        return 0
    except (BPCConfigError, OSError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
