#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"

usage() {
  cat <<'USAGE'
Usage:
  bpc node status
  bpc node info

Compatibility:
  Existing standalone commands such as bpc-status, bpc-update and bpc-node
  remain available.
USAGE
}

scope="${1:-}"
case "${scope}" in
  node)
    shift
    exec "${BPC_ROOT}/current/deploy/bpc-node.sh" "$@"
    ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    echo "Unknown BPC command: ${scope}" >&2
    usage >&2
    exit 2
    ;;
esac
