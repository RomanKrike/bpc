#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
NODE_MODEL="${BPC_ROOT}/current/deploy/bpc-node-model.py"
COMPAT="${BPC_ROOT}/current/deploy/bpc-compat.py"

usage() {
  cat <<'USAGE'
Usage:
  bpc-node status
  bpc-node info

Legacy read-only compatibility:
  bpc-node gateway list

The old BP Gateway write workflow is retired. Site routing is represented by a
Node with the site_router capability. Route transport/provisioning is deferred
to the site-router stage.
USAGE
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    echo "Run bpc-node as root" >&2
    exit 1
  fi
}

require_node_model() {
  if [[ ! -f "${NODE_MODEL}" ]]; then
    echo "BPC node model helper is missing: ${NODE_MODEL}" >&2
    exit 3
  fi
}

legacy_write_disabled() {
  cat >&2 <<'MSG'
WARNING:
Legacy BP Gateway write workflow is deprecated and disabled.
Use a Node with the site_router capability. New route advertisement/provisioning
will use the canonical Node model rather than Device records.
MSG
  exit 2
}

require_root
scope="${1:-}"

case "${scope}" in
  status)
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    require_node_model
    exec python3 "${NODE_MODEL}" --state-dir "${BPC_STATE_DIR}" status
    ;;
  info)
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    require_node_model
    exec python3 "${NODE_MODEL}" --state-dir "${BPC_STATE_DIR}" info
    ;;
  gateway)
    command="${2:-}"
    case "${command}" in
      list)
        [[ $# -eq 2 ]] || { usage >&2; exit 2; }
        if [[ ! -f "${COMPAT}" ]]; then
          echo "BPC compatibility helper is missing: ${COMPAT}" >&2
          exit 3
        fi
        exec python3 "${COMPAT}" --state-dir "${BPC_STATE_DIR}" gateway-list
        ;;
      create|grant|ungrant|remove)
        legacy_write_disabled
        ;;
      -h|--help|help|"")
        usage
        ;;
      *)
        echo "Unknown gateway command: ${command}" >&2
        usage >&2
        exit 2
        ;;
    esac
    ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    echo "Unknown bpc-node command: ${scope}" >&2
    usage >&2
    exit 2
    ;;
esac
