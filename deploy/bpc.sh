#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
ENROLL="${BPC_ROOT}/current/deploy/bpc_node_enrollment.py"

usage() {
  cat <<'USAGE'
Usage:
  bpc join <TOKEN>
  bpc status
  bpc leave [--force]
  bpc node info
  bpc node status
  bpc node token create --roles ROLE[,ROLE...] [--name NAME] [--expires 15m]
  bpc node list

Compatibility:
  Existing standalone commands such as bpc-status, bpc-update and bpc-node
  remain available.
USAGE
}

require_enrollment_helper() {
  if [[ ! -f "${ENROLL}" ]]; then
    echo "BPC Node enrollment helper is missing: ${ENROLL}" >&2
    exit 3
  fi
}

scope="${1:-}"
case "${scope}" in
  join)
    require_enrollment_helper
    shift
    exec python3 "${ENROLL}" --state-dir "${BPC_STATE_DIR}" join "$@"
    ;;
  status)
    require_enrollment_helper
    shift
    python3 "${ENROLL}" --state-dir "${BPC_STATE_DIR}" status || true
    exec "${BPC_ROOT}/current/deploy/bpc-node.sh" status
    ;;
  leave)
    require_enrollment_helper
    shift
    exec python3 "${ENROLL}" --state-dir "${BPC_STATE_DIR}" leave "$@"
    ;;
  node)
    shift
    case "${1:-}" in
      token)
        if [[ "${2:-}" != "create" ]]; then
          usage >&2
          exit 2
        fi
        require_enrollment_helper
        shift 2
        exec python3 "${ENROLL}" --state-dir "${BPC_STATE_DIR}" token-create "$@"
        ;;
      list)
        require_enrollment_helper
        shift
        exec python3 "${ENROLL}" --state-dir "${BPC_STATE_DIR}" list "$@"
        ;;
      *)
        exec "${BPC_ROOT}/current/deploy/bpc-node.sh" "$@"
        ;;
    esac
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
