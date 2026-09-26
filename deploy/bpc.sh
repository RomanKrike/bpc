#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
ENROLL="${BPC_ROOT}/current/deploy/bpc_node_enrollment.py"
IDENTITY="${BPC_ROOT}/current/deploy/bpc_identity.py"
CONTROL_DIR="${BPC_STATE_DIR}/ru-node/control"

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
  bpc user add USER [--password-stdin]
  bpc user disable USER
  bpc device list
  bpc device revoke DEVICE

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

require_identity_helper() {
  if [[ ! -f "${IDENTITY}" ]]; then
    echo "BPC identity helper is missing: ${IDENTITY}" >&2
    exit 3
  fi
}

scope="${1:-}"

# All Node management commands touch root-owned state or systemd. Preserve the
# target UX ("bpc join ...") by elevating once here rather than requiring the
# user to remember which subcommands need sudo.
if [[ ${EUID} -ne 0 && -n "${scope}" && "${scope}" != "-h" && "${scope}" != "--help" && "${scope}" != "help" ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo "$0" "$@"
  fi
  echo "BPC Node management requires root privileges and sudo is unavailable." >&2
  exit 1
fi

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
  user)
    shift
    require_identity_helper
    case "${1:-}" in
      add)
        shift
        exec python3 "${IDENTITY}" --state-dir "${CONTROL_DIR}" user-add "$@"
        ;;
      disable)
        shift
        exec python3 "${IDENTITY}" --state-dir "${CONTROL_DIR}" user-disable "$@"
        ;;
      *)
        usage >&2
        exit 2
        ;;
    esac
    ;;
  device)
    shift
    require_identity_helper
    case "${1:-}" in
      list)
        shift
        exec python3 "${IDENTITY}" --state-dir "${CONTROL_DIR}" device-list "$@"
        ;;
      revoke)
        shift
        exec python3 "${IDENTITY}" --state-dir "${CONTROL_DIR}" device-revoke "$@"
        ;;
      *)
        usage >&2
        exit 2
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
