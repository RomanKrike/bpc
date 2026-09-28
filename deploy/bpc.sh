#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
ENROLL="${BPC_ROOT}/current/deploy/bpc_node_enrollment.py"
IDENTITY="${BPC_ROOT}/current/deploy/bpc_identity.py"
ACCESS="${BPC_ROOT}/current/deploy/bpc_access.py"
CLUSTER="${BPC_ROOT}/current/deploy/bpc_cluster.py"
CLUSTER_OPS="${BPC_ROOT}/current/deploy/bpc_cluster_ops.py"
STATE_MIGRATE="${BPC_ROOT}/current/deploy/bpc-state-migrate.py"
CONTROL_DIR="${BPC_STATE_DIR}/control"

usage() {
  cat <<'USAGE'
Usage:
  bpc init [--name NAME] [--roles controller,gateway,relay] [--hostname DNS]
  bpc join <TOKEN>
  bpc status
  bpc leave [--force]
  bpc node info
  bpc node status
  bpc node token create --roles ROLE[,ROLE...] [--name NAME] [--expires 15m]
  bpc node list
  bpc node create --name NAME --preset public-node --host HOST
  bpc node create --name NAME --preset site-router --route CIDR
  bpc cluster status
  bpc cluster members
  bpc cluster remove NODE [--force]
  bpc cluster backup [--output FILE]
  bpc cluster restore BACKUP --confirm CLUSTER_ID [--force]
  bpc user add USER [--password-stdin]
  bpc user disable USER
  bpc device list
  bpc device revoke DEVICE
  bpc access list [--user USER | --device DEVICE]
  bpc access grant (--user USER | --device DEVICE) CIDR [CIDR ...]
  bpc access revoke (--user USER | --device DEVICE) CIDR [CIDR ...]
  bpc state migrate

Compatibility:
  bpc-node gateway list is read-only. Legacy BP Gateway write commands are
  deprecated and disabled.
USAGE
}

require_file() {
  local path="$1"
  local label="$2"
  if [[ ! -f "${path}" ]]; then
    echo "${label} is missing: ${path}" >&2
    exit 3
  fi
}

scope="${1:-}"

if [[ ${EUID} -ne 0 && -n "${scope}" && "${scope}" != "-h" && "${scope}" != "--help" && "${scope}" != "help" ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo "$0" "$@"
  fi
  echo "BPC management requires root privileges and sudo is unavailable." >&2
  exit 1
fi

case "${scope}" in
  init)
    require_file "${CLUSTER}" "BPC cluster helper"
    shift
    exec python3 "${CLUSTER}" --state-dir "${BPC_STATE_DIR}" init "$@"
    ;;
  join)
    require_file "${ENROLL}" "BPC Node enrollment helper"
    shift
    exec python3 "${ENROLL}" --state-dir "${BPC_STATE_DIR}" --control-dir "${CONTROL_DIR}" join "$@"
    ;;
  status)
    require_file "${ENROLL}" "BPC Node enrollment helper"
    shift
    python3 "${ENROLL}" --state-dir "${BPC_STATE_DIR}" --control-dir "${CONTROL_DIR}" status || true
    exec "${BPC_ROOT}/current/deploy/bpc-node.sh" status
    ;;
  leave)
    require_file "${ENROLL}" "BPC Node enrollment helper"
    shift
    exec python3 "${ENROLL}" --state-dir "${BPC_STATE_DIR}" --control-dir "${CONTROL_DIR}" leave "$@"
    ;;
  node)
    shift
    case "${1:-}" in
      create)
        require_file "${ENROLL}" "BPC Node enrollment helper"
        shift
        exec python3 "${ENROLL}" --state-dir "${BPC_STATE_DIR}" --control-dir "${CONTROL_DIR}" node-create "$@"
        ;;
      token)
        if [[ "${2:-}" != "create" ]]; then
          usage >&2
          exit 2
        fi
        require_file "${ENROLL}" "BPC Node enrollment helper"
        shift 2
        exec python3 "${ENROLL}" --state-dir "${BPC_STATE_DIR}" --control-dir "${CONTROL_DIR}" token-create "$@"
        ;;
      list)
        require_file "${ENROLL}" "BPC Node enrollment helper"
        shift
        exec python3 "${ENROLL}" --state-dir "${BPC_STATE_DIR}" --control-dir "${CONTROL_DIR}" list "$@"
        ;;
      status)
        shift
        "${BPC_ROOT}/current/deploy/bpc-node.sh" status
        if [[ -f "${BPC_STATE_DIR}/cluster/controller.json" ]]; then
          require_file "${CLUSTER_OPS}" "BPC cluster operations helper"
          echo
          exec python3 "${CLUSTER_OPS}" --state-dir "${BPC_STATE_DIR}" status
        fi
        ;;
      *)
        exec "${BPC_ROOT}/current/deploy/bpc-node.sh" "$@"
        ;;
    esac
    ;;
  cluster)
    require_file "${CLUSTER_OPS}" "BPC cluster operations helper"
    shift
    exec python3 "${CLUSTER_OPS}" --state-dir "${BPC_STATE_DIR}" "$@"
    ;;
  user)
    shift
    require_file "${IDENTITY}" "BPC identity helper"
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
    require_file "${IDENTITY}" "BPC identity helper"
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
  access)
    shift
    require_file "${ACCESS}" "BPC Access helper"
    case "${1:-}" in
      list)
        shift
        exec python3 "${ACCESS}" --state-dir "${CONTROL_DIR}" list "$@"
        ;;
      grant)
        shift
        exec python3 "${ACCESS}" --state-dir "${CONTROL_DIR}" grant "$@"
        ;;
      revoke)
        shift
        exec python3 "${ACCESS}" --state-dir "${CONTROL_DIR}" revoke "$@"
        ;;
      *)
        usage >&2
        exit 2
        ;;
    esac
    ;;
  state)
    if [[ "${2:-}" != "migrate" || $# -ne 2 ]]; then
      usage >&2
      exit 2
    fi
    require_file "${STATE_MIGRATE}" "BPC state migration helper"
    exec python3 "${STATE_MIGRATE}" --state-dir "${BPC_STATE_DIR}"
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
