#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
TARGETS_FILE="${BPC_ROUTE_TARGETS_FILE:-${RU_DIR}/route-targets.txt}"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
RENDERER="${SCRIPT_DIR}/bpc-render-clash.sh"

usage() {
  cat <<'USAGE'
Usage:
  bpc-route-target add IPv4
  bpc-route-target remove IPv4
  bpc-route-target list
  bpc-route-target clear

Selective route targets are exact IPv4 endpoints whose traffic must use BPC.
When one or more targets exist, the generated Clash profile sends only those
destinations through BPC-ROUTE and leaves all other traffic DIRECT.
USAGE
}

is_valid_ipv4() {
  local ip="$1"
  local a b c d extra octet

  IFS='.' read -r a b c d extra <<< "${ip}"
  [[ -z "${extra:-}" ]] || return 1

  for octet in "${a:-}" "${b:-}" "${c:-}" "${d:-}"; do
    [[ "${octet}" =~ ^[0-9]{1,3}$ ]] || return 1
    (( 10#${octet} <= 255 )) || return 1
  done
}

render_profile() {
  if [[ ! -x "${RENDERER}" ]]; then
    echo "BPC Clash renderer is missing: ${RENDERER}" >&2
    exit 3
  fi
  "${RENDERER}"
}

write_targets() {
  local tmp
  tmp="$(mktemp "${RU_DIR}/.route-targets.XXXXXX")"
  trap 'rm -f "${tmp}"' RETURN
  cat > "${tmp}"
  if [[ -s "${tmp}" ]]; then
    sort -u -o "${tmp}" "${tmp}"
    chmod 0600 "${tmp}"
    mv -f "${tmp}" "${TARGETS_FILE}"
  else
    rm -f "${tmp}" "${TARGETS_FILE}"
  fi
  trap - RETURN
}

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-route-target as root" >&2
  exit 1
fi

if [[ ! -f "${RU_DIR}/client.env" ]]; then
  echo "RU-node client.env is missing; install the RU node first" >&2
  exit 2
fi

action="${1:-}"
case "${action}" in
  add)
    target="${2:-}"
    [[ -n "${target}" && $# -eq 2 ]] || { usage >&2; exit 2; }
    if ! is_valid_ipv4 "${target}"; then
      echo "Invalid IPv4 route target: ${target}" >&2
      exit 2
    fi

    bpc_host="$(sed -n 's/^BPC_RU_HOST=//p' "${RU_DIR}/client.env" | head -n1)"
    if [[ "${target}" == "${bpc_host}" ]]; then
      echo "Refusing to route the BPC RU endpoint through itself: ${target}" >&2
      exit 2
    fi

    if [[ -f "${TARGETS_FILE}" ]] && grep -Fxq "${target}" "${TARGETS_FILE}"; then
      echo "BPC route target already exists: ${target}"
    else
      {
        [[ -f "${TARGETS_FILE}" ]] && cat "${TARGETS_FILE}"
        printf '%s\n' "${target}"
      } | write_targets
      echo "Added BPC route target: ${target}"
    fi
    render_profile
    ;;
  remove)
    target="${2:-}"
    [[ -n "${target}" && $# -eq 2 ]] || { usage >&2; exit 2; }
    if ! is_valid_ipv4 "${target}"; then
      echo "Invalid IPv4 route target: ${target}" >&2
      exit 2
    fi

    if [[ ! -f "${TARGETS_FILE}" ]] || ! grep -Fxq "${target}" "${TARGETS_FILE}"; then
      echo "BPC route target is not configured: ${target}"
    else
      awk -v target="${target}" 'NF && $0 != target {print}' "${TARGETS_FILE}" | write_targets
      echo "Removed BPC route target: ${target}"
    fi
    render_profile
    ;;
  list)
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    if [[ -s "${TARGETS_FILE}" ]]; then
      cat "${TARGETS_FILE}"
    else
      echo "No selective BPC route targets configured."
    fi
    ;;
  clear)
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    rm -f "${TARGETS_FILE}"
    echo "Cleared all BPC route targets."
    render_profile
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
