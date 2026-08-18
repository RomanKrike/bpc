#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
ROLE="${BPC_ROLE:-}"

if [[ -f "${BPC_STATE_DIR}/install.env" ]]; then
  # shellcheck disable=SC1090,SC1091
  source "${BPC_STATE_DIR}/install.env"
  ROLE="${BPC_ROLE:-${ROLE}}"
fi

check_awg() {
  local awg_dir="${BPC_STATE_DIR}/ru-node/awg"
  local runtime_env="${awg_dir}/runtime.env"
  local container interface

  [[ -f "${awg_dir}/enabled" ]] || return 0
  if [[ ! -f "${runtime_env}" ]]; then
    echo "AmneziaWG runtime metadata is missing" >&2
    return 1
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is missing for enabled AmneziaWG transport" >&2
    return 1
  fi

  # shellcheck disable=SC1090,SC1091
  source "${runtime_env}"
  container="${AWG_CONTAINER:-bpc-awg}"
  interface="${AWG_INTERFACE:-awg0}"

  docker ps --format '{{.Names}}' | grep -Fxq "${container}"
  docker exec "${container}" awg show "${interface}" >/dev/null
  systemctl --quiet is-active bpc-awg-firewall.service
}

case "${ROLE}" in
  ru-node)
    config="${BPC_STATE_DIR}/ru-node/config.json"
    if [[ ! -x /usr/local/bin/xray ]]; then
      echo "xray binary is missing" >&2
      exit 1
    fi
    if [[ ! -s "${config}" ]]; then
      echo "RU-node Xray configuration is missing" >&2
      exit 1
    fi
    /usr/local/bin/xray run -test -config "${config}" >/dev/null
    systemctl --quiet is-active xray
    check_awg
    ;;
  *)
    echo "Unknown or missing BPC_ROLE: ${ROLE:-<empty>}" >&2
    exit 1
    ;;
esac
