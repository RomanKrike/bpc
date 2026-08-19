#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
ROLE="${BPC_ROLE:-}"

if [[ -f "${BPC_STATE_DIR}/install.env" ]]; then
  # shellcheck disable=SC1090,SC1091
  source "${BPC_STATE_DIR}/install.env"
  ROLE="${BPC_ROLE:-${ROLE}}"
fi

fail_health() {
  echo "Health check FAILED: $*" >&2
  return 1
}

check_awg() {
  local awg_dir="${BPC_STATE_DIR}/ru-node/awg"
  local runtime_env="${awg_dir}/runtime.env"
  local container interface

  [[ -f "${awg_dir}/enabled" ]] || return 0
  if [[ ! -f "${runtime_env}" ]]; then
    fail_health "AmneziaWG runtime metadata is missing"
    return 1
  fi
  if ! command -v docker >/dev/null 2>&1; then
    fail_health "docker is missing for enabled AmneziaWG transport"
    return 1
  fi

  # shellcheck disable=SC1090,SC1091
  source "${runtime_env}"
  container="${AWG_CONTAINER:-bpc-awg}"
  interface="${AWG_INTERFACE:-awg0}"

  if ! docker ps --format '{{.Names}}' | grep -Fxq "${container}"; then
    fail_health "AmneziaWG container ${container} is not running"
    return 1
  fi
  if ! docker exec "${container}" awg show "${interface}" >/dev/null 2>&1; then
    fail_health "AmneziaWG interface ${interface} is unavailable in ${container}"
    return 1
  fi
  if ! systemctl --quiet is-active bpc-awg-firewall.service; then
    fail_health "bpc-awg-firewall.service is not active"
    return 1
  fi
}

check_wg() {
  local wg_dir="${BPC_STATE_DIR}/ru-node/wg"
  local runtime_env="${wg_dir}/runtime.env"
  local interface

  [[ -f "${wg_dir}/enabled" ]] || return 0
  if [[ ! -f "${runtime_env}" ]]; then
    fail_health "WireGuard runtime metadata is missing"
    return 1
  fi
  if ! command -v wg >/dev/null 2>&1; then
    fail_health "wg is missing for enabled WireGuard transport"
    return 1
  fi

  # shellcheck disable=SC1090,SC1091
  source "${runtime_env}"
  interface="${WG_INTERFACE:-bpcwg0}"

  if ! systemctl --quiet is-active "wg-quick@${interface}.service"; then
    fail_health "wg-quick@${interface}.service is not active"
    return 1
  fi
  if ! wg show "${interface}" >/dev/null 2>&1; then
    fail_health "WireGuard interface ${interface} is unavailable"
    return 1
  fi
  if ! systemctl --quiet is-active bpc-wg-firewall.service; then
    fail_health "bpc-wg-firewall.service is not active"
    return 1
  fi
}

case "${ROLE}" in
  ru-node)
    config="${BPC_STATE_DIR}/ru-node/config.json"
    if [[ ! -x /usr/local/bin/xray ]]; then
      fail_health "xray binary is missing"
      exit 1
    fi
    if [[ ! -s "${config}" ]]; then
      fail_health "RU-node Xray configuration is missing"
      exit 1
    fi
    if ! /usr/local/bin/xray run -test -config "${config}" >/dev/null 2>&1; then
      fail_health "Xray configuration validation failed: ${config}"
      exit 1
    fi
    if ! systemctl --quiet is-active xray; then
      fail_health "xray.service is not active"
      exit 1
    fi
    check_awg
    check_wg
    ;;
  *)
    fail_health "Unknown or missing BPC_ROLE: ${ROLE:-<empty>}"
    exit 1
    ;;
esac
