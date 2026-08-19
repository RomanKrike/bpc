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

check_mihomo_transports() {
  local server_dir="${BPC_STATE_DIR}/ru-node/mihomo-server"
  local runtime_env="${server_dir}/runtime.env"
  local config="${server_dir}/config.yaml"
  local transport

  [[ -f "${server_dir}/enabled" ]] || return 0
  if [[ ! -s "${runtime_env}" || ! -s "${config}" ]]; then
    fail_health "Mihomo transport-pack runtime metadata or config is missing"
    return 1
  fi
  if [[ ! -x /usr/local/bin/bpc-mihomo ]]; then
    fail_health "bpc-mihomo binary is missing for enabled transport pack"
    return 1
  fi

  # shellcheck disable=SC1090,SC1091
  source "${runtime_env}"
  if [[ ! -s "${TLS_CERT:-}" || ! -s "${TLS_KEY:-}" ]]; then
    fail_health "Mihomo transport-pack TLS certificate or key is missing"
    return 1
  fi
  if ! /usr/local/bin/bpc-mihomo -t -d "${server_dir}/home" -f "${config}" >/dev/null 2>&1; then
    fail_health "Mihomo transport-pack configuration validation failed"
    return 1
  fi
  if ! systemctl --quiet is-active bpc-mihomo-transports.service; then
    fail_health "bpc-mihomo-transports.service is not active"
    return 1
  fi

  for transport in hy2 tuic anytls shadowtls trojan mieru trusttunnel; do
    if [[ ! -f "${BPC_STATE_DIR}/ru-node/${transport}/enabled" || \
      ! -s "${BPC_STATE_DIR}/ru-node/${transport}/clash-verge.yaml" ]]; then
      fail_health "Mihomo transport profile is missing or disabled: ${transport}"
      return 1
    fi
  done
}

check_ssh_rescue() {
  local ssh_dir="${BPC_STATE_DIR}/ru-node/ssh-rescue"
  local runtime_env="${ssh_dir}/runtime.env"
  local service user

  [[ -f "${ssh_dir}/enabled" ]] || return 0
  if [[ ! -s "${runtime_env}" || ! -s "${ssh_dir}/client.key" || \
    ! -s "${ssh_dir}/clash-verge.yaml" ]]; then
    fail_health "SSH rescue state is incomplete"
    return 1
  fi
  # shellcheck disable=SC1090,SC1091
  source "${runtime_env}"
  service="${SSH_RESCUE_SERVICE:-ssh.service}"
  user="${SSH_RESCUE_USER:-bpc-rescue}"
  if ! id "${user}" >/dev/null 2>&1; then
    fail_health "SSH rescue account ${user} is missing"
    return 1
  fi
  if ! systemctl --quiet is-active "${service}"; then
    fail_health "SSH rescue service ${service} is not active"
    return 1
  fi
  if command -v sshd >/dev/null 2>&1 && ! sshd -t; then
    fail_health "OpenSSH configuration validation failed"
    return 1
  fi
}

check_subscription() {
  local sub_dir="${BPC_STATE_DIR}/ru-node/subscription"
  local runtime_env="${sub_dir}/runtime.env"

  [[ -f "${sub_dir}/enabled" ]] || return 0
  if [[ ! -f "${runtime_env}" ]]; then
    fail_health "subscription runtime metadata is missing"
    return 1
  fi
  if [[ ! -s "${sub_dir}/token" ]]; then
    fail_health "subscription token is missing"
    return 1
  fi
  if [[ ! -s "${BPC_STATE_DIR}/ru-node/clash-verge-auto.yaml" ]]; then
    fail_health "aggregate Clash profile is missing for enabled subscription"
    return 1
  fi

  # shellcheck disable=SC1090,SC1091
  source "${runtime_env}"
  if [[ ! -s "${SUBSCRIPTION_CERT:-}" || ! -s "${SUBSCRIPTION_KEY:-}" ]]; then
    fail_health "subscription TLS certificate or private key is missing"
    return 1
  fi
  if ! systemctl --quiet is-active bpc-subscription.service; then
    fail_health "bpc-subscription.service is not active"
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
    check_mihomo_transports
    check_ssh_rescue
    check_subscription
    ;;
  *)
    fail_health "Unknown or missing BPC_ROLE: ${ROLE:-<empty>}"
    exit 1
    ;;
esac
