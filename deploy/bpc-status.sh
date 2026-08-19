#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
role="unknown"

format_age() {
  local seconds="$1"

  if (( seconds < 60 )); then
    printf '%ss ago' "${seconds}"
  elif (( seconds < 3600 )); then
    printf '%sm ago' "$((seconds / 60))"
  elif (( seconds < 86400 )); then
    printf '%sh ago' "$((seconds / 3600))"
  else
    printf '%sd ago' "$((seconds / 86400))"
  fi
}

print_peer_line() {
  local label="$1"
  local handshake="$2"
  local rx="$3"
  local tx="$4"
  local now age

  if [[ "${handshake}" =~ ^[0-9]+$ ]] && (( handshake > 0 )); then
    now="$(date +%s)"
    age=$((now - handshake))
    (( age < 0 )) && age=0
    printf '%s peer: handshake %s; rx=%s B; tx=%s B\n' \
      "${label}" "$(format_age "${age}")" "${rx:-0}" "${tx:-0}"
  else
    printf '%s peer: no handshake; rx=%s B; tx=%s B\n' \
      "${label}" "${rx:-0}" "${tx:-0}"
  fi
}

if [[ -f "${BPC_STATE_DIR}/install.env" ]]; then
  # shellcheck disable=SC1090,SC1091
  source "${BPC_STATE_DIR}/install.env"
  role="${BPC_ROLE:-unknown}"
fi

version="unknown"
if [[ -f "${BPC_ROOT}/current/VERSION" ]]; then
  version="$(tr -d '[:space:]' < "${BPC_ROOT}/current/VERSION")"
fi

printf 'BPC version: %s\n' "${version}"
printf 'Role: %s\n' "${role}"

if "${BPC_ROOT}/current/deploy/bpc-healthcheck.sh"; then
  echo "Health: OK"
else
  echo "Health: FAILED"
  exit 1
fi

if getent ahostsv4 deb.debian.org >/dev/null 2>&1; then
  echo "DNS: OK"
else
  echo "DNS: FAILED (run bpc-ensure-dns)"
fi

if [[ "${role}" == "ru-node" ]]; then
  printf 'Xray: %s\n' "$(systemctl is-active xray 2>/dev/null || true)"
  host="unknown"
  if [[ -f "${BPC_STATE_DIR}/ru-node/client.env" ]]; then
    host="$(sed -n 's/^BPC_RU_HOST=//p' "${BPC_STATE_DIR}/ru-node/client.env" | head -n1)"
    port="$(sed -n 's/^BPC_RU_PORT=//p' "${BPC_STATE_DIR}/ru-node/client.env" | head -n1)"
    printf 'Endpoint: %s:%s/tcp\n' "${host:-unknown}" "${port:-unknown}"
  fi

  awg_dir="${BPC_STATE_DIR}/ru-node/awg"
  if [[ -f "${awg_dir}/enabled" ]]; then
    # shellcheck disable=SC1090,SC1091
    source "${awg_dir}/runtime.env"
    awg_container="${AWG_CONTAINER:-bpc-awg}"
    awg_interface="${AWG_INTERFACE:-awg0}"
    awg_port="${AWG_PORT:-443}"
    if docker ps --format '{{.Names}}' | grep -Fxq "${awg_container}"; then
      awg_state="active"
    else
      awg_state="inactive"
    fi
    printf 'AmneziaWG: %s\n' "${awg_state}"
    printf 'AWG endpoint: %s:%s/udp\n' "${host:-unknown}" "${awg_port}"

    awg_handshake="0"
    awg_rx="0"
    awg_tx="0"
    if [[ "${awg_state}" == "active" ]]; then
      awg_handshake="$(
        docker exec "${awg_container}" awg show "${awg_interface}" latest-handshakes \
          2>/dev/null | awk 'NR==1 {print $2}' || true
      )"
      read -r _ awg_rx awg_tx <<< "$(
        docker exec "${awg_container}" awg show "${awg_interface}" transfer \
          2>/dev/null | head -n1 || true
      )"
    fi
    print_peer_line "AWG" "${awg_handshake:-0}" "${awg_rx:-0}" "${awg_tx:-0}"
  else
    echo 'AmneziaWG: disabled'
  fi

  wg_dir="${BPC_STATE_DIR}/ru-node/wg"
  if [[ -f "${wg_dir}/enabled" ]]; then
    # shellcheck disable=SC1090,SC1091
    source "${wg_dir}/runtime.env"
    wg_interface="${WG_INTERFACE:-bpcwg0}"
    wg_port="${WG_PORT:-51820}"
    if systemctl --quiet is-active "wg-quick@${wg_interface}.service" && \
      wg show "${wg_interface}" >/dev/null 2>&1; then
      wg_state="active"
    else
      wg_state="inactive"
    fi
    printf 'WireGuard: %s\n' "${wg_state}"
    printf 'WG endpoint: %s:%s/udp\n' "${host:-unknown}" "${wg_port}"

    wg_handshake="0"
    wg_rx="0"
    wg_tx="0"
    if [[ "${wg_state}" == "active" ]]; then
      wg_handshake="$(
        wg show "${wg_interface}" latest-handshakes 2>/dev/null \
          | awk 'NR==1 {print $2}' || true
      )"
      read -r _ wg_rx wg_tx <<< "$(
        wg show "${wg_interface}" transfer 2>/dev/null | head -n1 || true
      )"
    fi
    print_peer_line "WG" "${wg_handshake:-0}" "${wg_rx:-0}" "${wg_tx:-0}"
  else
    echo 'WireGuard: disabled'
  fi

  auto_profile="${BPC_STATE_DIR}/ru-node/clash-verge-auto.yaml"
  if [[ -s "${auto_profile}" ]]; then
    printf 'Clash auto profile: ready (%s)\n' "${auto_profile}"
  else
    echo 'Clash auto profile: missing (run bpc-render-clash)'
  fi

  sub_dir="${BPC_STATE_DIR}/ru-node/subscription"
  if [[ -f "${sub_dir}/enabled" && -f "${sub_dir}/runtime.env" ]]; then
    # shellcheck disable=SC1090,SC1091
    source "${sub_dir}/runtime.env"
    sub_state="$(systemctl is-active bpc-subscription.service 2>/dev/null || true)"
    printf 'Subscription: %s (https://%s:%s/<hidden>/clash.yaml)\n' \
      "${sub_state:-unknown}" "${SUBSCRIPTION_HOST:-unknown}" "${SUBSCRIPTION_PORT:-unknown}"
  else
    echo 'Subscription: disabled'
  fi
fi
