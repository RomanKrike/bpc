#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
OUTPUT="${BPC_CLASH_OUTPUT:-${RU_DIR}/clash-verge-auto.yaml}"
HEALTH_URL="${BPC_CLASH_HEALTH_URL:-https://www.gstatic.com/generate_204}"
HEALTH_INTERVAL="${BPC_CLASH_HEALTH_INTERVAL:-15}"
HEALTH_TIMEOUT="${BPC_CLASH_HEALTH_TIMEOUT:-5000}"
MAX_FAILED_TIMES="${BPC_CLASH_MAX_FAILED_TIMES:-2}"
TRANSPORT_ORDER="${BPC_CLASH_TRANSPORT_ORDER:-awg wg vless}"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-render-clash as root" >&2
  exit 1
fi

if [[ ! -f "${RU_DIR}/client.env" ]]; then
  echo "RU-node client.env is missing" >&2
  exit 2
fi

for value_spec in \
  "BPC_CLASH_HEALTH_INTERVAL:${HEALTH_INTERVAL}:5:3600" \
  "BPC_CLASH_HEALTH_TIMEOUT:${HEALTH_TIMEOUT}:500:30000" \
  "BPC_CLASH_MAX_FAILED_TIMES:${MAX_FAILED_TIMES}:1:20"; do
  name="${value_spec%%:*}"
  rest="${value_spec#*:}"
  value="${rest%%:*}"
  rest="${rest#*:}"
  min="${rest%%:*}"
  max="${rest#*:}"
  if ! [[ "${value}" =~ ^[0-9]+$ ]] || (( value < min || value > max )); then
    echo "${name} must be between ${min} and ${max}" >&2
    exit 2
  fi
done

# shellcheck disable=SC1090,SC1091
source "${RU_DIR}/client.env"

require_vless_values() {
  local name
  for name in \
    BPC_RU_HOST BPC_RU_PORT BPC_VLESS_UUID BPC_REALITY_SERVER_NAME \
    BPC_REALITY_PUBLIC_KEY BPC_REALITY_SHORT_ID; do
    if [[ -z "${!name:-}" ]]; then
      echo "${name} is missing from ${RU_DIR}/client.env" >&2
      return 1
    fi
  done
}

emit_existing_proxy() {
  local profile="$1"
  awk '
    /^proxies:[[:space:]]*$/ {inside=1; next}
    /^proxy-groups:[[:space:]]*$/ {inside=0}
    inside {print}
  ' "${profile}"
}

emit_vless_proxy() {
  require_vless_values
  cat <<VLESS
  - name: BPC-RU-VLESS-01
    type: vless
    server: ${BPC_RU_HOST}
    port: ${BPC_RU_PORT}
    uuid: ${BPC_VLESS_UUID}
    flow: xtls-rprx-vision
    udp: true
    packet-encoding: xudp
    tls: true
    servername: ${BPC_REALITY_SERVER_NAME}
    client-fingerprint: chrome
    reality-opts:
      public-key: ${BPC_REALITY_PUBLIC_KEY}
      short-id: ${BPC_REALITY_SHORT_ID}
    network: tcp
VLESS
}

transport_available() {
  case "$1" in
    awg) [[ -f "${RU_DIR}/awg/enabled" && -s "${RU_DIR}/awg/clash-verge.yaml" ]] ;;
    wg) [[ -f "${RU_DIR}/wg/enabled" && -s "${RU_DIR}/wg/clash-verge.yaml" ]] ;;
    vless) require_vless_values >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

transport_name() {
  case "$1" in
    awg) printf '%s\n' 'BPC-RU-AWG-01' ;;
    wg) printf '%s\n' 'BPC-RU-WG-01' ;;
    vless) printf '%s\n' 'BPC-RU-VLESS-01' ;;
    *) return 1 ;;
  esac
}

emit_transport_proxy() {
  case "$1" in
    awg) emit_existing_proxy "${RU_DIR}/awg/clash-verge.yaml" ;;
    wg) emit_existing_proxy "${RU_DIR}/wg/clash-verge.yaml" ;;
    vless) emit_vless_proxy ;;
    *) return 1 ;;
  esac
}

declare -a enabled_transports=()
declare -a proxy_names=()
for transport in ${TRANSPORT_ORDER}; do
  case "${transport}" in
    awg|wg|vless) ;;
    *)
      echo "Unsupported transport in BPC_CLASH_TRANSPORT_ORDER: ${transport}" >&2
      exit 2
      ;;
  esac
  if transport_available "${transport}"; then
    enabled_transports+=("${transport}")
    proxy_names+=("$(transport_name "${transport}")")
  fi
done

if (( ${#enabled_transports[@]} == 0 )); then
  echo "No enabled BPC transports are available for the Clash profile" >&2
  exit 3
fi

# RU_DIR already contains the live RU-node state and has deliberately managed
# ownership/mode so the Xray service account can traverse it. Never chmod or
# recreate this directory here; the renderer only owns the generated profile.
if [[ ! -d "${RU_DIR}" ]]; then
  echo "RU-node state directory is missing: ${RU_DIR}" >&2
  exit 3
fi

tmp="$(mktemp "${RU_DIR}/.clash-verge-auto.XXXXXX")"
trap 'rm -f "${tmp}"' EXIT

{
  cat <<HEADER
mixed-port: 7897
allow-lan: false
mode: rule
log-level: info
ipv6: false
unified-delay: true

proxies:
HEADER

  for transport in "${enabled_transports[@]}"; do
    emit_transport_proxy "${transport}"
  done

  cat <<GROUP

proxy-groups:
  - name: BPC-AUTO
    type: fallback
    proxies:
GROUP

  for name in "${proxy_names[@]}"; do
    printf '      - %s\n' "${name}"
  done

  cat <<GROUP
    url: ${HEALTH_URL}
    interval: ${HEALTH_INTERVAL}
    lazy: false
    timeout: ${HEALTH_TIMEOUT}
    max-failed-times: ${MAX_FAILED_TIMES}
    expected-status: 204

rules:
  - MATCH,BPC-AUTO
GROUP
} > "${tmp}"

chmod 0600 "${tmp}"
mv -f "${tmp}" "${OUTPUT}"
trap - EXIT

printf 'BPC automatic Clash profile rendered: %s\n' "${OUTPUT}"
printf 'Transport order:'
for name in "${proxy_names[@]}"; do
  printf ' %s' "${name}"
done
printf '\n'
printf 'Strategy: first healthy transport in priority order; no DIRECT fallback.\n'
