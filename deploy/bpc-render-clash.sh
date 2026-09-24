#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
OUTPUT="${BPC_CLASH_OUTPUT:-${RU_DIR}/clash-verge-auto.yaml}"
HEALTH_URL="${BPC_CLASH_HEALTH_URL:-https://www.gstatic.com/generate_204}"
HEALTH_INTERVAL="${BPC_CLASH_HEALTH_INTERVAL:-15}"
HEALTH_TIMEOUT="${BPC_CLASH_HEALTH_TIMEOUT:-5000}"
MAX_FAILED_TIMES="${BPC_CLASH_MAX_FAILED_TIMES:-2}"
TRANSPORT_ORDER="${BPC_CLASH_TRANSPORT_ORDER:-awg wg hy2 tuic vless anytls shadowtls trojan mieru trusttunnel}"

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

profile_available() {
  local transport="$1"
  [[ -f "${RU_DIR}/${transport}/enabled" && -s "${RU_DIR}/${transport}/clash-verge.yaml" ]]
}

transport_available() {
  case "$1" in
    awg|wg|hy2|tuic|anytls|shadowtls|trojan|mieru|trusttunnel)
      profile_available "$1"
      ;;
    vless)
      require_vless_values >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

transport_name() {
  case "$1" in
    awg) printf '%s\n' 'BPC-RU-AWG-01' ;;
    wg) printf '%s\n' 'BPC-RU-WG-01' ;;
    hy2) printf '%s\n' 'BPC-RU-HY2-01' ;;
    tuic) printf '%s\n' 'BPC-RU-TUIC-01' ;;
    vless) printf '%s\n' 'BPC-RU-VLESS-01' ;;
    anytls) printf '%s\n' 'BPC-RU-ANYTLS-01' ;;
    shadowtls) printf '%s\n' 'BPC-RU-SHADOWTLS-01' ;;
    trojan) printf '%s\n' 'BPC-RU-TROJAN-01' ;;
    mieru) printf '%s\n' 'BPC-RU-MIERU-01' ;;
    trusttunnel) printf '%s\n' 'BPC-RU-TRUST-01' ;;
    *) return 1 ;;
  esac
}

emit_transport_proxy() {
  case "$1" in
    awg|wg|hy2|tuic|anytls|shadowtls|trojan|mieru|trusttunnel)
      emit_existing_proxy "${RU_DIR}/$1/clash-verge.yaml"
      ;;
    vless)
      emit_vless_proxy
      ;;
    *)
      return 1
      ;;
  esac
}

declare -a manual_profiles=()
declare -a manual_names=()
if profile_available openvpn; then
  manual_profiles+=("${RU_DIR}/openvpn/clash-verge.yaml")
  manual_names+=("BPC-RU-OPENVPN-01")
fi
if profile_available ssh-rescue; then
  manual_profiles+=("${RU_DIR}/ssh-rescue/clash-verge.yaml")
  manual_names+=("BPC-RU-SSH-RESCUE")
fi

declare -a enabled_transports=()
declare -a proxy_names=()
for transport in ${TRANSPORT_ORDER}; do
  case "${transport}" in
    awg|wg|hy2|tuic|vless|anytls|shadowtls|trojan|mieru|trusttunnel) ;;
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

declare -a route_targets=()
if [[ -s "${ROUTE_TARGETS_FILE}" ]]; then
  while IFS= read -r target; do
    [[ -n "${target}" ]] || continue
    if ! is_valid_ipv4 "${target}"; then
      echo "Invalid IPv4 address in ${ROUTE_TARGETS_FILE}: ${target}" >&2
      exit 2
    fi
    if [[ "${target}" == "${BPC_RU_HOST:-}" ]]; then
      echo "BPC route target would create a loop through the RU endpoint: ${target}" >&2
      exit 2
    fi
    route_targets+=("${target}")
  done < "${ROUTE_TARGETS_FILE}"
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
  for profile in "${manual_profiles[@]}"; do
    emit_existing_proxy "${profile}"
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

  - name: BPC-MANUAL
    type: select
    proxies:
GROUP
  for name in "${proxy_names[@]}"; do
    printf '      - %s\n' "${name}"
  done

  cat <<GROUP

  - name: BPC-ROUTE
    type: select
    proxies:
      - BPC-AUTO
      - BPC-MANUAL
GROUP
  for name in "${manual_names[@]}"; do
    printf '      - %s\n' "${name}"
  done

  if (( ${#route_targets[@]} > 0 )); then
    cat <<GROUP

rules:
GROUP
    for target in "${route_targets[@]}"; do
      printf '  - IP-CIDR,%s/32,BPC-ROUTE,no-resolve\n' "${target}"
    done
    cat <<GROUP
  - MATCH,DIRECT
GROUP
  else
    cat <<GROUP

rules:
  - MATCH,BPC-ROUTE
GROUP
  fi
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
if (( ${#manual_names[@]} > 0 )); then
  printf 'Manual fallbacks:'
  for name in "${manual_names[@]}"; do
    printf ' %s' "${name}"
  done
  printf '\n'
fi
if (( ${#route_targets[@]} > 0 )); then
  printf 'Routing mode: selective underlay; BPC targets:'
  for target in "${route_targets[@]}"; do
    printf ' %s' "${target}"
  done
  printf '\n'
  printf 'Non-target traffic: DIRECT. Target traffic remains fail-closed through BPC-ROUTE.\n'
else
  printf 'Routing mode: full-tunnel fail-closed through BPC-ROUTE.\n'
fi
printf 'Strategy: first healthy automatic transport in priority order; BPC-MANUAL is available for protocol testing.\n'
