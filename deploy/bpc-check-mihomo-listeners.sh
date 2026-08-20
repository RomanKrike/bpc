#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
SERVER_DIR="${RU_DIR}/mihomo-server"
RUNTIME_ENV="${SERVER_DIR}/runtime.env"
SERVICE="bpc-mihomo-transports.service"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-check-mihomo-listeners as root" >&2
  exit 1
fi

if [[ ! -f "${SERVER_DIR}/enabled" ]]; then
  exit 0
fi
if [[ ! -s "${RUNTIME_ENV}" ]]; then
  echo "Mihomo transport runtime metadata is missing" >&2
  exit 1
fi
if ! command -v ss >/dev/null 2>&1; then
  echo "ss is required to verify Mihomo listeners" >&2
  exit 1
fi

# shellcheck disable=SC1090,SC1091
source "${RUNTIME_ENV}"

check_socket() {
  local proto="$1"
  local port="$2"
  local label="$3"
  local attempt output

  for ((attempt = 0; attempt < 30; attempt++)); do
    if [[ "${proto}" == "tcp" ]]; then
      output="$(ss -H -ltnp "sport = :${port}" 2>/dev/null || true)"
    else
      output="$(ss -H -lunp "sport = :${port}" 2>/dev/null || true)"
    fi
    if grep -Fq 'bpc-mihomo' <<<"${output}"; then
      return 0
    fi
    sleep 0.1
  done

  echo "Mihomo listener is missing: ${label} ${proto^^}/${port}" >&2
  return 1
}

check_socket udp "${HY2_PORT}" "Hysteria2"
check_socket udp "${TUIC_PORT}" "TUIC"
check_socket tcp "${ANYTLS_PORT}" "AnyTLS"
check_socket tcp "${SHADOWTLS_PORT}" "ShadowTLS"
check_socket udp "${SHADOWTLS_PORT}" "Shadowsocks UDP"
check_socket tcp "${TROJAN_PORT}" "Trojan"
check_socket tcp "${MIERU_PORT}" "Mieru"
check_socket tcp "${TRUSTTUNNEL_PORT}" "TrustTunnel"
check_socket udp "${TRUSTTUNNEL_PORT}" "TrustTunnel"

if systemctl --quiet is-active "${SERVICE}" 2>/dev/null; then
  exit 0
fi

# ExecStartPost invokes this script while systemd still considers the service
# activating, so only require active state when the check is run manually.
if [[ -z "${INVOCATION_ID:-}" ]]; then
  echo "${SERVICE} is not active" >&2
  exit 1
fi
