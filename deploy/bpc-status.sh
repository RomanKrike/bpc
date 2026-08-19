#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
role="unknown"

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
    awg_port="${AWG_PORT:-443}"
    if docker ps --format '{{.Names}}' | grep -Fxq "${awg_container}"; then
      awg_state="active"
    else
      awg_state="inactive"
    fi
    printf 'AmneziaWG: %s\n' "${awg_state}"
    printf 'AWG endpoint: %s:%s/udp\n' "${host:-unknown}" "${awg_port}"
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
  else
    echo 'WireGuard: disabled'
  fi
fi
