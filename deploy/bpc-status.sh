#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"

version="unknown"
if [[ -f "${BPC_ROOT}/current/VERSION" ]]; then
  version="$(tr -d '[:space:]' < "${BPC_ROOT}/current/VERSION")"
fi

role="unknown"
if [[ -f "${BPC_STATE_DIR}/install.env" ]]; then
  # shellcheck disable=SC1090
  source "${BPC_STATE_DIR}/install.env"
  role="${BPC_ROLE:-unknown}"
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
  if [[ -f "${BPC_STATE_DIR}/ru-node/client.env" ]]; then
    # Do not print credentials.
    host="$(sed -n 's/^BPC_RU_HOST=//p' "${BPC_STATE_DIR}/ru-node/client.env" | head -n1)"
    port="$(sed -n 's/^BPC_RU_PORT=//p' "${BPC_STATE_DIR}/ru-node/client.env" | head -n1)"
    printf 'Endpoint: %s:%s\n' "${host:-unknown}" "${port:-unknown}"
  fi
fi
