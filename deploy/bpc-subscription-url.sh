#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
SUB_DIR="${BPC_STATE_DIR}/ru-node/subscription"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-subscription-url as root because the URL is a secret" >&2
  exit 1
fi

if [[ ! -f "${SUB_DIR}/enabled" || ! -f "${SUB_DIR}/runtime.env" || ! -s "${SUB_DIR}/token" ]]; then
  echo "BPC Clash subscription is not enabled" >&2
  exit 2
fi

# shellcheck disable=SC1090,SC1091
source "${SUB_DIR}/runtime.env"
token="$(tr -d '\r\n' < "${SUB_DIR}/token")"

if [[ -z "${SUBSCRIPTION_HOST:-}" || -z "${SUBSCRIPTION_PORT:-}" || -z "${token}" ]]; then
  echo "BPC Clash subscription state is incomplete" >&2
  exit 2
fi

printf 'https://%s:%s/%s/clash.yaml\n' \
  "${SUBSCRIPTION_HOST}" "${SUBSCRIPTION_PORT}" "${token}"
