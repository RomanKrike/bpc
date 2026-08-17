#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
ROLE="${BPC_ROLE:-}"

if [[ -f "${BPC_STATE_DIR}/install.env" ]]; then
  # shellcheck disable=SC1090
  source "${BPC_STATE_DIR}/install.env"
  ROLE="${BPC_ROLE:-${ROLE}}"
fi

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
    ;;
  *)
    echo "Unknown or missing BPC_ROLE: ${ROLE:-<empty>}" >&2
    exit 1
    ;;
esac
