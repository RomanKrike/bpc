#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
WGSHIM_DIR="${RU_DIR}/wgshim"
SUB_DIR="${RU_DIR}/subscription"
CONTROL_DIR="${RU_DIR}/control"
PORT="${BPC_CONTROL_PORT:-8444}"

usage() {
  cat <<'USAGE'
Usage:
  bpc-enable-control [--port PORT]

Options:
  --port PORT   HTTPS control-plane port (default: 8444)
  -h, --help    Show this help

The BPC control plane reuses the trusted TLS certificate provisioned by
bpc-enable-subscription. WGShim must already be enabled.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)
      PORT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-enable-control as root" >&2
  exit 1
fi
if ! [[ "${PORT}" =~ ^[0-9]+$ ]] || (( PORT < 1024 || PORT > 65535 )); then
  echo "--port must be between 1024 and 65535" >&2
  exit 2
fi
if [[ ! -f "${WGSHIM_DIR}/enabled" || ! -s "${WGSHIM_DIR}/runtime.env" || ! -s "${WGSHIM_DIR}/psk" ]]; then
  echo "WGShim must be enabled before the BPC control plane" >&2
  exit 3
fi
if [[ ! -f "${SUB_DIR}/enabled" || ! -s "${SUB_DIR}/runtime.env" ]]; then
  echo "Secure subscription HTTPS must be enabled first with bpc-enable-subscription" >&2
  exit 3
fi

# shellcheck disable=SC1090,SC1091
source "${WGSHIM_DIR}/runtime.env"
# shellcheck disable=SC1090,SC1091
source "${SUB_DIR}/runtime.env"

if [[ ! -s "${SUBSCRIPTION_CERT}" || ! -s "${SUBSCRIPTION_KEY}" ]]; then
  echo "Subscription TLS certificate is missing" >&2
  exit 3
fi

client_env="${RU_DIR}/client.env"
if [[ ! -s "${client_env}" ]]; then
  echo "RU-node client.env is missing" >&2
  exit 3
fi
BPC_RU_HOST="$(sed -n 's/^BPC_RU_HOST=//p' "${client_env}" | head -n1)"
if [[ -z "${BPC_RU_HOST}" ]]; then
  echo "BPC_RU_HOST is missing from client.env" >&2
  exit 3
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends openssl python3 ca-certificates

install -d -m 0700   "${CONTROL_DIR}"   "${CONTROL_DIR}/enroll"   "${CONTROL_DIR}/devices"   "${CONTROL_DIR}/tokens"   "${CONTROL_DIR}/update"

signing_key="${CONTROL_DIR}/update-signing-key.pem"
signing_public="${CONTROL_DIR}/update-signing-public.pem"
if [[ ! -s "${signing_key}" || ! -s "${signing_public}" ]]; then
  umask 077
  openssl genpkey -algorithm ED25519 -out "${signing_key}"
  openssl pkey -in "${signing_key}" -pubout -out "${signing_public}"
fi
chmod 0600 "${signing_key}" "${signing_public}"

wgshim_psk="$(tr -d '\r\n' < "${WGSHIM_DIR}/psk")"
python3 - "${CONTROL_DIR}/config.json" <<PY
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = {
    "config_version": 1,
    "wgshim_server": "${BPC_RU_HOST}:${WGSHIM_PORT:-24443}",
    "wgshim_listen": "127.0.0.1:${WGSHIM_LOCAL_PORT:-24081}",
    "wgshim_target": "${WGSHIM_TARGET_HOST}:${WGSHIM_TARGET_PORT}",
    "wgshim_psk": "${wgshim_psk}",
    "padding_min": int("${WGSHIM_PADDING_MIN:-0}"),
    "padding_max": int("${WGSHIM_PADDING_MAX:-31}"),
    "update_channel": "stable",
}
tmp = path.with_suffix(".tmp")
tmp.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
chmod 0600 "${CONTROL_DIR}/config.json"

cat > "${CONTROL_DIR}/runtime.env" <<RUNTIME
CONTROL_HOST=${SUBSCRIPTION_HOST}
CONTROL_PORT=${PORT}
CONTROL_CERT=${SUBSCRIPTION_CERT}
CONTROL_KEY=${SUBSCRIPTION_KEY}
RUNTIME
chmod 0600 "${CONTROL_DIR}/runtime.env"

cat > /etc/systemd/system/bpc-control.service <<UNIT
[Unit]
Description=BPC Agent control plane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${BPC_ROOT}/current/deploy/bpc-control-server.py --listen 0.0.0.0 --port ${PORT} --state-dir ${CONTROL_DIR} --cert-file ${SUBSCRIPTION_CERT} --key-file ${SUBSCRIPTION_KEY}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${CONTROL_DIR}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictNamespaces=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now bpc-control.service
sleep 1
if ! systemctl --quiet is-active bpc-control.service; then
  systemctl status bpc-control.service --no-pager >&2 || true
  exit 5
fi

touch "${CONTROL_DIR}/enabled"
chmod 0600 "${CONTROL_DIR}/enabled"

cat <<DONE
BPC Agent control plane is active.

Endpoint:
  https://${SUBSCRIPTION_HOST}:${PORT}

State:
  ${CONTROL_DIR}

Update signing public key:
  ${signing_public}

Allow inbound TCP/${PORT} in the VPS provider firewall if it is filtered there.
DONE
