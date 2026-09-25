#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
AGENT_DIR="${RU_DIR}/agent"
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
bpc-enable-subscription. It provisions the dedicated self-contained BPC Agent
WireGuard/WGShim data plane automatically.
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
if [[ ! -f "${SUB_DIR}/enabled" || ! -s "${SUB_DIR}/runtime.env" ]]; then
  echo "Secure subscription HTTPS must be enabled first with bpc-enable-subscription" >&2
  exit 3
fi

# shellcheck disable=SC1090,SC1091
source "${SUB_DIR}/runtime.env"

if [[ ! -x "${BPC_ROOT}/current/deploy/bpc-enable-agent-dataplane.sh" ]]; then
  echo "BPC Agent data-plane provisioner is missing from the current release" >&2
  exit 3
fi
"${BPC_ROOT}/current/deploy/bpc-enable-agent-dataplane.sh"
if [[ ! -f "${AGENT_DIR}/enabled" || ! -s "${AGENT_DIR}/runtime.env" ]]; then
  echo "BPC Agent data plane did not initialize" >&2
  exit 3
fi
# shellcheck disable=SC1090,SC1091
source "${AGENT_DIR}/runtime.env"

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

install -d -m 0700   "${CONTROL_DIR}"   "${CONTROL_DIR}/enroll"   "${CONTROL_DIR}/devices"   "${CONTROL_DIR}/tokens"   "${CONTROL_DIR}/downloads"   "${CONTROL_DIR}/update"

control_server="${CONTROL_DIR}/bpc-control-server.py"
install -m 0700 "${BPC_ROOT}/current/deploy/bpc-control-server.py" "${control_server}"

signing_key="${CONTROL_DIR}/update-signing-key.pem"
signing_public="${CONTROL_DIR}/update-signing-public.pem"
if [[ ! -s "${signing_key}" || ! -s "${signing_public}" ]]; then
  umask 077
  openssl genpkey -algorithm ED25519 -out "${signing_key}"
  openssl pkey -in "${signing_key}" -pubout -out "${signing_public}"
fi
chmod 0600 "${signing_key}" "${signing_public}"

python3 - "${CONTROL_DIR}/config.json" \
  "${AGENT_PUBLIC_HOST}" "${AGENT_WGSHIM_PORT}" "${AGENT_WGSHIM_LOCAL_PORT}" \
  "${AGENT_WG_PORT}" "${AGENT_WGSHIM_PADDING_MIN}" "${AGENT_WGSHIM_PADDING_MAX}" \
  "${AGENT_WG_INTERFACE}" "${AGENT_WG_SUBNET}" "${AGENT_WG_SERVER_ADDRESS}" \
  "${AGENT_WG_SERVER_PUBLIC_KEY}" "${AGENT_WG_MTU}" "${AGENT_WG_KEEPALIVE}" \
  "${AGENT_WG_ALLOWED_IPS}" "${AGENT_WGSHIM_KEY_DIR}" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = {
    "config_version": 3,
    "wgshim_server": f"{sys.argv[2]}:{sys.argv[3]}",
    "wgshim_listen": f"127.0.0.1:{sys.argv[4]}",
    "wgshim_target": f"127.0.0.1:{sys.argv[5]}",
    "padding_min": int(sys.argv[6]),
    "padding_max": int(sys.argv[7]),
    "wireguard_interface": sys.argv[8],
    "wireguard_subnet": sys.argv[9],
    "wireguard_server_address": sys.argv[10],
    "wireguard_server_public_key": sys.argv[11],
    "wireguard_mtu": int(sys.argv[12]),
    "wireguard_keepalive": int(sys.argv[13]),
    "wireguard_allowed_ips": [item.strip() for item in sys.argv[14].split(",") if item.strip()],
    "wgshim_key_dir": sys.argv[15],
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
After=network-online.target wg-quick@${AGENT_WG_INTERFACE}.service bpc-agent-relay.service
Wants=network-online.target
Requires=wg-quick@${AGENT_WG_INTERFACE}.service bpc-agent-relay.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${control_server} --listen 0.0.0.0 --port ${PORT} --state-dir ${CONTROL_DIR} --cert-file ${SUBSCRIPTION_CERT} --key-file ${SUBSCRIPTION_KEY}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${CONTROL_DIR} ${AGENT_DIR}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable bpc-control.service >/dev/null
systemctl reset-failed bpc-control.service >/dev/null 2>&1 || true
systemctl restart bpc-control.service
sleep 1
if ! systemctl --quiet is-active bpc-control.service; then
  systemctl status bpc-control.service --no-pager >&2 || true
  exit 5
fi

touch "${CONTROL_DIR}/enabled"
chmod 0600 "${CONTROL_DIR}/enabled"

if [[ -x "${BPC_ROOT}/current/deploy/bpc-agent.sh" ]]; then
  "${BPC_ROOT}/current/deploy/bpc-agent.sh" publish-update
fi

cat <<DONE
BPC Agent control plane is active.

Endpoint:
  https://${SUBSCRIPTION_HOST}:${PORT}

State:
  ${CONTROL_DIR}

Update signing public key:
  ${signing_public}

Allow inbound TCP/${PORT} and UDP/${AGENT_WGSHIM_PORT} in the VPS provider firewall if filtered there.
DONE
