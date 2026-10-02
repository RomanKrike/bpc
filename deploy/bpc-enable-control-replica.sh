#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
CONTROL_DIR="${BPC_STATE_DIR}/control"
HOSTNAME=""
PORT="${BPC_CONTROL_PORT:-8444}"
EMAIL=""

usage() {
  cat <<'USAGE'
Usage:
  bpc-enable-control-replica --hostname HOST [--port PORT] [--email EMAIL]

Starts the public BPC control API on an additional Controller without creating
or mutating a local Agent/WireGuard dataplane. Canonical control/config.json is
expected to have arrived through Raft first.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostname)
      HOSTNAME="${2:-}"
      shift 2
      ;;
    --port)
      PORT="${2:-}"
      shift 2
      ;;
    --email)
      EMAIL="${2:-}"
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
  echo "Run bpc-enable-control-replica as root" >&2
  exit 1
fi
if ! [[ "${HOSTNAME}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || [[ "${HOSTNAME}" != *.* ]]; then
  echo "--hostname must be a public DNS hostname" >&2
  exit 2
fi
if ! [[ "${PORT}" =~ ^[0-9]+$ ]] || (( PORT < 1024 || PORT > 65535 )); then
  echo "--port must be between 1024 and 65535" >&2
  exit 2
fi
if [[ -n "${EMAIL}" && ! "${EMAIL}" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
  echo "--email does not look like a valid email address" >&2
  exit 2
fi

if [[ ! -s "${BPC_STATE_DIR}/cluster/controller.json" ]]; then
  echo "Distributed Controller marker is missing; complete Raft enrollment first" >&2
  exit 3
fi
# Historical files may still need projection after Raft catch-up.
python3 - "${BPC_ROOT}/current/deploy" "${CONTROL_DIR}" <<'PY_BARRIER'
import sys
import time
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import bpc_control_state

deadline = time.monotonic() + 45
while True:
    try:
        result = bpc_control_state.strong_read(Path(sys.argv[2]))
        break
    except bpc_control_state.ControlStateError:
        if time.monotonic() >= deadline:
            raise
        time.sleep(2)
if result.get("local_fallback"):
    raise SystemExit("Distributed Controller barrier is unavailable")
PY_BARRIER
if [[ ! -s "${CONTROL_DIR}/config.json" ]]; then
  echo "Canonical control/config.json has not caught up through Raft" >&2
  exit 3
fi

release_control_server="${BPC_ROOT}/current/deploy/bpc-control-server.py"
release_node_enrollment="${BPC_ROOT}/current/deploy/bpc_node_enrollment.py"
release_identity="${BPC_ROOT}/current/deploy/bpc_identity.py"
release_access="${BPC_ROOT}/current/deploy/bpc_access.py"
release_control_state="${BPC_ROOT}/current/deploy/bpc_control_state.py"
release_topology="${BPC_ROOT}/current/deploy/bpc_topology.py"
release_controller_enrollment="${BPC_ROOT}/current/deploy/bpc_controller_enrollment.py"
release_gateway_snapshot="${BPC_ROOT}/current/deploy/bpc_gateway_snapshot.py"
release_gateway_dataplane="${BPC_ROOT}/current/deploy/bpc_gateway_dataplane.py"
release_package="${BPC_ROOT}/current/src/bpc_connect"
for required in   "${release_control_server}" "${release_node_enrollment}"   "${release_identity}" "${release_access}" "${release_control_state}" "${release_topology}"   "${release_controller_enrollment}" "${release_gateway_snapshot}"   "${release_gateway_dataplane}" "${release_package}"; do
  if [[ ! -e "${required}" ]]; then
    echo "BPC control runtime dependency is missing: ${required}" >&2
    exit 3
  fi
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates certbot curl iproute2 openssl python3 python3-yaml python3-argon2 python3-cryptography

if ! getent ahostsv4 "${HOSTNAME}" >/dev/null 2>&1; then
  echo "${HOSTNAME} does not resolve to IPv4" >&2
  exit 4
fi
cert_dir="/etc/letsencrypt/live/${HOSTNAME}"
cert_file="${cert_dir}/fullchain.pem"
key_file="${cert_dir}/privkey.pem"
if [[ ! -s "${cert_file}" || ! -s "${key_file}" ]]; then
  if ss -H -ltn 'sport = :80' 2>/dev/null | grep -q .; then
    echo "TCP/80 is in use; cannot complete Let's Encrypt HTTP-01" >&2
    exit 4
  fi
  certbot_args=(
    certonly --standalone --preferred-challenges http
    --non-interactive --agree-tos --keep-until-expiring
    --cert-name "${HOSTNAME}" -d "${HOSTNAME}"
  )
  if [[ -n "${EMAIL}" ]]; then
    certbot_args+=(--email "${EMAIL}")
  else
    certbot_args+=(--register-unsafely-without-email)
  fi
  certbot "${certbot_args[@]}"
fi
if [[ ! -s "${cert_file}" || ! -s "${key_file}" ]]; then
  echo "Trusted TLS certificate was not provisioned for ${HOSTNAME}" >&2
  exit 4
fi

release_version="source"
if [[ -s "${BPC_ROOT}/current/VERSION" ]]; then
  release_version="$(tr -d '[:space:]' < "${BPC_ROOT}/current/VERSION")"
fi
runtime_version_dir="${CONTROL_DIR}/runtime-${release_version}"
runtime_tmp="$(mktemp -d "${CONTROL_DIR}/.runtime.XXXXXX")"
trap 'rm -rf "${runtime_tmp}"' EXIT
install -d -m 0700 "${runtime_tmp}/src"
install -m 0700 "${release_control_server}" "${runtime_tmp}/bpc-control-server.py"
install -m 0600 "${release_node_enrollment}" "${runtime_tmp}/bpc_node_enrollment.py"
install -m 0600 "${release_identity}" "${runtime_tmp}/bpc_identity.py"
install -m 0600 "${release_access}" "${runtime_tmp}/bpc_access.py"
install -m 0600 "${release_control_state}" "${runtime_tmp}/bpc_control_state.py"
install -m 0600 "${release_topology}" "${runtime_tmp}/bpc_topology.py"
install -m 0600 "${release_controller_enrollment}" "${runtime_tmp}/bpc_controller_enrollment.py"
install -m 0600 "${release_gateway_snapshot}" "${runtime_tmp}/bpc_gateway_snapshot.py"
install -m 0600 "${release_gateway_dataplane}" "${runtime_tmp}/bpc_gateway_dataplane.py"
cp -R "${release_package}" "${runtime_tmp}/src/bpc_connect"
chown -R root:root "${runtime_tmp}"
find "${runtime_tmp}" -type d -exec chmod 0700 {} +
find "${runtime_tmp}" -type f -exec chmod 0600 {} +
chmod 0700 "${runtime_tmp}/bpc-control-server.py"

rm -rf "${runtime_version_dir}"
mv "${runtime_tmp}" "${runtime_version_dir}"
trap - EXIT
if [[ -e "${CONTROL_DIR}/runtime" && ! -L "${CONTROL_DIR}/runtime" ]]; then
  rm -rf "${CONTROL_DIR}/runtime"
fi
ln -sfn "runtime-${release_version}" "${CONTROL_DIR}/runtime"

cat > "${CONTROL_DIR}/runtime.env" <<RUNTIME
CONTROL_HOST=${HOSTNAME}
CONTROL_PORT=${PORT}
CONTROL_CERT=${cert_file}
CONTROL_KEY=${key_file}
CONTROL_MODE=replica
RUNTIME
chmod 0600 "${CONTROL_DIR}/runtime.env"

python3 "${BPC_ROOT}/current/deploy/bpc_control_runtime.py" \
  --state-dir "${BPC_STATE_DIR}" --release-root "${BPC_ROOT}"

cat > /etc/systemd/system/bpc-control.service <<UNIT
[Unit]
Description=BPC public control API replica
After=network-online.target bpc-controld.service
Wants=network-online.target
Requires=bpc-controld.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${CONTROL_DIR}/runtime/bpc-control-server.py --listen 0.0.0.0 --port ${PORT} --state-dir ${CONTROL_DIR} --cert-file ${cert_file} --key-file ${key_file}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${CONTROL_DIR} ${BPC_STATE_DIR}/cluster ${BPC_STATE_DIR}/runtime-topology
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable bpc-control.service >/dev/null
systemctl restart bpc-control.service
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS --max-time 2 "https://${HOSTNAME}:${PORT}/v1/health" >/dev/null 2>&1; then
    touch "${CONTROL_DIR}/enabled"
    chmod 0600 "${CONTROL_DIR}/enabled"
    echo "BPC public Controller API is active: https://${HOSTNAME}:${PORT}"
    exit 0
  fi
  sleep 1
done

systemctl status bpc-control.service -l --no-pager >&2 || true
journalctl -u bpc-control.service -n 80 -o cat -l --no-pager >&2 || true
exit 5
