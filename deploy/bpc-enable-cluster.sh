#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RAFT_PORT="${BPC_RAFT_PORT:-9445}"
CLUSTER_API_PORT="${BPC_CLUSTER_API_PORT:-9447}"
LOCAL_API_PORT="${BPC_LOCAL_API_PORT:-9446}"
ADVERTISE_HOST=""
BOOTSTRAP="false"

usage() {
  cat <<'USAGE'
Usage:
  bpc-enable-cluster --advertise-host HOST [--bootstrap]
                     [--raft-port PORT] [--cluster-api-port PORT]
                     [--local-api-port PORT]

Initializes or reconciles the distributed Controller runtime for a BPC Node
with the controller capability. --bootstrap is for the first Controller only.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --advertise-host)
      ADVERTISE_HOST="${2:-}"
      shift 2
      ;;
    --bootstrap)
      BOOTSTRAP="true"
      shift
      ;;
    --raft-port)
      RAFT_PORT="${2:-}"
      shift 2
      ;;
    --cluster-api-port)
      CLUSTER_API_PORT="${2:-}"
      shift 2
      ;;
    --local-api-port)
      LOCAL_API_PORT="${2:-}"
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
  echo "Run bpc-enable-cluster as root" >&2
  exit 1
fi
if [[ -z "${ADVERTISE_HOST}" || "${ADVERTISE_HOST}" == *:* ]]; then
  echo "--advertise-host must be a DNS name or IPv4 address without a port" >&2
  exit 2
fi
for port in "${RAFT_PORT}" "${CLUSTER_API_PORT}" "${LOCAL_API_PORT}"; do
  if ! [[ "${port}" =~ ^[0-9]+$ ]] || (( port < 1024 || port > 65535 )); then
    echo "Controller ports must be between 1024 and 65535" >&2
    exit 2
  fi
done
if [[ "${RAFT_PORT}" == "${CLUSTER_API_PORT}" || "${RAFT_PORT}" == "${LOCAL_API_PORT}" || "${CLUSTER_API_PORT}" == "${LOCAL_API_PORT}" ]]; then
  echo "Raft, cluster API and local API ports must be distinct" >&2
  exit 2
fi

NODE_CONFIG="${BPC_STATE_DIR}/node.yaml"
CLUSTER_DIR="${BPC_STATE_DIR}/cluster"
PKI_DIR="${CLUSTER_DIR}/pki"
CONTROLLERS_DIR="${CLUSTER_DIR}/controllers"
RAFT_DIR="${CLUSTER_DIR}/raft"
MARKER="${CLUSTER_DIR}/controller.json"
TOKEN_FILE="${CLUSTER_DIR}/local-api.token"

if [[ ! -s "${NODE_CONFIG}" ]]; then
  echo "Canonical Node config is missing: ${NODE_CONFIG}" >&2
  exit 3
fi
if [[ ! -s "${CLUSTER_DIR}/cluster.json" ]]; then
  echo "Canonical cluster record is missing: ${CLUSTER_DIR}/cluster.json" >&2
  exit 3
fi

readarray -t node_meta < <(python3 - "${NODE_CONFIG}" "${CLUSTER_DIR}/cluster.json" <<'PY'
import json
import sys
from pathlib import Path

import yaml

node = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
cluster = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
node_id = str(node.get("node", {}).get("id", "")).strip()
roles = node.get("roles", {})
cluster_id = str(cluster.get("cluster_id", "")).strip()
if not node_id or not cluster_id:
    raise SystemExit("invalid canonical Node/cluster identity")
if not isinstance(roles, dict) or roles.get("controller") is not True:
    raise SystemExit("Node does not have controller capability")
print(node_id)
print(cluster_id)
PY
)
NODE_ID="${node_meta[0]:-}"
CLUSTER_ID="${node_meta[1]:-}"
if [[ -z "${NODE_ID}" || -z "${CLUSTER_ID}" ]]; then
  echo "Unable to resolve canonical Controller identity" >&2
  exit 3
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported Controller architecture: $(uname -m)" >&2
    exit 3
    ;;
esac
CONTROLD="${BPC_ROOT}/current/bin/bpc-controld-linux-${ARCH}"
if [[ ! -x "${CONTROLD}" ]]; then
  echo "Distributed Controller binary is missing: ${CONTROLD}" >&2
  exit 3
fi

install -d -m 0700 "${CLUSTER_DIR}" "${PKI_DIR}" "${CONTROLLERS_DIR}" "${RAFT_DIR}"

CA_KEY="${PKI_DIR}/cluster-ca.key"
CA_CERT="${PKI_DIR}/cluster-ca.crt"
NODE_KEY="${PKI_DIR}/controller.key"
NODE_CERT="${PKI_DIR}/controller.crt"

if [[ "${BOOTSTRAP}" == "true" ]]; then
  if [[ ! -s "${CA_KEY}" || ! -s "${CA_CERT}" ]]; then
    umask 077
    openssl genpkey -algorithm ED25519 -out "${CA_KEY}"
    openssl req -x509 -new -key "${CA_KEY}" -out "${CA_CERT}" -days 3650 \
      -subj "/CN=BPC Cluster ${CLUSTER_ID}" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign"
  fi
else
  if [[ ! -s "${CA_CERT}" ]]; then
    echo "Cluster CA is not provisioned for joining Controller" >&2
    exit 3
  fi
fi
chmod 0600 "${CA_KEY}" 2>/dev/null || true
chmod 0644 "${CA_CERT}"

if [[ ! -s "${NODE_KEY}" || ! -s "${NODE_CERT}" ]]; then
  if [[ "${BOOTSTRAP}" != "true" ]]; then
    echo "Controller certificate is not provisioned; secure Controller enrollment is required" >&2
    exit 3
  fi
  umask 077
  openssl genpkey -algorithm ED25519 -out "${NODE_KEY}"
  csr="$(mktemp "${PKI_DIR}/.controller.XXXXXX.csr")"
  ext="$(mktemp "${PKI_DIR}/.controller.XXXXXX.ext")"
  trap 'rm -f "${csr:-}" "${ext:-}"' EXIT
  if [[ "${ADVERTISE_HOST}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    host_san="IP:${ADVERTISE_HOST}"
  else
    host_san="DNS:${ADVERTISE_HOST}"
  fi
  cat > "${ext}" <<EXT
[v3_controller]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=${host_san},URI:bpc://${CLUSTER_ID}/controller/${NODE_ID}
EXT
  openssl req -new -key "${NODE_KEY}" -out "${csr}" -subj "/CN=${NODE_ID}"
  openssl x509 -req -in "${csr}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
    -CAcreateserial -out "${NODE_CERT}" -days 825 -extfile "${ext}" -extensions v3_controller
  rm -f "${csr}" "${ext}"
  trap - EXIT
fi
chmod 0600 "${NODE_KEY}"
chmod 0644 "${NODE_CERT}"

if [[ ! -s "${TOKEN_FILE}" ]]; then
  umask 077
  openssl rand -hex 32 > "${TOKEN_FILE}"
fi
chmod 0600 "${TOKEN_FILE}"
LOCAL_TOKEN="$(tr -d '[:space:]' < "${TOKEN_FILE}")"
if ! [[ "${LOCAL_TOKEN}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Invalid local Controller API token" >&2
  exit 3
fi

CERT_SHA256="$(openssl x509 -in "${NODE_CERT}" -outform DER | sha256sum | awk '{print $1}')"
VERSION="source"
if [[ -s "${BPC_ROOT}/current/VERSION" ]]; then
  VERSION="$(tr -d '[:space:]' < "${BPC_ROOT}/current/VERSION")"
fi
RAFT_ADDRESS="${ADVERTISE_HOST}:${RAFT_PORT}"
API_ADDRESS="${ADVERTISE_HOST}:${CLUSTER_API_PORT}"
LOCAL_ADDRESS="127.0.0.1:${LOCAL_API_PORT}"

if [[ ! -f "${MARKER}" ]]; then
  python3 - "${CONTROLLERS_DIR}/${NODE_ID}.json" "${NODE_ID}" "${RAFT_ADDRESS}" "${API_ADDRESS}" "${CERT_SHA256}" "${VERSION}" <<'PY'
import json
import os
import sys
import time
from pathlib import Path

path = Path(sys.argv[1])
value = {
    "node_id": sys.argv[2],
    "raft_address": sys.argv[3],
    "api_address": sys.argv[4],
    "state": "voter",
    "software_version": sys.argv[6],
    "protocol_version": 1,
    "state_schema_version": 1,
    "certificate_sha256": sys.argv[5],
    "updated_at": int(time.time()),
}
tmp = path.with_name("." + path.name + ".tmp")
tmp.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
fi

BOOTSTRAP_ARG=""
if [[ "${BOOTSTRAP}" == "true" ]]; then
  BOOTSTRAP_ARG="--bootstrap"
fi

cat > /etc/systemd/system/bpc-controld.service <<UNIT
[Unit]
Description=BPC distributed Controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${CONTROLD} \
  --node-id ${NODE_ID} \
  --raft-bind-address 0.0.0.0:${RAFT_PORT} \
  --raft-address ${RAFT_ADDRESS} \
  --cluster-api-address 0.0.0.0:${CLUSTER_API_PORT} \
  --local-api-address ${LOCAL_ADDRESS} \
  --state-root ${BPC_STATE_DIR} \
  --data-dir ${RAFT_DIR} \
  --cert-file ${NODE_CERT} \
  --key-file ${NODE_KEY} \
  --ca-file ${CA_CERT} \
  --local-api-token-file ${TOKEN_FILE} \
  --software-version ${VERSION} \
  ${BOOTSTRAP_ARG}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${BPC_STATE_DIR}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable bpc-controld.service >/dev/null
systemctl reset-failed bpc-controld.service >/dev/null 2>&1 || true
systemctl restart bpc-controld.service

healthy="false"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS --max-time 2 -H "Authorization: Bearer ${LOCAL_TOKEN}" \
    "http://${LOCAL_ADDRESS}/v1/health" >/dev/null 2>&1; then
    healthy="true"
    break
  fi
  sleep 1
done
if [[ "${healthy}" != "true" ]]; then
  systemctl status bpc-controld.service -l --no-pager >&2 || true
  journalctl -u bpc-controld.service -n 80 -o cat -l --no-pager >&2 || true
  exit 5
fi

python3 - "${MARKER}" "${NODE_ID}" "${RAFT_ADDRESS}" "${API_ADDRESS}" "${LOCAL_ADDRESS}" "${NODE_CERT}" "${NODE_KEY}" "${CA_CERT}" "${TOKEN_FILE}" "${VERSION}" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = {
    "version": 1,
    "node_id": sys.argv[2],
    "raft_address": sys.argv[3],
    "cluster_api_address": sys.argv[4],
    "local_api_address": sys.argv[5],
    "certificate_file": sys.argv[6],
    "key_file": sys.argv[7],
    "ca_file": sys.argv[8],
    "local_api_token_file": sys.argv[9],
    "software_version": sys.argv[10],
    "protocol_version": 1,
    "state_schema_version": 1,
}
tmp = path.with_name("." + path.name + ".tmp")
tmp.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY

echo "BPC distributed Controller is active."
echo "  Node: ${NODE_ID}"
echo "  Raft: ${RAFT_ADDRESS}"
echo "  Cluster API: ${API_ADDRESS}"
echo "  Local API: ${LOCAL_ADDRESS}"
echo "Allow inbound TCP/${RAFT_PORT} and TCP/${CLUSTER_API_PORT} between Controller Nodes."
