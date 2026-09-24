#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
WGSHIM_DIR="${RU_DIR}/wgshim"
WGSHIM_PORT="${BPC_WGSHIM_PORT:-24443}"
WGSHIM_LOCAL_PORT="${BPC_WGSHIM_LOCAL_PORT:-24081}"
WGSHIM_PADDING_MIN="${BPC_WGSHIM_PADDING_MIN:-0}"
WGSHIM_PADDING_MAX="${BPC_WGSHIM_PADDING_MAX:-31}"
TARGET=""

usage() {
  cat <<'USAGE'
Usage:
  bpc-enable-wgshim --target IPv4:PORT [options]

Options:
  --target IPv4:PORT     Existing WireGuard UDP endpoint to relay to (required)
  --port PORT            Public WGShim UDP port (default: 24443)
  --local-port PORT      Windows loopback UDP port for WireGuard (default: 24081)
  --padding-min N        Minimum random outer padding bytes (default: 0)
  --padding-max N        Maximum random outer padding bytes (default: 31)
  -h, --help             Show this help

WGShim is a low-latency authenticated UDP wrapper. It does not change
WireGuard cryptography. BPC 0.8.0 WGShim intentionally supports one active
client per server instance.
USAGE
}

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

is_valid_port() {
  local value="$1"
  [[ "${value}" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= 65535 ))
}

is_valid_padding() {
  local value="$1"
  [[ "${value}" =~ ^[0-9]+$ ]] && (( value >= 0 && value <= 255 ))
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    --port)
      WGSHIM_PORT="${2:-}"
      shift 2
      ;;
    --local-port)
      WGSHIM_LOCAL_PORT="${2:-}"
      shift 2
      ;;
    --padding-min)
      WGSHIM_PADDING_MIN="${2:-}"
      shift 2
      ;;
    --padding-max)
      WGSHIM_PADDING_MAX="${2:-}"
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
  echo "Run bpc-enable-wgshim as root" >&2
  exit 1
fi
if [[ -z "${TARGET}" || "${TARGET}" != *:* ]]; then
  echo "--target IPv4:PORT is required" >&2
  usage >&2
  exit 2
fi

target_host="${TARGET%:*}"
target_port="${TARGET##*:}"
if ! is_valid_ipv4 "${target_host}" || ! is_valid_port "${target_port}"; then
  echo "Invalid WireGuard target: ${TARGET}" >&2
  exit 2
fi
if ! is_valid_port "${WGSHIM_PORT}" || ! is_valid_port "${WGSHIM_LOCAL_PORT}"; then
  echo "WGShim ports must be between 1 and 65535" >&2
  exit 2
fi
if ! is_valid_padding "${WGSHIM_PADDING_MIN}" || ! is_valid_padding "${WGSHIM_PADDING_MAX}" || \
  (( WGSHIM_PADDING_MIN > WGSHIM_PADDING_MAX )); then
  echo "Padding must satisfy 0 <= min <= max <= 255" >&2
  exit 2
fi

client_env="${RU_DIR}/client.env"
if [[ ! -f "${client_env}" ]]; then
  echo "RU-node client.env is missing; install the RU node first" >&2
  exit 2
fi
BPC_RU_HOST="$(sed -n 's/^BPC_RU_HOST=//p' "${client_env}" | head -n1)"
if [[ -z "${BPC_RU_HOST}" ]]; then
  echo "BPC_RU_HOST is missing from client.env" >&2
  exit 2
fi
if [[ "${target_host}" == "${BPC_RU_HOST}" ]]; then
  echo "Refusing to relay WGShim back to the BPC RU endpoint itself: ${target_host}" >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *)
    echo "Unsupported server architecture: $(uname -m)" >&2
    exit 3
    ;;
esac

release_binary="${BPC_ROOT}/current/bin/bpc-wgshim-linux-${arch}"
if [[ ! -x "${release_binary}" ]]; then
  echo "WGShim release binary is missing: ${release_binary}" >&2
  echo "Update BPC to a release that contains WGShim and retry." >&2
  exit 3
fi

if [[ ! -f "${WGSHIM_DIR}/enabled" ]]; then
  if ss -H -lun "sport = :${WGSHIM_PORT}" | grep -q .; then
    echo "WGShim UDP port ${WGSHIM_PORT} is already in use" >&2
    exit 3
  fi
fi

install -d -m 0700 "${WGSHIM_DIR}"
install -m 0755 "${release_binary}" /usr/local/bin/bpc-wgshim

if [[ ! -s "${WGSHIM_DIR}/psk" ]]; then
  umask 077
  head -c 32 /dev/urandom | base64 > "${WGSHIM_DIR}/psk"
fi
chmod 0600 "${WGSHIM_DIR}/psk"

cat > "${WGSHIM_DIR}/runtime.env" <<STATE
WGSHIM_PORT=${WGSHIM_PORT}
WGSHIM_LOCAL_PORT=${WGSHIM_LOCAL_PORT}
WGSHIM_TARGET_HOST=${target_host}
WGSHIM_TARGET_PORT=${target_port}
WGSHIM_PADDING_MIN=${WGSHIM_PADDING_MIN}
WGSHIM_PADDING_MAX=${WGSHIM_PADDING_MAX}
STATE
chmod 0600 "${WGSHIM_DIR}/runtime.env"

install -m 0600 "${WGSHIM_DIR}/psk" "${WGSHIM_DIR}/client.key"
cat > "${WGSHIM_DIR}/client.txt" <<INFO
BPC WGShim Windows client

Server: ${BPC_RU_HOST}:${WGSHIM_PORT}/udp
Local WireGuard endpoint: 127.0.0.1:${WGSHIM_LOCAL_PORT}
Target behind BPC: ${target_host}:${target_port}/udp
Recommended first-test WireGuard MTU: 1360

1. Securely copy client.key to the Windows machine.
2. Download bpc-wgshim-windows-amd64.exe from the matching BPC GitHub Release.
3. Start:

   .\bpc-wgshim-windows-amd64.exe client --listen 127.0.0.1:${WGSHIM_LOCAL_PORT} --server ${BPC_RU_HOST}:${WGSHIM_PORT} --key-file .\client.key --padding-min ${WGSHIM_PADDING_MIN} --padding-max ${WGSHIM_PADDING_MAX}

4. Change the normal WireGuard peer Endpoint to:

   Endpoint = 127.0.0.1:${WGSHIM_LOCAL_PORT}

WGShim does not replace or modify WireGuard cryptography. It wraps complete
WireGuard UDP datagrams in a separate authenticated/encrypted UDP envelope.
BPC 0.8.0 supports one active WGShim client per server instance.
INFO
chmod 0600 "${WGSHIM_DIR}/client.txt" "${WGSHIM_DIR}/client.key"

cat > /etc/systemd/system/bpc-wgshim.service <<UNIT
[Unit]
Description=BPC WGShim low-latency WireGuard UDP wrapper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bpc-wgshim server --listen 0.0.0.0:${WGSHIM_PORT} --target ${target_host}:${target_port} --key-file ${WGSHIM_DIR}/psk --padding-min ${WGSHIM_PADDING_MIN} --padding-max ${WGSHIM_PADDING_MAX}
Restart=always
RestartSec=1
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable bpc-wgshim.service >/dev/null
systemctl restart bpc-wgshim.service

if ! systemctl --quiet is-active bpc-wgshim.service; then
  systemctl status bpc-wgshim.service --no-pager >&2 || true
  echo "WGShim service failed to start" >&2
  exit 5
fi
if ! ss -H -lun "sport = :${WGSHIM_PORT}" | grep -Fq 'bpc-wgshim'; then
  if ! ss -H -lun "sport = :${WGSHIM_PORT}" | grep -q .; then
    echo "WGShim UDP listener is unavailable on port ${WGSHIM_PORT}" >&2
    exit 5
  fi
fi

touch "${WGSHIM_DIR}/enabled"
chmod 0600 "${WGSHIM_DIR}/enabled"

cat <<DONE
BPC WGShim low-latency relay is active.
Public endpoint: ${BPC_RU_HOST}:${WGSHIM_PORT}/udp
WireGuard target: ${target_host}:${target_port}/udp
Windows instructions: ${WGSHIM_DIR}/client.txt
Windows key file: ${WGSHIM_DIR}/client.key

Allow UDP/${WGSHIM_PORT} in the VPS provider firewall if it is filtered there.
WGShim is separate from Clash/Mihomo and is intended for latency-sensitive
WireGuard traffic. BPC 0.8.0 supports one active client per WGShim instance.
DONE
