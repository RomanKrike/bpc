#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
AGENT_DIR="${RU_DIR}/agent"
KEY_DIR="${AGENT_DIR}/wgshim-keys"
WG_INTERFACE="${BPC_AGENT_WG_INTERFACE:-bpcag0}"
WG_PORT="${BPC_AGENT_WG_PORT:-51821}"
WG_SUBNET="${BPC_AGENT_WG_SUBNET:-10.253.0.0/24}"
WG_SERVER_ADDRESS="${BPC_AGENT_WG_SERVER_ADDRESS:-10.253.0.1/24}"
WG_MTU="${BPC_AGENT_WG_MTU:-1360}"
WG_KEEPALIVE="${BPC_AGENT_WG_KEEPALIVE:-25}"
WG_ALLOWED_IPS="${BPC_AGENT_ALLOWED_IPS:-0.0.0.0/0}"
WGSHIM_PORT_EXPLICIT="false"
if [[ -n "${BPC_AGENT_WGSHIM_PORT:-}" ]]; then
  WGSHIM_PORT_EXPLICIT="true"
fi
WGSHIM_PORT="${BPC_AGENT_WGSHIM_PORT:-24444}"
WGSHIM_LOCAL_PORT="${BPC_AGENT_WGSHIM_LOCAL_PORT:-24081}"
WGSHIM_PADDING_MIN="${BPC_AGENT_WGSHIM_PADDING_MIN:-0}"
WGSHIM_PADDING_MAX="${BPC_AGENT_WGSHIM_PADDING_MAX:-31}"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-enable-agent-dataplane as root" >&2
  exit 1
fi
for value in "${WG_PORT}" "${WGSHIM_PORT}" "${WGSHIM_LOCAL_PORT}" "${WG_KEEPALIVE}"; do
  if ! [[ "${value}" =~ ^[0-9]+$ ]] || (( value < 1 || value > 65535 )); then
    echo "Agent data-plane ports/keepalive must be between 1 and 65535" >&2
    exit 2
  fi
done
if ! [[ "${WG_MTU}" =~ ^[0-9]+$ ]] || (( WG_MTU < 1200 || WG_MTU > 1500 )); then
  echo "BPC agent WireGuard MTU must be between 1200 and 1500" >&2
  exit 2
fi
if [[ ${#WG_INTERFACE} -gt 15 ]] || ! [[ "${WG_INTERFACE}" =~ ^[A-Za-z0-9_=+.-]+$ ]]; then
  echo "BPC agent WireGuard interface name is invalid" >&2
  exit 2
fi
if ! [[ "${WGSHIM_PADDING_MIN}" =~ ^[0-9]+$ && "${WGSHIM_PADDING_MAX}" =~ ^[0-9]+$ ]] || \
  (( WGSHIM_PADDING_MIN < 0 || WGSHIM_PADDING_MAX > 255 || WGSHIM_PADDING_MIN > WGSHIM_PADDING_MAX )); then
  echo "WGShim padding must satisfy 0 <= min <= max <= 255" >&2
  exit 2
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

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *)
    echo "Unsupported server architecture: $(uname -m)" >&2
    exit 3
    ;;
esac
relay_binary="${BPC_ROOT}/current/bin/bpc-agent-relay-linux-${arch}"
if [[ ! -x "${relay_binary}" ]]; then
  echo "BPC agent relay binary is missing: ${relay_binary}" >&2
  exit 3
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates iproute2 iptables kmod wireguard-tools
modprobe wireguard 2>/dev/null || true

listener="$(ss -H -lunp "sport = :${WGSHIM_PORT}" 2>/dev/null || true)"
if [[ -n "${listener}" ]] && ! grep -Fq 'bpc-agent-relay' <<< "${listener}"; then
  if [[ "${WGSHIM_PORT_EXPLICIT}" == "true" ]]; then
    echo "BPC Agent relay UDP port ${WGSHIM_PORT} is already in use:" >&2
    echo "${listener}" >&2
    exit 4
  fi

  selected_port=""
  for candidate in $(seq 24444 24544); do
    candidate_listener="$(ss -H -lunp "sport = :${candidate}" 2>/dev/null || true)"
    if [[ -z "${candidate_listener}" ]] || grep -Fq 'bpc-agent-relay' <<< "${candidate_listener}"; then
      selected_port="${candidate}"
      break
    fi
  done
  if [[ -z "${selected_port}" ]]; then
    echo "Unable to find a free UDP port for the BPC Agent relay in 24444-24544" >&2
    exit 4
  fi
  echo "UDP/${WGSHIM_PORT} is occupied by another service; using UDP/${selected_port} for BPC Agent relay."
  WGSHIM_PORT="${selected_port}"
fi

install -d -m 0700 "${AGENT_DIR}" "${KEY_DIR}" /etc/wireguard
install -m 0755 "${relay_binary}" /usr/local/bin/bpc-agent-relay

if [[ ! -s "${AGENT_DIR}/server.key" ]]; then
  umask 077
  wg genkey > "${AGENT_DIR}/server.key"
  wg pubkey < "${AGENT_DIR}/server.key" > "${AGENT_DIR}/server.pub"
fi
chmod 0600 "${AGENT_DIR}/server.key" "${AGENT_DIR}/server.pub"
server_private="$(tr -d '\r\n' < "${AGENT_DIR}/server.key")"
server_public="$(tr -d '\r\n' < "${AGENT_DIR}/server.pub")"

cat > "/etc/wireguard/${WG_INTERFACE}.conf" <<CONF
[Interface]
Address = ${WG_SERVER_ADDRESS}
ListenPort = ${WG_PORT}
PrivateKey = ${server_private}
MTU = ${WG_MTU}
CONF
chmod 0600 "/etc/wireguard/${WG_INTERFACE}.conf"

cat > "${AGENT_DIR}/runtime.env" <<RUNTIME
AGENT_WG_INTERFACE=${WG_INTERFACE}
AGENT_WG_PORT=${WG_PORT}
AGENT_WG_SUBNET=${WG_SUBNET}
AGENT_WG_SERVER_ADDRESS=${WG_SERVER_ADDRESS}
AGENT_WG_SERVER_PUBLIC_KEY=${server_public}
AGENT_WG_MTU=${WG_MTU}
AGENT_WG_KEEPALIVE=${WG_KEEPALIVE}
AGENT_WG_ALLOWED_IPS=${WG_ALLOWED_IPS}
AGENT_WGSHIM_PORT=${WGSHIM_PORT}
AGENT_WGSHIM_LOCAL_PORT=${WGSHIM_LOCAL_PORT}
AGENT_WGSHIM_PADDING_MIN=${WGSHIM_PADDING_MIN}
AGENT_WGSHIM_PADDING_MAX=${WGSHIM_PADDING_MAX}
AGENT_WGSHIM_KEY_DIR=${KEY_DIR}
AGENT_PUBLIC_HOST=${BPC_RU_HOST}
RUNTIME
chmod 0600 "${AGENT_DIR}/runtime.env"

cat > /etc/sysctl.d/92-bpc-agent.conf <<'SYSCTL'
net.ipv4.ip_forward=1
SYSCTL
sysctl -q -p /etc/sysctl.d/92-bpc-agent.conf

cat > /usr/local/sbin/bpc-agent-dataplane-firewall <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RUNTIME_ENV="${BPC_STATE_DIR}/ru-node/agent/runtime.env"
ACTION="${1:-up}"
if [[ ! -s "${RUNTIME_ENV}" ]]; then
  echo "BPC agent data-plane runtime metadata is missing" >&2
  exit 1
fi
# shellcheck disable=SC1090,SC1091
source "${RUNTIME_ENV}"
DEFAULT_IF="$(ip -4 route show default | awk 'NR==1 {print $5}')"
if [[ -z "${DEFAULT_IF}" ]]; then
  echo "Unable to determine default IPv4 interface" >&2
  exit 1
fi
case "${ACTION}" in
  up)
    iptables -C FORWARD -i "${AGENT_WG_INTERFACE}" -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -i "${AGENT_WG_INTERFACE}" -j ACCEPT
    iptables -C FORWARD -o "${AGENT_WG_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -o "${AGENT_WG_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -C POSTROUTING -s "${AGENT_WG_SUBNET}" -o "${DEFAULT_IF}" -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -s "${AGENT_WG_SUBNET}" -o "${DEFAULT_IF}" -j MASQUERADE
    iptables -C INPUT -p udp --dport "${AGENT_WG_PORT}" -j DROP 2>/dev/null || \
      iptables -I INPUT 1 -p udp --dport "${AGENT_WG_PORT}" -j DROP
    iptables -C INPUT -i lo -p udp --dport "${AGENT_WG_PORT}" -j ACCEPT 2>/dev/null || \
      iptables -I INPUT 1 -i lo -p udp --dport "${AGENT_WG_PORT}" -j ACCEPT
    ;;
  down)
    iptables -D FORWARD -i "${AGENT_WG_INTERFACE}" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "${AGENT_WG_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "${AGENT_WG_SUBNET}" -o "${DEFAULT_IF}" -j MASQUERADE 2>/dev/null || true
    iptables -D INPUT -i lo -p udp --dport "${AGENT_WG_PORT}" -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p udp --dport "${AGENT_WG_PORT}" -j DROP 2>/dev/null || true
    ;;
  *) echo "Usage: bpc-agent-dataplane-firewall [up|down]" >&2; exit 2 ;;
esac
SCRIPT
chmod 0755 /usr/local/sbin/bpc-agent-dataplane-firewall

cat > /etc/systemd/system/bpc-agent-dataplane-firewall.service <<UNIT
[Unit]
Description=BPC Agent WireGuard forwarding and NAT
After=network-online.target wg-quick@${WG_INTERFACE}.service
Wants=network-online.target
Requires=wg-quick@${WG_INTERFACE}.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/bpc-agent-dataplane-firewall up
ExecStop=/usr/local/sbin/bpc-agent-dataplane-firewall down

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/bpc-agent-relay.service <<UNIT
[Unit]
Description=BPC Agent multi-client WGShim relay
After=network-online.target wg-quick@${WG_INTERFACE}.service
Wants=network-online.target
Requires=wg-quick@${WG_INTERFACE}.service

[Service]
Type=simple
ExecStart=/usr/local/bin/bpc-agent-relay --listen 0.0.0.0:${WGSHIM_PORT} --target 127.0.0.1:${WG_PORT} --key-dir ${KEY_DIR} --padding-min ${WGSHIM_PADDING_MIN} --padding-max ${WGSHIM_PADDING_MAX}
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

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "wg-quick@${WG_INTERFACE}.service" >/dev/null
systemctl restart "wg-quick@${WG_INTERFACE}.service"
systemctl enable bpc-agent-dataplane-firewall.service >/dev/null
systemctl restart bpc-agent-dataplane-firewall.service
systemctl enable bpc-agent-relay.service >/dev/null
systemctl reset-failed bpc-agent-relay.service >/dev/null 2>&1 || true
systemctl restart bpc-agent-relay.service

if ! systemctl --quiet is-active "wg-quick@${WG_INTERFACE}.service"; then
  systemctl status "wg-quick@${WG_INTERFACE}.service" --no-pager >&2 || true
  exit 5
fi
if ! systemctl --quiet is-active bpc-agent-relay.service; then
  systemctl status bpc-agent-relay.service --no-pager >&2 || true
  exit 5
fi
if ! ss -H -lun "sport = :${WGSHIM_PORT}" | grep -q .; then
  echo "BPC agent relay UDP listener is unavailable on ${WGSHIM_PORT}" >&2
  exit 5
fi

touch "${AGENT_DIR}/enabled"
chmod 0600 "${AGENT_DIR}/enabled"
cat <<DONE
BPC Agent data plane is active.

Public relay: ${BPC_RU_HOST}:${WGSHIM_PORT}/udp
Internal WireGuard: ${WG_INTERFACE} ${WG_SERVER_ADDRESS} on loopback UDP/${WG_PORT}
Device subnet: ${WG_SUBNET}
Device key directory: ${KEY_DIR}

Allow inbound UDP/${WGSHIM_PORT} in the VPS provider firewall.
Do not expose UDP/${WG_PORT}; BPC blocks it outside loopback.
DONE
