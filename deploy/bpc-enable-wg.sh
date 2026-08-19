#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
WG_DIR="${WG_DIR:-${BPC_STATE_DIR}/ru-node/wg}"
WG_PORT="${WG_PORT:-51820}"
WG_INTERFACE="${WG_INTERFACE:-bpcwg0}"
WG_SUBNET="${WG_SUBNET:-10.252.0.0/24}"
WG_SERVER_ADDRESS="${WG_SERVER_ADDRESS:-10.252.0.1/24}"
WG_CLIENT_ADDRESS="${WG_CLIENT_ADDRESS:-10.252.0.2/32}"
WG_CLIENT_IP="${WG_CLIENT_IP:-10.252.0.2}"
WG_MTU="${WG_MTU:-1380}"
WG_KEEPALIVE="${WG_KEEPALIVE:-25}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-enable-wg as root" >&2
  exit 1
fi

if ! [[ "${WG_PORT}" =~ ^[0-9]+$ ]] || (( WG_PORT < 1 || WG_PORT > 65535 )); then
  echo "WG_PORT must be between 1 and 65535" >&2
  exit 2
fi

if ! [[ "${WG_MTU}" =~ ^[0-9]+$ ]] || (( WG_MTU < 1200 || WG_MTU > 1500 )); then
  echo "WG_MTU must be between 1200 and 1500" >&2
  exit 2
fi

if [[ ${#WG_INTERFACE} -gt 15 ]] || ! [[ "${WG_INTERFACE}" =~ ^[A-Za-z0-9_=+.-]+$ ]]; then
  echo "WG_INTERFACE must be a valid Linux interface name no longer than 15 characters" >&2
  exit 2
fi

client_env="${BPC_STATE_DIR}/ru-node/client.env"
if [[ ! -f "${client_env}" ]]; then
  echo "RU-node client.env is missing; install the RU node before enabling WireGuard" >&2
  exit 2
fi

BPC_RU_HOST="$(sed -n 's/^BPC_RU_HOST=//p' "${client_env}" | head -n1)"
if [[ -z "${BPC_RU_HOST}" ]]; then
  echo "BPC_RU_HOST is missing from client.env" >&2
  exit 2
fi

if [[ -f "${SCRIPT_DIR}/bpc-ensure-dns.sh" ]]; then
  bash "${SCRIPT_DIR}/bpc-ensure-dns.sh"
fi

if ! getent ahostsv4 deb.debian.org >/dev/null 2>&1; then
  echo "DNS resolution is unavailable; configure an upstream resolver before enabling WireGuard" >&2
  exit 3
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates iproute2 iptables kmod wireguard-tools

if [[ ! -f "${WG_DIR}/enabled" ]] && ss -H -lun "sport = :${WG_PORT}" | grep -q .; then
  echo "UDP port ${WG_PORT} is already in use; set WG_PORT to another value" >&2
  exit 3
fi

modprobe wireguard 2>/dev/null || true

# Verify that this kernel can create a WireGuard interface before generating credentials.
probe_interface="bpcwgprobe"
if ip link show "${probe_interface}" >/dev/null 2>&1; then
  ip link delete "${probe_interface}" >/dev/null 2>&1 || true
fi
if ! ip link add dev "${probe_interface}" type wireguard 2>/dev/null; then
  echo "Kernel WireGuard support is unavailable on this VPS" >&2
  exit 3
fi
ip link delete "${probe_interface}"

install -d -m 0700 "${WG_DIR}" /etc/wireguard

if [[ -f "${WG_DIR}/enabled" ]]; then
  echo "BPC WireGuard is already configured; keeping existing keys and endpoint."
  for required in server.key server.pub client.key client.pub preshared.key "${WG_INTERFACE}.conf" client.conf runtime.env; do
    if [[ ! -s "${WG_DIR}/${required}" ]]; then
      echo "Enabled WireGuard state is incomplete: ${required} is missing" >&2
      exit 4
    fi
  done
else
  umask 077
  wg genkey > "${WG_DIR}/server.key"
  wg pubkey < "${WG_DIR}/server.key" > "${WG_DIR}/server.pub"
  wg genkey > "${WG_DIR}/client.key"
  wg pubkey < "${WG_DIR}/client.key" > "${WG_DIR}/client.pub"
  wg genpsk > "${WG_DIR}/preshared.key"

  server_private="$(tr -d '\r\n' < "${WG_DIR}/server.key")"
  server_public="$(tr -d '\r\n' < "${WG_DIR}/server.pub")"
  client_private="$(tr -d '\r\n' < "${WG_DIR}/client.key")"
  client_public="$(tr -d '\r\n' < "${WG_DIR}/client.pub")"
  preshared_key="$(tr -d '\r\n' < "${WG_DIR}/preshared.key")"

  cat > "${WG_DIR}/${WG_INTERFACE}.conf" <<CONF
[Interface]
Address = ${WG_SERVER_ADDRESS}
ListenPort = ${WG_PORT}
PrivateKey = ${server_private}
MTU = ${WG_MTU}

[Peer]
PublicKey = ${client_public}
PresharedKey = ${preshared_key}
AllowedIPs = ${WG_CLIENT_ADDRESS}
CONF

  cat > "${WG_DIR}/client.conf" <<CONF
[Interface]
PrivateKey = ${client_private}
Address = ${WG_CLIENT_ADDRESS}
DNS = 1.1.1.1
MTU = ${WG_MTU}

[Peer]
PublicKey = ${server_public}
PresharedKey = ${preshared_key}
Endpoint = ${BPC_RU_HOST}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = ${WG_KEEPALIVE}
CONF

  cat > "${WG_DIR}/clash-verge.yaml" <<CONF
mixed-port: 7897
allow-lan: false
mode: rule
log-level: info
ipv6: false

proxies:
  - name: BPC-RU-WG-01
    type: wireguard
    server: ${BPC_RU_HOST}
    port: ${WG_PORT}
    ip: ${WG_CLIENT_IP}
    private-key: ${client_private}
    public-key: ${server_public}
    pre-shared-key: ${preshared_key}
    allowed-ips: ['0.0.0.0/0']
    persistent-keepalive: ${WG_KEEPALIVE}
    udp: true
    mtu: ${WG_MTU}

proxy-groups:
  - name: BPC-RUSSIA
    type: select
    proxies:
      - BPC-RU-WG-01

rules:
  - MATCH,BPC-RUSSIA
CONF

  cat > "${WG_DIR}/transport.yaml" <<CONF
- name: RU-WG-01
  type: wireguard
  enabled: true
  priority: 30
  settings:
    server: ${BPC_RU_HOST}
    port: ${WG_PORT}
    client_ip: ${WG_CLIENT_IP}
    mtu: ${WG_MTU}
    private_key: ${client_private}
    public_key: ${server_public}
    preshared_key: ${preshared_key}
    persistent_keepalive: ${WG_KEEPALIVE}
CONF

  cat > "${WG_DIR}/runtime.env" <<CONF
WG_INTERFACE=${WG_INTERFACE}
WG_PORT=${WG_PORT}
WG_SUBNET=${WG_SUBNET}
WG_MTU=${WG_MTU}
WG_KEEPALIVE=${WG_KEEPALIVE}
CONF

  chmod 0600 "${WG_DIR}/server.key" "${WG_DIR}/server.pub" \
    "${WG_DIR}/client.key" "${WG_DIR}/client.pub" "${WG_DIR}/preshared.key" \
    "${WG_DIR}/${WG_INTERFACE}.conf" "${WG_DIR}/client.conf" \
    "${WG_DIR}/clash-verge.yaml" "${WG_DIR}/transport.yaml" "${WG_DIR}/runtime.env"
  touch "${WG_DIR}/enabled"
  chmod 0600 "${WG_DIR}/enabled"
fi

install -m 0600 "${WG_DIR}/${WG_INTERFACE}.conf" "/etc/wireguard/${WG_INTERFACE}.conf"

cat > /etc/sysctl.d/91-bpc-wg.conf <<'SYSCTL'
net.ipv4.ip_forward=1
SYSCTL
sysctl -q -p /etc/sysctl.d/91-bpc-wg.conf

cat > /usr/local/sbin/bpc-wg-firewall <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RUNTIME_ENV="${BPC_STATE_DIR}/ru-node/wg/runtime.env"
ACTION="${1:-up}"

if [[ ! -f "${RUNTIME_ENV}" ]]; then
  echo "WireGuard runtime metadata is missing" >&2
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
    iptables -C FORWARD -i "${WG_INTERFACE}" -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -i "${WG_INTERFACE}" -j ACCEPT
    iptables -C FORWARD -o "${WG_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -o "${WG_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -C POSTROUTING -s "${WG_SUBNET}" -o "${DEFAULT_IF}" -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -s "${WG_SUBNET}" -o "${DEFAULT_IF}" -j MASQUERADE
    ;;
  down)
    iptables -D FORWARD -i "${WG_INTERFACE}" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "${WG_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "${WG_SUBNET}" -o "${DEFAULT_IF}" -j MASQUERADE 2>/dev/null || true
    ;;
  *)
    echo "Usage: bpc-wg-firewall [up|down]" >&2
    exit 2
    ;;
esac
SCRIPT
chmod 0755 /usr/local/sbin/bpc-wg-firewall

cat > /etc/systemd/system/bpc-wg-firewall.service <<UNIT
[Unit]
Description=BPC WireGuard forwarding and NAT
After=network-online.target wg-quick@${WG_INTERFACE}.service
Wants=network-online.target
Requires=wg-quick@${WG_INTERFACE}.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/bpc-wg-firewall up
ExecStop=/usr/local/sbin/bpc-wg-firewall down

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "wg-quick@${WG_INTERFACE}.service" >/dev/null
systemctl restart "wg-quick@${WG_INTERFACE}.service"
systemctl enable bpc-wg-firewall.service >/dev/null
systemctl restart bpc-wg-firewall.service

if ! systemctl --quiet is-active "wg-quick@${WG_INTERFACE}.service"; then
  systemctl status "wg-quick@${WG_INTERFACE}.service" --no-pager >&2 || true
  echo "WireGuard service failed to start" >&2
  exit 5
fi
if ! wg show "${WG_INTERFACE}" >/dev/null 2>&1; then
  echo "WireGuard interface ${WG_INTERFACE} is not healthy" >&2
  exit 5
fi
if ! systemctl --quiet is-active bpc-wg-firewall.service; then
  echo "BPC WireGuard firewall service is not active" >&2
  exit 5
fi

cat <<DONE
BPC WireGuard is active.

Endpoint: ${BPC_RU_HOST}:${WG_PORT}/udp
Native client config:
  ${WG_DIR}/client.conf
Clash Verge Rev profile:
  ${WG_DIR}/clash-verge.yaml

WireGuard status:
  wg show ${WG_INTERFACE}
DONE
