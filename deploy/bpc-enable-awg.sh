#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
AWG_DIR="${AWG_DIR:-${BPC_STATE_DIR}/ru-node/awg}"
AWG_PORT="${AWG_PORT:-443}"
AWG_INTERFACE="awg0"
AWG_SUBNET="${AWG_SUBNET:-10.251.0.0/24}"
AWG_SERVER_ADDRESS="${AWG_SERVER_ADDRESS:-10.251.0.1/24}"
AWG_CLIENT_ADDRESS="${AWG_CLIENT_ADDRESS:-10.251.0.2/32}"
AWG_MTU="${AWG_MTU:-1280}"
AWG_CONTAINER="${AWG_CONTAINER:-bpc-awg}"
AWG_IMAGE="${AWG_IMAGE:-amneziavpn/amneziawg-go:2.0.0@sha256:4ada4adcf55142c55239f7ae4d683745f6f2d7ad707c758af8f250c5f1cd368e}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Conservative AWG2 profile for the first interoperability test. CPS/I1-I5
# are intentionally left empty until the base transport is proven end to end.
AWG_JC="${AWG_JC:-7}"
AWG_JMIN="${AWG_JMIN:-20}"
AWG_JMAX="${AWG_JMAX:-70}"
AWG_S1="${AWG_S1:-30}"
AWG_S2="${AWG_S2:-40}"
AWG_S3="${AWG_S3:-50}"
AWG_S4="${AWG_S4:-8}"
AWG_H1="${AWG_H1:-100000000-100000999}"
AWG_H2="${AWG_H2:-200000000-200000999}"
AWG_H3="${AWG_H3:-300000000-300000999}"
AWG_H4="${AWG_H4:-400000000-400000999}"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-enable-awg as root" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) ;;
  *)
    echo "BPC AWG2 currently supports amd64 VPS hosts only" >&2
    exit 2
    ;;
esac

if [[ ! -f "${BPC_STATE_DIR}/ru-node/client.env" ]]; then
  echo "RU-node client.env is missing; install the RU node before enabling AWG" >&2
  exit 2
fi

BPC_RU_HOST="$(sed -n 's/^BPC_RU_HOST=//p' "${BPC_STATE_DIR}/ru-node/client.env" | head -n1)"
if [[ -z "${BPC_RU_HOST}" ]]; then
  echo "BPC_RU_HOST is missing from client.env" >&2
  exit 2
fi

# On repeated runs, persisted runtime values win. This prevents accidental
# endpoint/image changes without regenerating the matching client config.
if [[ -f "${AWG_DIR}/enabled" && -f "${AWG_DIR}/runtime.env" ]]; then
  # shellcheck disable=SC1090,SC1091
  source "${AWG_DIR}/runtime.env"
  AWG_INTERFACE="awg0"
fi

if ! [[ "${AWG_PORT}" =~ ^[0-9]+$ ]] || (( AWG_PORT < 1 || AWG_PORT > 65535 )); then
  echo "AWG_PORT must be between 1 and 65535" >&2
  exit 2
fi

# TCP/443 can remain occupied by Xray; AWG uses UDP/443.
if [[ ! -f "${AWG_DIR}/enabled" ]] && ss -H -lun "sport = :${AWG_PORT}" | grep -q .; then
  echo "UDP port ${AWG_PORT} is already in use; set AWG_PORT to another value" >&2
  exit 3
fi

if [[ -f "${SCRIPT_DIR}/bpc-ensure-dns.sh" ]]; then
  bash "${SCRIPT_DIR}/bpc-ensure-dns.sh"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates docker.io iproute2 iptables
systemctl enable --now docker

if [[ ! -c /dev/net/tun ]]; then
  echo "/dev/net/tun is unavailable on this VPS" >&2
  exit 3
fi

install -d -m 0700 "${AWG_DIR}"
docker pull "${AWG_IMAGE}"

run_awg() {
  docker run --rm --network none "${AWG_IMAGE}" "$@"
}

if [[ -f "${AWG_DIR}/enabled" ]]; then
  echo "BPC AmneziaWG is already configured; keeping existing keys and parameters."
else
  server_private="$(run_awg awg genkey | tr -d '\r\n')"
  server_public="$(printf '%s\n' "${server_private}" | docker run --rm -i --network none "${AWG_IMAGE}" awg pubkey | tr -d '\r\n')"
  client_private="$(run_awg awg genkey | tr -d '\r\n')"
  client_public="$(printf '%s\n' "${client_private}" | docker run --rm -i --network none "${AWG_IMAGE}" awg pubkey | tr -d '\r\n')"
  preshared_key="$(run_awg awg genpsk | tr -d '\r\n')"

  if [[ -z "${server_private}" || -z "${server_public}" || -z "${client_private}" || -z "${client_public}" || -z "${preshared_key}" ]]; then
    echo "Failed to generate AmneziaWG keys" >&2
    exit 4
  fi

  cat > "${AWG_DIR}/${AWG_INTERFACE}.conf" <<CONF
[Interface]
PrivateKey = ${server_private}
Address = ${AWG_SERVER_ADDRESS}
ListenPort = ${AWG_PORT}
MTU = ${AWG_MTU}
Jc = ${AWG_JC}
Jmin = ${AWG_JMIN}
Jmax = ${AWG_JMAX}
S1 = ${AWG_S1}
S2 = ${AWG_S2}
S3 = ${AWG_S3}
S4 = ${AWG_S4}
H1 = ${AWG_H1}
H2 = ${AWG_H2}
H3 = ${AWG_H3}
H4 = ${AWG_H4}

[Peer]
PublicKey = ${client_public}
PresharedKey = ${preshared_key}
AllowedIPs = ${AWG_CLIENT_ADDRESS}
CONF

  cat > "${AWG_DIR}/client.conf" <<CONF
[Interface]
PrivateKey = ${client_private}
Address = ${AWG_CLIENT_ADDRESS}
MTU = ${AWG_MTU}
Jc = ${AWG_JC}
Jmin = ${AWG_JMIN}
Jmax = ${AWG_JMAX}
S1 = ${AWG_S1}
S2 = ${AWG_S2}
S3 = ${AWG_S3}
S4 = ${AWG_S4}
H1 = ${AWG_H1}
H2 = ${AWG_H2}
H3 = ${AWG_H3}
H4 = ${AWG_H4}

[Peer]
PublicKey = ${server_public}
PresharedKey = ${preshared_key}
AllowedIPs = 0.0.0.0/0
Endpoint = ${BPC_RU_HOST}:${AWG_PORT}
PersistentKeepalive = 25
CONF

  cat > "${AWG_DIR}/clash-verge.yaml" <<CONF
mixed-port: 7897
allow-lan: false
mode: rule
log-level: info
ipv6: false

proxies:
  - name: BPC-RU-AWG-01
    type: wireguard
    server: ${BPC_RU_HOST}
    port: ${AWG_PORT}
    ip: 10.251.0.2
    private-key: ${client_private}
    public-key: ${server_public}
    pre-shared-key: ${preshared_key}
    allowed-ips: ['0.0.0.0/0']
    persistent-keepalive: 25
    udp: true
    mtu: ${AWG_MTU}
    amnezia-wg-option:
      version: 2
      jc: ${AWG_JC}
      jmin: ${AWG_JMIN}
      jmax: ${AWG_JMAX}
      s1: ${AWG_S1}
      s2: ${AWG_S2}
      s3: ${AWG_S3}
      s4: ${AWG_S4}
      h1: ${AWG_H1}
      h2: ${AWG_H2}
      h3: ${AWG_H3}
      h4: ${AWG_H4}

proxy-groups:
  - name: BPC-RUSSIA
    type: select
    proxies:
      - BPC-RU-AWG-01

rules:
  - MATCH,BPC-RUSSIA
CONF

  cat > "${AWG_DIR}/transport.yaml" <<CONF
- name: RU-AWG-01
  type: amneziawg
  enabled: true
  priority: 20
  settings:
    server: ${BPC_RU_HOST}
    port: ${AWG_PORT}
    client_ip: 10.251.0.2/32
    mtu: ${AWG_MTU}
    private_key: ${client_private}
    public_key: ${server_public}
    preshared_key: ${preshared_key}
    version: 2
    jc: ${AWG_JC}
    jmin: ${AWG_JMIN}
    jmax: ${AWG_JMAX}
    s1: ${AWG_S1}
    s2: ${AWG_S2}
    s3: ${AWG_S3}
    s4: ${AWG_S4}
    h1: ${AWG_H1}
    h2: ${AWG_H2}
    h3: ${AWG_H3}
    h4: ${AWG_H4}
CONF

  cat > "${AWG_DIR}/start.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  awg-quick down /etc/amnezia/amneziawg/awg0.conf >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

awg-quick up /etc/amnezia/amneziawg/awg0.conf
while true; do
  sleep 3600 &
  wait $!
done
SCRIPT

  cat > "${AWG_DIR}/runtime.env" <<CONF
AWG_IMAGE=${AWG_IMAGE}
AWG_CONTAINER=${AWG_CONTAINER}
AWG_INTERFACE=${AWG_INTERFACE}
AWG_PORT=${AWG_PORT}
AWG_SUBNET=${AWG_SUBNET}
CONF

  chmod 0700 "${AWG_DIR}/start.sh"
  chmod 0600 "${AWG_DIR}/${AWG_INTERFACE}.conf" "${AWG_DIR}/client.conf" \
    "${AWG_DIR}/clash-verge.yaml" "${AWG_DIR}/transport.yaml" "${AWG_DIR}/runtime.env"
  touch "${AWG_DIR}/enabled"
  chmod 0600 "${AWG_DIR}/enabled"
fi

cat > /etc/sysctl.d/90-bpc-awg.conf <<SYSCTL
net.ipv4.ip_forward=1
SYSCTL
sysctl -q -p /etc/sysctl.d/90-bpc-awg.conf

cat > /usr/local/sbin/bpc-awg-firewall <<EOF_FIREWALL
#!/usr/bin/env bash
set -euo pipefail
ACTION="\${1:-up}"
AWG_INTERFACE="${AWG_INTERFACE}"
AWG_SUBNET="${AWG_SUBNET}"
DEFAULT_IF="\$(ip -4 route show default | awk 'NR==1 {print \$5}')"
if [[ -z "\${DEFAULT_IF}" ]]; then
  echo "Unable to determine default IPv4 interface" >&2
  exit 1
fi
case "\${ACTION}" in
  up)
    iptables -C FORWARD -i "\${AWG_INTERFACE}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "\${AWG_INTERFACE}" -j ACCEPT
    iptables -C FORWARD -o "\${AWG_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o "\${AWG_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -C POSTROUTING -s "\${AWG_SUBNET}" -o "\${DEFAULT_IF}" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "\${AWG_SUBNET}" -o "\${DEFAULT_IF}" -j MASQUERADE
    ;;
  down)
    iptables -D FORWARD -i "\${AWG_INTERFACE}" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "\${AWG_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "\${AWG_SUBNET}" -o "\${DEFAULT_IF}" -j MASQUERADE 2>/dev/null || true
    ;;
  *)
    echo "Usage: bpc-awg-firewall [up|down]" >&2
    exit 2
    ;;
esac
EOF_FIREWALL
chmod 0755 /usr/local/sbin/bpc-awg-firewall

cat > /etc/systemd/system/bpc-awg-firewall.service <<'UNIT'
[Unit]
Description=BPC AmneziaWG forwarding and NAT
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/bpc-awg-firewall up
ExecStop=/usr/local/sbin/bpc-awg-firewall down

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now bpc-awg-firewall.service

if docker ps -a --format '{{.Names}}' | grep -Fxq "${AWG_CONTAINER}"; then
  docker rm -f "${AWG_CONTAINER}" >/dev/null
fi

docker run -d \
  --name "${AWG_CONTAINER}" \
  --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  -v "${AWG_DIR}:/etc/amnezia/amneziawg:ro" \
  "${AWG_IMAGE}" \
  /bin/bash /etc/amnezia/amneziawg/start.sh >/dev/null

sleep 2
if ! docker ps --format '{{.Names}}' | grep -Fxq "${AWG_CONTAINER}"; then
  docker logs "${AWG_CONTAINER}" >&2 || true
  echo "BPC AmneziaWG container failed to start" >&2
  exit 5
fi
if ! docker exec "${AWG_CONTAINER}" awg show "${AWG_INTERFACE}" >/dev/null; then
  docker logs "${AWG_CONTAINER}" >&2 || true
  echo "AmneziaWG interface ${AWG_INTERFACE} is not healthy" >&2
  exit 5
fi

cat <<DONE
BPC AmneziaWG 2.0 is active.

Endpoint: ${BPC_RU_HOST}:${AWG_PORT}/udp
Native client config:
  ${AWG_DIR}/client.conf
Clash Verge Rev profile:
  ${AWG_DIR}/clash-verge.yaml

Keep TCP/${AWG_PORT} for Xray and permit UDP/${AWG_PORT} in the provider firewall.
DONE
