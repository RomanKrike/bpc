#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
OVPN_DIR="${RU_DIR}/openvpn"
OVPN_PORT="${BPC_OPENVPN_PORT:-1194}"
OVPN_PROTO="${BPC_OPENVPN_PROTO:-udp}"
OVPN_INTERFACE="${BPC_OPENVPN_INTERFACE:-bpcovpn}"
OVPN_SUBNET="${BPC_OPENVPN_SUBNET:-10.253.0.0/24}"
OVPN_SERVER_NETWORK="${BPC_OPENVPN_SERVER_NETWORK:-10.253.0.0}"
OVPN_SERVER_NETMASK="${BPC_OPENVPN_SERVER_NETMASK:-255.255.255.0}"
OVPN_CLIENT_IP="${BPC_OPENVPN_CLIENT_IP:-10.253.0.2}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-enable-openvpn as root" >&2
  exit 1
fi
if ! [[ "${OVPN_PORT}" =~ ^[0-9]+$ ]] || (( OVPN_PORT < 1 || OVPN_PORT > 65535 )); then
  echo "BPC_OPENVPN_PORT must be between 1 and 65535" >&2
  exit 2
fi
if [[ "${OVPN_PROTO}" != "udp" && "${OVPN_PROTO}" != "tcp" ]]; then
  echo "BPC_OPENVPN_PROTO must be udp or tcp" >&2
  exit 2
fi
if [[ ${#OVPN_INTERFACE} -gt 15 ]] || ! [[ "${OVPN_INTERFACE}" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo "BPC_OPENVPN_INTERFACE must be a valid Linux interface name no longer than 15 characters" >&2
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

if [[ -x "${SCRIPT_DIR}/bpc-ensure-dns.sh" ]]; then
  "${SCRIPT_DIR}/bpc-ensure-dns.sh"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates iproute2 iptables openvpn openssl

if [[ ! -f "${OVPN_DIR}/enabled" ]]; then
  if [[ "${OVPN_PROTO}" == "udp" ]]; then
    in_use="$(ss -H -lun "sport = :${OVPN_PORT}" || true)"
  else
    in_use="$(ss -H -ltn "sport = :${OVPN_PORT}" || true)"
  fi
  if [[ -n "${in_use}" ]]; then
    echo "OpenVPN ${OVPN_PROTO^^} port ${OVPN_PORT} is already in use" >&2
    exit 3
  fi
fi

install -d -m 0700 "${OVPN_DIR}" /etc/openvpn/server

if [[ -f "${OVPN_DIR}/enabled" ]]; then
  echo "BPC OpenVPN is already configured; keeping existing credentials."
  for required in ca.crt ca.key server.crt server.key client.crt client.key tls-crypt.key \
    server.conf client.ovpn clash-verge.yaml runtime.env; do
    if [[ ! -s "${OVPN_DIR}/${required}" ]]; then
      echo "Enabled OpenVPN state is incomplete: ${required} is missing" >&2
      exit 4
    fi
  done
  # shellcheck disable=SC1090,SC1091
  source "${OVPN_DIR}/runtime.env"
else
  umask 077

  openssl genrsa -out "${OVPN_DIR}/ca.key" 3072 >/dev/null 2>&1
  openssl req -x509 -new -sha256 -days 3650 \
    -key "${OVPN_DIR}/ca.key" \
    -subj "/CN=BPC OpenVPN CA" \
    -out "${OVPN_DIR}/ca.crt"

  openssl genrsa -out "${OVPN_DIR}/server.key" 3072 >/dev/null 2>&1
  openssl req -new -sha256 \
    -key "${OVPN_DIR}/server.key" \
    -subj "/CN=BPC OpenVPN Server" \
    -out "${OVPN_DIR}/server.csr"
  cat > "${OVPN_DIR}/server.ext" <<'EXT'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
  openssl x509 -req -sha256 -days 825 \
    -in "${OVPN_DIR}/server.csr" \
    -CA "${OVPN_DIR}/ca.crt" \
    -CAkey "${OVPN_DIR}/ca.key" \
    -CAcreateserial \
    -extfile "${OVPN_DIR}/server.ext" \
    -out "${OVPN_DIR}/server.crt"

  openssl genrsa -out "${OVPN_DIR}/client.key" 3072 >/dev/null 2>&1
  openssl req -new -sha256 \
    -key "${OVPN_DIR}/client.key" \
    -subj "/CN=BPC OpenVPN Client" \
    -out "${OVPN_DIR}/client.csr"
  cat > "${OVPN_DIR}/client.ext" <<'EXT'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
  openssl x509 -req -sha256 -days 825 \
    -in "${OVPN_DIR}/client.csr" \
    -CA "${OVPN_DIR}/ca.crt" \
    -CAkey "${OVPN_DIR}/ca.key" \
    -CAserial "${OVPN_DIR}/ca.srl" \
    -extfile "${OVPN_DIR}/client.ext" \
    -out "${OVPN_DIR}/client.crt"

  openvpn --genkey secret "${OVPN_DIR}/tls-crypt.key"
  rm -f "${OVPN_DIR}/server.csr" "${OVPN_DIR}/server.ext" \
    "${OVPN_DIR}/client.csr" "${OVPN_DIR}/client.ext" "${OVPN_DIR}/ca.srl"

  cat > "${OVPN_DIR}/server.conf" <<CONF
port ${OVPN_PORT}
proto ${OVPN_PROTO}
dev ${OVPN_INTERFACE}
dev-type tun
topology subnet
server ${OVPN_SERVER_NETWORK} ${OVPN_SERVER_NETMASK}
ca ${OVPN_DIR}/ca.crt
cert ${OVPN_DIR}/server.crt
key ${OVPN_DIR}/server.key
tls-crypt ${OVPN_DIR}/tls-crypt.key
tls-version-min 1.2
data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
auth SHA256
reneg-sec 0
keepalive 10 60
persist-key
persist-tun
user nobody
group nogroup
explicit-exit-notify 1
verb 3
CONF

  ca_pem="$(cat "${OVPN_DIR}/ca.crt")"
  client_cert="$(cat "${OVPN_DIR}/client.crt")"
  client_key="$(cat "${OVPN_DIR}/client.key")"
  tls_crypt="$(cat "${OVPN_DIR}/tls-crypt.key")"

  cat > "${OVPN_DIR}/client.ovpn" <<CONF
client
dev tun
proto ${OVPN_PROTO}
remote ${BPC_RU_HOST} ${OVPN_PORT}
remote-cert-tls server
nobind
persist-key
persist-tun
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
reneg-sec 0
verb 3
<ca>
${ca_pem}
</ca>
<cert>
${client_cert}
</cert>
<key>
${client_key}
</key>
<tls-crypt>
${tls_crypt}
</tls-crypt>
CONF

  indent_pem() {
    sed 's/^/      /' "$1"
  }

  cat > "${OVPN_DIR}/clash-verge.yaml" <<CONF
proxies:
  - name: BPC-RU-OPENVPN-01
    type: openvpn
    server: ${BPC_RU_HOST}
    port: ${OVPN_PORT}
    proto: ${OVPN_PROTO}
    dev: tun
    cipher: AES-256-GCM
    auth: SHA256
    ping: 10
    ping-restart: 60
    udp: true
    ca: |-
$(indent_pem "${OVPN_DIR}/ca.crt")
    cert: |-
$(indent_pem "${OVPN_DIR}/client.crt")
    key: |-
$(indent_pem "${OVPN_DIR}/client.key")
    tls-crypt: |-
$(indent_pem "${OVPN_DIR}/tls-crypt.key")
CONF

  cat > "${OVPN_DIR}/runtime.env" <<STATE
OPENVPN_PORT=${OVPN_PORT}
OPENVPN_PROTO=${OVPN_PROTO}
OPENVPN_INTERFACE=${OVPN_INTERFACE}
OPENVPN_SUBNET=${OVPN_SUBNET}
OPENVPN_CLIENT_IP=${OVPN_CLIENT_IP}
STATE

  chmod 0600 "${OVPN_DIR}"/*
  touch "${OVPN_DIR}/enabled"
  chmod 0600 "${OVPN_DIR}/enabled"
fi

install -m 0600 "${OVPN_DIR}/server.conf" /etc/openvpn/server/bpc.conf

cat > /etc/sysctl.d/92-bpc-openvpn.conf <<'SYSCTL'
net.ipv4.ip_forward=1
SYSCTL
sysctl -q -p /etc/sysctl.d/92-bpc-openvpn.conf

cat > /usr/local/sbin/bpc-openvpn-firewall <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RUNTIME_ENV="${BPC_STATE_DIR}/ru-node/openvpn/runtime.env"
ACTION="${1:-up}"

if [[ ! -f "${RUNTIME_ENV}" ]]; then
  echo "OpenVPN runtime metadata is missing" >&2
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
    iptables -C FORWARD -i "${OPENVPN_INTERFACE}" -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -i "${OPENVPN_INTERFACE}" -j ACCEPT
    iptables -C FORWARD -o "${OPENVPN_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -o "${OPENVPN_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -C POSTROUTING -s "${OPENVPN_SUBNET}" -o "${DEFAULT_IF}" -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -s "${OPENVPN_SUBNET}" -o "${DEFAULT_IF}" -j MASQUERADE
    ;;
  down)
    iptables -D FORWARD -i "${OPENVPN_INTERFACE}" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "${OPENVPN_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "${OPENVPN_SUBNET}" -o "${DEFAULT_IF}" -j MASQUERADE 2>/dev/null || true
    ;;
  *)
    echo "Usage: bpc-openvpn-firewall [up|down]" >&2
    exit 2
    ;;
esac
SCRIPT
chmod 0755 /usr/local/sbin/bpc-openvpn-firewall

cat > /etc/systemd/system/bpc-openvpn-firewall.service <<UNIT
[Unit]
Description=BPC OpenVPN forwarding and NAT
After=network-online.target openvpn-server@bpc.service
Wants=network-online.target
Requires=openvpn-server@bpc.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/bpc-openvpn-firewall up
ExecStop=/usr/local/sbin/bpc-openvpn-firewall down

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable openvpn-server@bpc.service >/dev/null
systemctl restart openvpn-server@bpc.service
systemctl enable bpc-openvpn-firewall.service >/dev/null
systemctl restart bpc-openvpn-firewall.service

if ! systemctl --quiet is-active openvpn-server@bpc.service; then
  systemctl status openvpn-server@bpc.service --no-pager >&2 || true
  echo "OpenVPN service failed to start" >&2
  exit 5
fi
if ! ip link show "${OVPN_INTERFACE}" >/dev/null 2>&1; then
  echo "OpenVPN interface ${OVPN_INTERFACE} is unavailable" >&2
  exit 5
fi
if ! systemctl --quiet is-active bpc-openvpn-firewall.service; then
  echo "BPC OpenVPN firewall service is not active" >&2
  exit 5
fi

if [[ -x "${SCRIPT_DIR}/bpc-render-clash.sh" ]]; then
  "${SCRIPT_DIR}/bpc-render-clash.sh"
fi

cat <<DONE
BPC OpenVPN fallback is active.
Endpoint: ${BPC_RU_HOST}:${OVPN_PORT}/${OVPN_PROTO}
Native client profile: ${OVPN_DIR}/client.ovpn
Mihomo client profile: ${OVPN_DIR}/clash-verge.yaml

OpenVPN is exposed as a manual BPC-ROUTE fallback, not as a default BPC-AUTO
transport. Mihomo v1.19.29 has a known upstream server-initiated rekey issue;
this BPC server disables time-based renegotiation with reneg-sec 0, but manual
selection remains the safer default until upstream fixes the client implementation.
DONE
