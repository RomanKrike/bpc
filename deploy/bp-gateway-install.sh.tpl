#!/usr/bin/env bash
set -euo pipefail

NAME="@@NAME@@"
RELAY="@@RELAY@@"
TCP_RELAY="@@TCP_RELAY@@"
OVERLAY="@@OVERLAY@@"
SERVER_OVERLAY_IP="@@SERVER_OVERLAY_IP@@"
GATEWAY_ADDRESS="@@GATEWAY_ADDRESS@@"
SERVER_PUBLIC_KEY="@@SERVER_PUBLIC_KEY@@"
GATEWAY_PRIVATE_KEY="@@GATEWAY_PRIVATE_KEY@@"
WGSHIM_PSK="@@WGSHIM_PSK@@"
MTU="@@MTU@@"
KEEPALIVE="@@KEEPALIVE@@"
PADDING_MIN="@@PADDING_MIN@@"
PADDING_MAX="@@PADDING_MAX@@"
ROUTES_CSV="@@ROUTES_CSV@@"

REPO="${BPC_REPO:-RomanKrike/bpc}"
STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}/bp-gateway"
WG_IF="${BP_GATEWAY_WG_INTERFACE:-bpgw0}"
WGSHIM_LISTEN="${BP_GATEWAY_WGSHIM_LISTEN:-127.0.0.1:24081}"
TRANSPORT="${BP_GATEWAY_TRANSPORT:-auto}"
PROBE_INTERVAL="${BP_GATEWAY_PROBE_INTERVAL:-15s}"
PROBE_TIMEOUT="${BP_GATEWAY_PROBE_TIMEOUT:-750ms}"
SWITCH_THRESHOLD="${BP_GATEWAY_SWITCH_THRESHOLD:-5ms}"
LAN_IF="${BP_GATEWAY_LAN_INTERFACE:-}"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run the BP Gateway installer as root" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl iproute2 iptables python3 wireguard-tools

IFS=',' read -r -a ROUTES <<< "${ROUTES_CSV}"
if (( ${#ROUTES[@]} == 0 )); then
  echo "BP Gateway has no home routes" >&2
  exit 3
fi

if [[ -z "${LAN_IF}" ]]; then
  first_route="${ROUTES[0]}"
  probe_ip="$(python3 - "${first_route}" <<'PY'
import ipaddress
import sys
network = ipaddress.ip_network(sys.argv[1], strict=False)
print(next(network.hosts(), network.network_address))
PY
)"
  LAN_IF="$(ip -4 route get "${probe_ip}" 2>/dev/null | awk '
    {
      for (i = 1; i <= NF; i++) {
        if ($i == "dev" && (i + 1) <= NF) {
          print $(i + 1)
          exit
        }
      }
    }'
  )"
fi
if [[ -z "${LAN_IF}" || ! "${LAN_IF}" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
  echo "Unable to determine the home LAN interface." >&2
  echo "Retry with BP_GATEWAY_LAN_INTERFACE=vmbr0 (or the correct interface)." >&2
  exit 3
fi

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 3 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
asset="bpc-wgshim-linux-${arch}"
base="https://github.com/${REPO}/releases/latest/download"
curl --fail --location --proto '=https' --tlsv1.2 "${base}/${asset}" -o "${tmp}/${asset}"
curl --fail --location --proto '=https' --tlsv1.2 "${base}/SHA256SUMS" -o "${tmp}/SHA256SUMS"
checksum_line="$(grep -E "([[:space:]]|\*)${asset}$" "${tmp}/SHA256SUMS" | head -n1 || true)"
if [[ -z "${checksum_line}" ]]; then
  echo "SHA256SUMS does not contain ${asset}" >&2
  exit 3
fi
(
  cd "${tmp}"
  printf '%s\n' "${checksum_line}" | sha256sum --check --strict -
)
install -m 0755 "${tmp}/${asset}" /usr/local/bin/bpc-wgshim

case "${TRANSPORT}" in
  auto)
    WGSHIM_EXEC="client-auto --listen ${WGSHIM_LISTEN} --udp-server ${RELAY} --tcp-server ${TCP_RELAY} --probe-interval ${PROBE_INTERVAL} --probe-timeout ${PROBE_TIMEOUT} --switch-threshold ${SWITCH_THRESHOLD}"
    ;;
  udp)
    WGSHIM_EXEC="client --listen ${WGSHIM_LISTEN} --server ${RELAY}"
    ;;
  tcp)
    WGSHIM_EXEC="client-tcp --listen ${WGSHIM_LISTEN} --server ${TCP_RELAY}"
    ;;
  *)
    echo "BP_GATEWAY_TRANSPORT must be auto, udp, or tcp" >&2
    exit 2
    ;;
esac

install -d -m 0700 "${STATE_DIR}" /etc/wireguard
printf '%s\n' "${WGSHIM_PSK}" > "${STATE_DIR}/wgshim.key"
chmod 0600 "${STATE_DIR}/wgshim.key"

cat > "/etc/wireguard/${WG_IF}.conf" <<EOF
[Interface]
Address = ${GATEWAY_ADDRESS}
PrivateKey = ${GATEWAY_PRIVATE_KEY}
MTU = ${MTU}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
AllowedIPs = ${OVERLAY}
Endpoint = ${WGSHIM_LISTEN}
PersistentKeepalive = ${KEEPALIVE}
EOF
chmod 0600 "/etc/wireguard/${WG_IF}.conf"

cat > "${STATE_DIR}/runtime.env" <<EOF
BP_GATEWAY_NAME=${NAME}
BP_GATEWAY_WG_INTERFACE=${WG_IF}
BP_GATEWAY_LAN_INTERFACE=${LAN_IF}
BP_GATEWAY_OVERLAY=${OVERLAY}
BP_GATEWAY_ROUTES=${ROUTES_CSV}
BP_GATEWAY_TRANSPORT=${TRANSPORT}
BP_GATEWAY_UDP_RELAY=${RELAY}
BP_GATEWAY_TCP_RELAY=${TCP_RELAY}
EOF
chmod 0600 "${STATE_DIR}/runtime.env"

cat > /etc/sysctl.d/93-bp-gateway.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
sysctl -q -p /etc/sysctl.d/93-bp-gateway.conf

cat > /usr/local/sbin/bp-gateway-firewall <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RUNTIME="${BPC_STATE_DIR}/bp-gateway/runtime.env"
ACTION="${1:-up}"
# shellcheck disable=SC1090,SC1091
source "${RUNTIME}"
IFS=',' read -r -a ROUTES <<< "${BP_GATEWAY_ROUTES}"
case "${ACTION}" in
  up)
    iptables -C FORWARD -i "${BP_GATEWAY_WG_INTERFACE}" -o "${BP_GATEWAY_LAN_INTERFACE}" -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -i "${BP_GATEWAY_WG_INTERFACE}" -o "${BP_GATEWAY_LAN_INTERFACE}" -j ACCEPT
    iptables -C FORWARD -i "${BP_GATEWAY_LAN_INTERFACE}" -o "${BP_GATEWAY_WG_INTERFACE}" \
      -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -i "${BP_GATEWAY_LAN_INTERFACE}" -o "${BP_GATEWAY_WG_INTERFACE}" \
        -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    for route in "${ROUTES[@]}"; do
      iptables -t nat -C POSTROUTING -s "${BP_GATEWAY_OVERLAY}" -d "${route}" \
        -o "${BP_GATEWAY_LAN_INTERFACE}" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "${BP_GATEWAY_OVERLAY}" -d "${route}" \
          -o "${BP_GATEWAY_LAN_INTERFACE}" -j MASQUERADE
    done
    ;;
  down)
    iptables -D FORWARD -i "${BP_GATEWAY_WG_INTERFACE}" -o "${BP_GATEWAY_LAN_INTERFACE}" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "${BP_GATEWAY_LAN_INTERFACE}" -o "${BP_GATEWAY_WG_INTERFACE}" \
      -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    for route in "${ROUTES[@]}"; do
      iptables -t nat -D POSTROUTING -s "${BP_GATEWAY_OVERLAY}" -d "${route}" \
        -o "${BP_GATEWAY_LAN_INTERFACE}" -j MASQUERADE >/dev/null || true
    done
    ;;
  *) echo "Usage: bp-gateway-firewall [up|down]" >&2; exit 2 ;;
esac
EOF
chmod 0755 /usr/local/sbin/bp-gateway-firewall

cat > /etc/systemd/system/bp-gateway-wgshim.service <<EOF
[Unit]
Description=BP Gateway relay transport
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bpc-wgshim ${WGSHIM_EXEC} --key-file ${STATE_DIR}/wgshim.key --padding-min ${PADDING_MIN} --padding-max ${PADDING_MAX} --stats-interval 30s
Restart=always
RestartSec=1
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths=${STATE_DIR}

[Install]
WantedBy=multi-user.target
EOF

install -d -m 0755 "/etc/systemd/system/wg-quick@${WG_IF}.service.d"
cat > "/etc/systemd/system/wg-quick@${WG_IF}.service.d/10-bp-gateway.conf" <<EOF
[Unit]
After=bp-gateway-wgshim.service
Requires=bp-gateway-wgshim.service
EOF

cat > /etc/systemd/system/bp-gateway-firewall.service <<EOF
[Unit]
Description=BP Gateway forwarding and NAT
After=wg-quick@${WG_IF}.service
Requires=wg-quick@${WG_IF}.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/bp-gateway-firewall up
ExecStop=/usr/local/sbin/bp-gateway-firewall down

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable bp-gateway-wgshim.service "wg-quick@${WG_IF}.service" bp-gateway-firewall.service >/dev/null
systemctl restart bp-gateway-wgshim.service
systemctl restart "wg-quick@${WG_IF}.service"
systemctl restart bp-gateway-firewall.service

sleep 1
if ! systemctl --quiet is-active bp-gateway-wgshim.service || \
   ! systemctl --quiet is-active "wg-quick@${WG_IF}.service"; then
  systemctl status bp-gateway-wgshim.service "wg-quick@${WG_IF}.service" --no-pager >&2 || true
  exit 5
fi

if ! ping -c 2 -W 2 "${SERVER_OVERLAY_IP}" >/dev/null 2>&1; then
  echo "BP Gateway services are running, but the relay handshake is not confirmed." >&2
  echo "Check: systemctl status bp-gateway-wgshim wg-quick@${WG_IF}" >&2
  exit 5
fi

echo "BP Gateway ${NAME} is connected to BP Network."
echo "Home routes: ${ROUTES_CSV}"
echo "LAN interface: ${LAN_IF}"
echo "Transport policy: ${TRANSPORT} (UDP ${RELAY}; TCP ${TCP_RELAY})"
echo "BP overlay address: ${GATEWAY_ADDRESS}"
