#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
STATE_DIR="${BPC_STATE_DIR}/bp-gateway"
SERVICE_FILE="/etc/systemd/system/bp-gateway-wgshim.service"
RUNTIME="${STATE_DIR}/runtime.env"
REPO="${BPC_REPO:-RomanKrike/bpc}"
LOCAL_WGSHIM_BINARY="${BPC_WGSHIM_BINARY:-}"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bp-gateway-upgrade as root" >&2
  exit 1
fi
if [[ ! -s "${RUNTIME}" || ! -s "${STATE_DIR}/wgshim.key" || ! -s "${SERVICE_FILE}" ]]; then
  echo "Existing BP Gateway runtime is incomplete" >&2
  exit 3
fi

# shellcheck disable=SC1090,SC1091
source "${RUNTIME}"

exec_line="$(sed -n 's/^ExecStart=//p' "${SERVICE_FILE}" | head -n1)"
listen="${BP_GATEWAY_WGSHIM_LISTEN:-}"
if [[ -z "${listen}" ]]; then
  listen="$(sed -nE 's/.*--listen[[:space:]]+([^[:space:]]+).*/\1/p' <<< "${exec_line}" | head -n1)"
fi
udp_relay="${BP_GATEWAY_UDP_RELAY:-}"
if [[ -z "${udp_relay}" ]]; then
  udp_relay="$(sed -nE 's/.*--udp-server[[:space:]]+([^[:space:]]+).*/\1/p' <<< "${exec_line}" | head -n1)"
fi
if [[ -z "${udp_relay}" ]]; then
  udp_relay="$(sed -nE 's/.*--server[[:space:]]+([^[:space:]]+).*/\1/p' <<< "${exec_line}" | head -n1)"
fi
tcp_relay="${BP_GATEWAY_TCP_RELAY:-${udp_relay}}"
padding_min="$(sed -nE 's/.*--padding-min[[:space:]]+([^[:space:]]+).*/\1/p' <<< "${exec_line}" | head -n1)"
padding_max="$(sed -nE 's/.*--padding-max[[:space:]]+([^[:space:]]+).*/\1/p' <<< "${exec_line}" | head -n1)"
listen="${listen:-127.0.0.1:24081}"
padding_min="${padding_min:-0}"
padding_max="${padding_max:-31}"

if [[ -z "${udp_relay}" || -z "${tcp_relay}" ]]; then
  echo "Unable to determine BP Relay endpoint from the existing gateway service" >&2
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

if [[ -n "${LOCAL_WGSHIM_BINARY}" ]]; then
  if [[ ! -f "${LOCAL_WGSHIM_BINARY}" ]]; then
    echo "BPC_WGSHIM_BINARY does not exist: ${LOCAL_WGSHIM_BINARY}" >&2
    exit 3
  fi
  install -m 0755 "${LOCAL_WGSHIM_BINARY}" /usr/local/bin/bpc-wgshim
else
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
fi

cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=BP Gateway adaptive relay transport
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bpc-wgshim client-auto --listen ${listen} --udp-server ${udp_relay} --tcp-server ${tcp_relay} --probe-interval 15s --probe-timeout 750ms --switch-threshold 5ms --key-file ${STATE_DIR}/wgshim.key --padding-min ${padding_min} --padding-max ${padding_max} --stats-interval 30s
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

python3 - "${RUNTIME}" "${listen}" "${udp_relay}" "${tcp_relay}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
updates = {
    "BP_GATEWAY_WGSHIM_LISTEN": sys.argv[2],
    "BP_GATEWAY_TRANSPORT": "auto",
    "BP_GATEWAY_UDP_RELAY": sys.argv[3],
    "BP_GATEWAY_TCP_RELAY": sys.argv[4],
}
lines = path.read_text(encoding="utf-8").splitlines()
seen = set()
out = []
for line in lines:
    if "=" in line:
        key = line.split("=", 1)[0]
        if key in updates:
            out.append(f"{key}={updates[key]}")
            seen.add(key)
            continue
    out.append(line)
for key, value in updates.items():
    if key not in seen:
        out.append(f"{key}={value}")
path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
chmod 0600 "${RUNTIME}"

if [[ -z "${BP_GATEWAY_WG_INTERFACE:-}" || -z "${BP_GATEWAY_LAN_INTERFACE:-}" || \
      -z "${BP_GATEWAY_OVERLAY:-}" || -z "${BP_GATEWAY_ROUTES:-}" ]]; then
  echo "BP Gateway runtime is missing firewall routing metadata" >&2
  exit 3
fi

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
        -o "${BP_GATEWAY_LAN_INTERFACE}" -j MASQUERADE >/dev/null 2>&1 || true
    done
    ;;
  *) echo "Usage: bp-gateway-firewall [up|down]" >&2; exit 2 ;;
esac
EOF
chmod 0755 /usr/local/sbin/bp-gateway-firewall

cat > /etc/systemd/system/bp-gateway-firewall.service <<EOF
[Unit]
Description=BP Gateway forwarding and NAT
After=wg-quick@${BP_GATEWAY_WG_INTERFACE}.service
Requires=wg-quick@${BP_GATEWAY_WG_INTERFACE}.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/bp-gateway-firewall up
ExecStop=/usr/local/sbin/bp-gateway-firewall down

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl restart bp-gateway-wgshim.service
systemctl enable bp-gateway-firewall.service >/dev/null
systemctl reset-failed bp-gateway-firewall.service >/dev/null 2>&1 || true
systemctl restart bp-gateway-firewall.service
sleep 1
if ! systemctl --quiet is-active bp-gateway-wgshim.service || \
   ! systemctl --quiet is-active bp-gateway-firewall.service; then
  systemctl status bp-gateway-wgshim.service bp-gateway-firewall.service --no-pager >&2 || true
  exit 5
fi

echo "BP Gateway transport upgraded to adaptive UDP/TCP."
echo "UDP relay: ${udp_relay}"
echo "TCP relay: ${tcp_relay}"
echo "Inspect selection: journalctl -u bp-gateway-wgshim.service -n 20 --no-pager"
