#!/usr/bin/env bash
set -euo pipefail

XRAY_VERSION="${XRAY_VERSION:-v26.3.27}"
XRAY_PORT="${XRAY_PORT:-443}"
REALITY_DEST_PORT="${REALITY_DEST_PORT:-443}"
REALITY_SERVER_NAME="${REALITY_SERVER_NAME:-}"
BPC_DIR="${BPC_DIR:-/etc/bpc-connect/ru-node}"
XRAY_INSTALL_URL="${XRAY_INSTALL_URL:-https://github.com/XTLS/Xray-install/raw/main/install-release.sh}"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

if [[ -z "${REALITY_SERVER_NAME}" ]]; then
  echo "REALITY_SERVER_NAME is required (example: REALITY_SERVER_NAME=www.example.com)" >&2
  exit 2
fi

if ! [[ "${XRAY_PORT}" =~ ^[0-9]+$ ]] || (( XRAY_PORT < 1 || XRAY_PORT > 65535 )); then
  echo "XRAY_PORT must be between 1 and 65535" >&2
  exit 2
fi

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl iproute2 openssl

if ss -H -ltn "sport = :${XRAY_PORT}" | grep -q .; then
  echo "TCP port ${XRAY_PORT} is already in use; choose another XRAY_PORT" >&2
  exit 3
fi

install -d -m 0700 "${BPC_DIR}"
installer="$(mktemp)"
trap 'rm -f "${installer}"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 "${XRAY_INSTALL_URL}" -o "${installer}"
bash "${installer}" install --version "${XRAY_VERSION}" --without-geodata

uuid="$(/usr/local/bin/xray uuid | tr -d '\r\n')"
key_output="$(/usr/local/bin/xray x25519)"
private_key="$(printf '%s\n' "${key_output}" | sed -n 's/^PrivateKey:[[:space:]]*//p' | head -n1)"
public_key="$(printf '%s\n' "${key_output}" | sed -n -E 's/^Password( \(PublicKey\))?:[[:space:]]*//p' | head -n1)"
short_id="$(openssl rand -hex 8)"

if [[ -z "${uuid}" || -z "${private_key}" || -z "${public_key}" || -z "${short_id}" ]]; then
  echo "Failed to generate Xray credentials" >&2
  exit 4
fi

cat > "${BPC_DIR}/config.json" <<JSON
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${XRAY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "${uuid}", "flow": "xtls-rprx-vision"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALITY_SERVER_NAME}:${REALITY_DEST_PORT}",
          "xver": 0,
          "serverNames": ["${REALITY_SERVER_NAME}"],
          "privateKey": "${private_key}",
          "shortIds": ["${short_id}"]
        }
      },
      "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
    }
  ],
  "outbounds": [
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "blocked"}
  ]
}
JSON

chmod 0600 "${BPC_DIR}/config.json"
/usr/local/bin/xray run -test -config "${BPC_DIR}/config.json"

install -d -m 0755 /etc/systemd/system/xray.service.d
cat > /etc/systemd/system/xray.service.d/20-bpc.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/xray run -config ${BPC_DIR}/config.json
EOF

cat > "${BPC_DIR}/client.env" <<EOF
BPC_RU_HOST=$(hostname -f 2>/dev/null || hostname)
BPC_RU_PORT=${XRAY_PORT}
BPC_VLESS_UUID=${uuid}
BPC_REALITY_SERVER_NAME=${REALITY_SERVER_NAME}
BPC_REALITY_PUBLIC_KEY=${public_key}
BPC_REALITY_SHORT_ID=${short_id}
EOF
chmod 0600 "${BPC_DIR}/client.env"

systemctl daemon-reload
systemctl enable --now xray
systemctl restart xray

if ! systemctl --quiet is-active xray; then
  systemctl status xray --no-pager >&2 || true
  exit 5
fi

cat <<EOF
BPC RU node is active.

Client values were written to:
  ${BPC_DIR}/client.env

IMPORTANT:
- Replace BPC_RU_HOST with the VPS public IP/FQDN if hostname is not publicly resolvable.
- Permit inbound TCP/${XRAY_PORT} in the VPS/provider firewall.
- Do not commit client.env or config.json; both contain credentials.
EOF
