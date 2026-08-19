#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
SERVER_DIR="${RU_DIR}/mihomo-server"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MIHOMO_VERSION="${BPC_MIHOMO_VERSION:-v1.19.29}"
TLS_HOST=""
CERT_EMAIL=""
HY2_PORT="${BPC_HY2_PORT:-8443}"
TUIC_PORT="${BPC_TUIC_PORT:-10443}"
ANYTLS_PORT="${BPC_ANYTLS_PORT:-10443}"
SHADOWTLS_PORT="${BPC_SHADOWTLS_PORT:-9443}"
TROJAN_PORT="${BPC_TROJAN_PORT:-12443}"
MIERU_PORT="${BPC_MIERU_PORT:-2999}"
TRUSTTUNNEL_PORT="${BPC_TRUSTTUNNEL_PORT:-11443}"
SHADOWTLS_TARGET="${BPC_SHADOWTLS_TARGET:-www.bing.com:443}"

usage() {
  cat <<'USAGE'
Usage: bpc-enable-mihomo-transports --hostname HOST [options]

Enables the BPC Mihomo transport pack on the RU node:
  Hysteria2, TUIC v5, AnyTLS, Shadowsocks 2022 + ShadowTLS,
  Trojan, Mieru and TrustTunnel.

Options:
  --hostname HOST        TLS hostname whose A record points to this RU node
  --email EMAIL          Optional Let's Encrypt registration email
  --hy2-port PORT        Hysteria2 UDP port (default: 8443)
  --tuic-port PORT       TUIC v5 UDP port (default: 10443)
  --anytls-port PORT     AnyTLS TCP port (default: 10443)
  --shadowtls-port PORT  Shadowsocks+ShadowTLS TCP port (default: 9443)
  --trojan-port PORT     Trojan TCP port (default: 12443)
  --mieru-port PORT      Mieru TCP port (default: 2999)
  --trust-port PORT      TrustTunnel TCP+UDP port (default: 11443)
  -h, --help             Show this help

TCP and UDP may safely reuse the same numeric port. The defaults intentionally
share 10443 between TUIC/UDP and AnyTLS/TCP.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostname) TLS_HOST="${2:-}"; shift 2 ;;
    --email) CERT_EMAIL="${2:-}"; shift 2 ;;
    --hy2-port) HY2_PORT="${2:-}"; shift 2 ;;
    --tuic-port) TUIC_PORT="${2:-}"; shift 2 ;;
    --anytls-port) ANYTLS_PORT="${2:-}"; shift 2 ;;
    --shadowtls-port) SHADOWTLS_PORT="${2:-}"; shift 2 ;;
    --trojan-port) TROJAN_PORT="${2:-}"; shift 2 ;;
    --mieru-port) MIERU_PORT="${2:-}"; shift 2 ;;
    --trust-port) TRUSTTUNNEL_PORT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-enable-mihomo-transports as root" >&2
  exit 1
fi

if [[ -z "${TLS_HOST}" ]]; then
  echo "--hostname is required" >&2
  exit 2
fi
if ! [[ "${TLS_HOST}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || [[ "${TLS_HOST}" != *.* ]]; then
  echo "Invalid TLS hostname: ${TLS_HOST}" >&2
  exit 2
fi

for spec in \
  "HY2_PORT:${HY2_PORT}" \
  "TUIC_PORT:${TUIC_PORT}" \
  "ANYTLS_PORT:${ANYTLS_PORT}" \
  "SHADOWTLS_PORT:${SHADOWTLS_PORT}" \
  "TROJAN_PORT:${TROJAN_PORT}" \
  "MIERU_PORT:${MIERU_PORT}" \
  "TRUSTTUNNEL_PORT:${TRUSTTUNNEL_PORT}"; do
  name="${spec%%:*}"
  value="${spec#*:}"
  if ! [[ "${value}" =~ ^[0-9]+$ ]] || (( value < 1024 || value > 65535 )); then
    echo "${name} must be between 1024 and 65535" >&2
    exit 2
  fi
done

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
apt-get install -y --no-install-recommends ca-certificates certbot curl gzip openssl python3 iproute2

resolved_ipv4="$(getent ahostsv4 "${TLS_HOST}" | awk '$2 == "STREAM" {print $1; exit}')"
if [[ -z "${resolved_ipv4}" ]]; then
  echo "TLS hostname does not resolve to IPv4: ${TLS_HOST}" >&2
  exit 3
fi
if [[ "${BPC_RU_HOST}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && \
  [[ "${resolved_ipv4}" != "${BPC_RU_HOST}" ]]; then
  echo "${TLS_HOST} resolves to ${resolved_ipv4}, expected RU endpoint ${BPC_RU_HOST}" >&2
  echo "Use a DNS-only A record pointing directly at the RU node." >&2
  exit 3
fi

cert="/etc/letsencrypt/live/${TLS_HOST}/fullchain.pem"
key="/etc/letsencrypt/live/${TLS_HOST}/privkey.pem"
if [[ ! -s "${cert}" || ! -s "${key}" ]]; then
  if ss -H -ltn 'sport = :80' | grep -q .; then
    echo "TCP/80 is in use; Certbot standalone HTTP-01 cannot obtain the certificate" >&2
    exit 3
  fi
  certbot_args=(certonly --standalone --non-interactive --agree-tos -d "${TLS_HOST}")
  if [[ -n "${CERT_EMAIL}" ]]; then
    certbot_args+=(--email "${CERT_EMAIL}")
  else
    certbot_args+=(--register-unsafely-without-email)
  fi
  certbot "${certbot_args[@]}"
fi
if [[ ! -s "${cert}" || ! -s "${key}" ]]; then
  echo "TLS certificate provisioning failed for ${TLS_HOST}" >&2
  exit 3
fi

install_mihomo() {
  local arch asset release_json asset_path digest expected actual tmp
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) asset="mihomo-linux-amd64-compatible-${MIHOMO_VERSION}.gz" ;;
    aarch64|arm64) asset="mihomo-linux-arm64-${MIHOMO_VERSION}.gz" ;;
    *) echo "Unsupported architecture for BPC Mihomo server: ${arch}" >&2; return 1 ;;
  esac

  if [[ -x /usr/local/bin/bpc-mihomo ]] && \
    /usr/local/bin/bpc-mihomo -v 2>/dev/null | grep -Fq "${MIHOMO_VERSION#v}"; then
    return 0
  fi

  tmp="$(mktemp -d)"
  release_json="${tmp}/release.json"
  asset_path="${tmp}/${asset}"
  curl --fail --location --proto '=https' --tlsv1.2 \
    "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/${MIHOMO_VERSION}" \
    -o "${release_json}"
  digest="$(python3 - "${release_json}" "${asset}" <<'PY'
import json
import sys

release = json.load(open(sys.argv[1], encoding="utf-8"))
name = sys.argv[2]
for asset in release.get("assets", []):
    if asset.get("name") == name:
        digest = asset.get("digest") or ""
        if digest.startswith("sha256:"):
            print(digest.removeprefix("sha256:"))
        break
PY
)"
  if ! [[ "${digest}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    rm -rf "${tmp}"
    echo "GitHub release does not provide a usable SHA-256 digest for ${asset}" >&2
    return 1
  fi

  curl --fail --location --proto '=https' --tlsv1.2 \
    "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/${asset}" \
    -o "${asset_path}"
  actual="$(sha256sum "${asset_path}" | awk '{print $1}')"
  expected="${digest,,}"
  if [[ "${actual}" != "${expected}" ]]; then
    rm -rf "${tmp}"
    echo "Mihomo SHA-256 verification failed for ${asset}" >&2
    return 1
  fi

  gzip -dc "${asset_path}" > "${tmp}/mihomo"
  install -m 0755 "${tmp}/mihomo" /usr/local/bin/bpc-mihomo
  rm -rf "${tmp}"
}

install_mihomo

if [[ ! -f "${SERVER_DIR}/enabled" ]]; then
  declare -a port_checks=(
    "udp:${HY2_PORT}:Hysteria2"
    "udp:${TUIC_PORT}:TUIC"
    "tcp:${ANYTLS_PORT}:AnyTLS"
    "tcp:${SHADOWTLS_PORT}:ShadowTLS"
    "tcp:${TROJAN_PORT}:Trojan"
    "tcp:${MIERU_PORT}:Mieru"
    "tcp:${TRUSTTUNNEL_PORT}:TrustTunnel"
    "udp:${TRUSTTUNNEL_PORT}:TrustTunnel"
  )
  for check in "${port_checks[@]}"; do
    proto="${check%%:*}"
    rest="${check#*:}"
    port="${rest%%:*}"
    label="${rest#*:}"
    if [[ "${proto}" == "tcp" ]]; then
      in_use="$(ss -H -ltn "sport = :${port}" || true)"
    else
      in_use="$(ss -H -lun "sport = :${port}" || true)"
    fi
    if [[ -n "${in_use}" ]]; then
      echo "${label} ${proto^^} port ${port} is already in use" >&2
      exit 3
    fi
  done
fi

install -d -m 0700 "${SERVER_DIR}" "${SERVER_DIR}/home"
state_env="${SERVER_DIR}/runtime.env"
if [[ -f "${SERVER_DIR}/enabled" ]]; then
  if [[ ! -s "${state_env}" ]]; then
    echo "Enabled Mihomo transport pack has no runtime.env" >&2
    exit 4
  fi
  # shellcheck disable=SC1090,SC1091
  source "${state_env}"
  echo "BPC Mihomo transport pack already exists; keeping transport credentials."
else
  umask 077
  HY2_PASSWORD="$(openssl rand -hex 24)"
  HY2_OBFS_PASSWORD="$(openssl rand -hex 24)"
  TUIC_UUID="$(cat /proc/sys/kernel/random/uuid)"
  TUIC_PASSWORD="$(openssl rand -hex 24)"
  ANYTLS_PASSWORD="$(openssl rand -hex 24)"
  SS_PASSWORD="$(openssl rand -base64 32 | tr -d '\r\n')"
  SHADOWTLS_PASSWORD="$(openssl rand -hex 24)"
  TROJAN_PASSWORD="$(openssl rand -hex 24)"
  MIERU_USERNAME="bpc"
  MIERU_PASSWORD="$(openssl rand -hex 24)"
  TRUSTTUNNEL_USERNAME="bpc"
  TRUSTTUNNEL_PASSWORD="$(openssl rand -hex 24)"

  cat > "${state_env}" <<STATE
MIHOMO_VERSION=${MIHOMO_VERSION}
TLS_HOST=${TLS_HOST}
TLS_CERT=${cert}
TLS_KEY=${key}
HY2_PORT=${HY2_PORT}
HY2_PASSWORD=${HY2_PASSWORD}
HY2_OBFS_PASSWORD=${HY2_OBFS_PASSWORD}
TUIC_PORT=${TUIC_PORT}
TUIC_UUID=${TUIC_UUID}
TUIC_PASSWORD=${TUIC_PASSWORD}
ANYTLS_PORT=${ANYTLS_PORT}
ANYTLS_PASSWORD=${ANYTLS_PASSWORD}
SHADOWTLS_PORT=${SHADOWTLS_PORT}
SHADOWTLS_PASSWORD=${SHADOWTLS_PASSWORD}
SS_PASSWORD=${SS_PASSWORD}
TROJAN_PORT=${TROJAN_PORT}
TROJAN_PASSWORD=${TROJAN_PASSWORD}
MIERU_PORT=${MIERU_PORT}
MIERU_USERNAME=${MIERU_USERNAME}
MIERU_PASSWORD=${MIERU_PASSWORD}
TRUSTTUNNEL_PORT=${TRUSTTUNNEL_PORT}
TRUSTTUNNEL_USERNAME=${TRUSTTUNNEL_USERNAME}
TRUSTTUNNEL_PASSWORD=${TRUSTTUNNEL_PASSWORD}
SHADOWTLS_TARGET=${SHADOWTLS_TARGET}
STATE
  chmod 0600 "${state_env}"
fi

# Reuse the saved hostname/ports on repeated invocations so credentials and
# generated client profiles always stay aligned with the active server state.
# shellcheck disable=SC1090,SC1091
source "${state_env}"
cert="${TLS_CERT}"
key="${TLS_KEY}"

server_config="${SERVER_DIR}/config.yaml"
cat > "${server_config}" <<CONFIG
mode: rule
log-level: info
ipv6: false

listeners:
  - name: bpc-hy2-in
    type: hysteria2
    port: ${HY2_PORT}
    listen: 0.0.0.0
    users:
      bpc: "${HY2_PASSWORD}"
    up: 1000
    down: 1000
    ignore-client-bandwidth: true
    obfs: salamander
    obfs-password: "${HY2_OBFS_PASSWORD}"
    alpn: [h3]
    certificate: "${cert}"
    private-key: "${key}"

  - name: bpc-tuic-in
    type: tuic
    port: ${TUIC_PORT}
    listen: 0.0.0.0
    users:
      "${TUIC_UUID}": "${TUIC_PASSWORD}"
    certificate: "${cert}"
    private-key: "${key}"
    congestion-controller: bbr
    max-idle-time: 15000
    authentication-timeout: 1000
    alpn: [h3]
    max-udp-relay-packet-size: 1500

  - name: bpc-anytls-in
    type: anytls
    port: ${ANYTLS_PORT}
    listen: 0.0.0.0
    users:
      bpc: "${ANYTLS_PASSWORD}"
    certificate: "${cert}"
    private-key: "${key}"

  - name: bpc-shadowtls-in
    type: shadowsocks
    port: ${SHADOWTLS_PORT}
    listen: 0.0.0.0
    cipher: 2022-blake3-aes-256-gcm
    password: "${SS_PASSWORD}"
    udp: true
    shadow-tls:
      enable: true
      version: 2
      password: "${SHADOWTLS_PASSWORD}"
      handshake:
        dest: "${SHADOWTLS_TARGET}"

  - name: bpc-trojan-in
    type: trojan
    port: ${TROJAN_PORT}
    listen: 0.0.0.0
    users:
      - username: bpc
        password: "${TROJAN_PASSWORD}"
    certificate: "${cert}"
    private-key: "${key}"

  - name: bpc-mieru-in
    type: mieru
    port: ${MIERU_PORT}
    listen: 0.0.0.0
    transport: TCP
    users:
      "${MIERU_USERNAME}": "${MIERU_PASSWORD}"
    user-hint-is-mandatory: true

  - name: bpc-trusttunnel-in
    type: trusttunnel
    port: ${TRUSTTUNNEL_PORT}
    listen: 0.0.0.0
    users:
      - username: "${TRUSTTUNNEL_USERNAME}"
        password: "${TRUSTTUNNEL_PASSWORD}"
    certificate: "${cert}"
    private-key: "${key}"
    network: [tcp, udp]
    congestion-controller: bbr

rules:
  - MATCH,DIRECT
CONFIG
chmod 0600 "${server_config}"

write_profile() {
  local transport="$1"
  local content="$2"
  local dir="${RU_DIR}/${transport}"
  install -d -m 0700 "${dir}"
  printf '%s\n' "${content}" > "${dir}/clash-verge.yaml"
  chmod 0600 "${dir}/clash-verge.yaml"
  touch "${dir}/enabled"
  chmod 0600 "${dir}/enabled"
}

write_profile hy2 "$(cat <<PROFILE
proxies:
  - name: BPC-RU-HY2-01
    type: hysteria2
    server: ${BPC_RU_HOST}
    port: ${HY2_PORT}
    password: \"${HY2_PASSWORD}\"
    obfs: salamander
    obfs-password: \"${HY2_OBFS_PASSWORD}\"
    sni: ${TLS_HOST}
    skip-cert-verify: false
    alpn: [h3]
PROFILE
)"

write_profile tuic "$(cat <<PROFILE
proxies:
  - name: BPC-RU-TUIC-01
    type: tuic
    server: ${BPC_RU_HOST}
    port: ${TUIC_PORT}
    uuid: ${TUIC_UUID}
    password: \"${TUIC_PASSWORD}\"
    sni: ${TLS_HOST}
    alpn: [h3]
    skip-cert-verify: false
    reduce-rtt: true
    udp-relay-mode: native
    congestion-controller: bbr
PROFILE
)"

write_profile anytls "$(cat <<PROFILE
proxies:
  - name: BPC-RU-ANYTLS-01
    type: anytls
    server: ${BPC_RU_HOST}
    port: ${ANYTLS_PORT}
    password: \"${ANYTLS_PASSWORD}\"
    client-fingerprint: chrome
    udp: true
    sni: ${TLS_HOST}
    alpn: [h2, http/1.1]
    skip-cert-verify: false
PROFILE
)"

shadowtls_host="${SHADOWTLS_TARGET%%:*}"
write_profile shadowtls "$(cat <<PROFILE
proxies:
  - name: BPC-RU-SHADOWTLS-01
    type: ss
    server: ${BPC_RU_HOST}
    port: ${SHADOWTLS_PORT}
    cipher: 2022-blake3-aes-256-gcm
    password: \"${SS_PASSWORD}\"
    udp: true
    plugin: shadow-tls
    client-fingerprint: chrome
    plugin-opts:
      host: ${shadowtls_host}
      password: \"${SHADOWTLS_PASSWORD}\"
      version: 2
PROFILE
)"

write_profile trojan "$(cat <<PROFILE
proxies:
  - name: BPC-RU-TROJAN-01
    type: trojan
    server: ${BPC_RU_HOST}
    port: ${TROJAN_PORT}
    password: \"${TROJAN_PASSWORD}\"
    udp: true
    sni: ${TLS_HOST}
    alpn: [h2, http/1.1]
    client-fingerprint: chrome
    skip-cert-verify: false
PROFILE
)"

write_profile mieru "$(cat <<PROFILE
proxies:
  - name: BPC-RU-MIERU-01
    type: mieru
    server: ${BPC_RU_HOST}
    port: ${MIERU_PORT}
    transport: TCP
    username: \"${MIERU_USERNAME}\"
    password: \"${MIERU_PASSWORD}\"
    multiplexing: MULTIPLEXING_LOW
PROFILE
)"

write_profile trusttunnel "$(cat <<PROFILE
proxies:
  - name: BPC-RU-TRUST-01
    type: trusttunnel
    server: ${BPC_RU_HOST}
    port: ${TRUSTTUNNEL_PORT}
    username: \"${TRUSTTUNNEL_USERNAME}\"
    password: \"${TRUSTTUNNEL_PASSWORD}\"
    health-check: true
    udp: true
    sni: ${TLS_HOST}
    alpn: [h2]
    skip-cert-verify: false
    quic: true
    congestion-controller: bbr
PROFILE
)"

/usr/local/bin/bpc-mihomo -t -d "${SERVER_DIR}/home" -f "${server_config}"

cat > /etc/systemd/system/bpc-mihomo-transports.service <<UNIT
[Unit]
Description=BPC Mihomo multi-protocol transport server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bpc-mihomo -d ${SERVER_DIR}/home -f ${server_config}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${SERVER_DIR}

[Install]
WantedBy=multi-user.target
UNIT

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/bpc-mihomo-transports <<'HOOK'
#!/usr/bin/env bash
set -euo pipefail
if systemctl --quiet is-enabled bpc-mihomo-transports.service 2>/dev/null; then
  systemctl restart bpc-mihomo-transports.service
fi
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/bpc-mihomo-transports
systemctl enable certbot.timer >/dev/null 2>&1 || true

systemctl daemon-reload
systemctl enable bpc-mihomo-transports.service >/dev/null
systemctl restart bpc-mihomo-transports.service
if ! systemctl --quiet is-active bpc-mihomo-transports.service; then
  systemctl status bpc-mihomo-transports.service --no-pager >&2 || true
  exit 5
fi

touch "${SERVER_DIR}/enabled"
chmod 0600 "${SERVER_DIR}/enabled"

if [[ -x "${SCRIPT_DIR}/bpc-render-clash.sh" ]]; then
  "${SCRIPT_DIR}/bpc-render-clash.sh"
fi

cat <<DONE
BPC Mihomo transport pack is active.
TLS hostname: ${TLS_HOST}
Mihomo: ${MIHOMO_VERSION}

Endpoints:
  Hysteria2:              ${BPC_RU_HOST}:${HY2_PORT}/udp
  TUIC v5:                ${BPC_RU_HOST}:${TUIC_PORT}/udp
  AnyTLS:                 ${BPC_RU_HOST}:${ANYTLS_PORT}/tcp
  Shadowsocks+ShadowTLS:  ${BPC_RU_HOST}:${SHADOWTLS_PORT}/tcp
  Trojan:                 ${BPC_RU_HOST}:${TROJAN_PORT}/tcp
  Mieru:                  ${BPC_RU_HOST}:${MIERU_PORT}/tcp
  TrustTunnel:            ${BPC_RU_HOST}:${TRUSTTUNNEL_PORT}/tcp+udp

Credentials are stored root-only under ${RU_DIR} and are not printed.
Update the BPC Clash subscription/profile after this command completes.
DONE
