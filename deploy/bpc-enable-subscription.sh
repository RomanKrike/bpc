#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
SUB_DIR="${RU_DIR}/subscription"
PROFILE="${RU_DIR}/clash-verge-auto.yaml"
HOSTNAME=""
PORT="8443"
EMAIL=""
SKIP_DNS_CHECK="false"

usage() {
  cat <<'USAGE'
Usage: bpc-enable-subscription --hostname HOST [options]

Options:
  --hostname HOST          Public DNS name for the subscription endpoint
  --port PORT              HTTPS listen port (default: 8443; must be >=1024)
  --email EMAIL            Optional Let's Encrypt account email
  --skip-dns-check         Skip verification that HOST resolves to this RU node
  -h, --help               Show this help

The command obtains a trusted Let's Encrypt certificate using HTTP-01 on TCP/80,
then serves the root-only aggregate Clash profile on a tokenized HTTPS URL.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostname)
      HOSTNAME="${2:-}"
      shift 2
      ;;
    --port)
      PORT="${2:-}"
      shift 2
      ;;
    --email)
      EMAIL="${2:-}"
      shift 2
      ;;
    --skip-dns-check)
      SKIP_DNS_CHECK="true"
      shift
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
  echo "Run bpc-enable-subscription as root" >&2
  exit 1
fi

if [[ -f "${SUB_DIR}/runtime.env" ]]; then
  # shellcheck disable=SC1090,SC1091
  source "${SUB_DIR}/runtime.env"
  HOSTNAME="${HOSTNAME:-${SUBSCRIPTION_HOST:-}}"
  PORT="${PORT:-${SUBSCRIPTION_PORT:-8443}}"
fi

if [[ -z "${HOSTNAME}" ]]; then
  echo "--hostname is required" >&2
  exit 2
fi
if ! [[ "${HOSTNAME}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || [[ "${HOSTNAME}" != *.* ]]; then
  echo "--hostname must be a valid DNS hostname" >&2
  exit 2
fi
if ! [[ "${PORT}" =~ ^[0-9]+$ ]] || (( PORT < 1024 || PORT > 65535 )); then
  echo "--port must be between 1024 and 65535" >&2
  exit 2
fi
if [[ -n "${EMAIL}" && ! "${EMAIL}" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
  echo "--email does not look like a valid email address" >&2
  exit 2
fi

if [[ ! -x "${BPC_ROOT}/current/deploy/bpc-render-clash.sh" ]]; then
  echo "bpc-render-clash is unavailable; update BPC first" >&2
  exit 2
fi
"${BPC_ROOT}/current/deploy/bpc-render-clash.sh"
if [[ ! -s "${PROFILE}" ]]; then
  echo "Aggregate Clash profile is missing: ${PROFILE}" >&2
  exit 3
fi

if [[ -x "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh" ]]; then
  "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates certbot curl openssl python3 iproute2

if [[ "${SKIP_DNS_CHECK}" != "true" ]]; then
  if ! getent ahostsv4 "${HOSTNAME}" >/dev/null 2>&1; then
    echo "${HOSTNAME} does not resolve to an IPv4 address yet" >&2
    echo "Create the DNS A record first, then retry." >&2
    exit 3
  fi

  client_env="${RU_DIR}/client.env"
  expected_host=""
  if [[ -f "${client_env}" ]]; then
    expected_host="$(sed -n 's/^BPC_RU_HOST=//p' "${client_env}" | head -n1)"
  fi
  if [[ -n "${expected_host}" ]]; then
    mapfile -t subscription_ips < <(getent ahostsv4 "${HOSTNAME}" | awk '{print $1}' | sort -u)
    if [[ "${expected_host}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      expected_ips=("${expected_host}")
    else
      mapfile -t expected_ips < <(getent ahostsv4 "${expected_host}" 2>/dev/null | awk '{print $1}' | sort -u)
    fi

    matched="false"
    for ip in "${subscription_ips[@]}"; do
      for expected_ip in "${expected_ips[@]:-}"; do
        if [[ "${ip}" == "${expected_ip}" ]]; then
          matched="true"
          break 2
        fi
      done
    done
    if [[ "${matched}" != "true" ]]; then
      echo "${HOSTNAME} does not resolve to the RU-node public address (${expected_host})." >&2
      echo "Fix DNS or retry with --skip-dns-check if a trusted reverse proxy is intentional." >&2
      exit 3
    fi
  fi
fi

cert_dir="/etc/letsencrypt/live/${HOSTNAME}"
cert_file="${cert_dir}/fullchain.pem"
key_file="${cert_dir}/privkey.pem"

if [[ ! -s "${cert_file}" || ! -s "${key_file}" ]]; then
  if ss -H -ltn 'sport = :80' | grep -q .; then
    echo "TCP/80 is already in use; Let's Encrypt standalone HTTP-01 cannot start." >&2
    echo "Free TCP/80 temporarily or provision the certificate manually, then retry." >&2
    exit 4
  fi

  certbot_args=(
    certonly --standalone --preferred-challenges http
    --non-interactive --agree-tos --keep-until-expiring
    --cert-name "${HOSTNAME}" -d "${HOSTNAME}"
  )
  if [[ -n "${EMAIL}" ]]; then
    certbot_args+=(--email "${EMAIL}")
  else
    certbot_args+=(--register-unsafely-without-email)
  fi
  certbot "${certbot_args[@]}"
fi

if [[ ! -s "${cert_file}" || ! -s "${key_file}" ]]; then
  echo "Let's Encrypt certificate files were not created for ${HOSTNAME}" >&2
  exit 4
fi

install -d -m 0700 "${SUB_DIR}"
token_file="${SUB_DIR}/token"
if [[ ! -s "${token_file}" ]]; then
  umask 077
  openssl rand -hex 32 > "${token_file}"
fi
chmod 0600 "${token_file}"

token="$(tr -d '\r\n' < "${token_file}")"
if ! [[ "${token}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Subscription token is invalid" >&2
  exit 5
fi

cat > "${SUB_DIR}/runtime.env" <<RUNTIME
SUBSCRIPTION_HOST=${HOSTNAME}
SUBSCRIPTION_PORT=${PORT}
SUBSCRIPTION_CERT=${cert_file}
SUBSCRIPTION_KEY=${key_file}
RUNTIME
chmod 0600 "${SUB_DIR}/runtime.env"

cat > /etc/systemd/system/bpc-subscription.service <<UNIT
[Unit]
Description=BPC secure Clash subscription endpoint
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${BPC_ROOT}/current/deploy/bpc-subscription-server.py --listen 0.0.0.0 --port ${PORT} --profile ${PROFILE} --token-file ${token_file} --cert-file ${cert_file} --key-file ${key_file}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictNamespaces=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/bpc-subscription <<'HOOK'
#!/usr/bin/env bash
set -euo pipefail
if systemctl --quiet is-enabled bpc-subscription.service 2>/dev/null; then
  systemctl restart bpc-subscription.service
fi
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/bpc-subscription

systemctl daemon-reload
systemctl enable --now bpc-subscription.service
systemctl enable --now certbot.timer >/dev/null 2>&1 || true

sleep 1
if ! systemctl --quiet is-active bpc-subscription.service; then
  systemctl status bpc-subscription.service --no-pager >&2 || true
  exit 5
fi

if ! curl --fail --silent --show-error --output /dev/null \
  --resolve "${HOSTNAME}:${PORT}:127.0.0.1" \
  "https://${HOSTNAME}:${PORT}/${token}/clash.yaml"; then
  echo "Local HTTPS subscription self-test failed" >&2
  systemctl status bpc-subscription.service --no-pager >&2 || true
  exit 5
fi

touch "${SUB_DIR}/enabled"
chmod 0600 "${SUB_DIR}/enabled"

cat <<DONE
BPC Clash subscription is active.

Endpoint: https://${HOSTNAME}:${PORT}/<secret-token>/clash.yaml
Subscription URL:
  https://${HOSTNAME}:${PORT}/${token}/clash.yaml

The URL contains credentials by reference. Keep it private.
Permit inbound TCP/${PORT} in the provider firewall.
Certificate renewal is handled by certbot.timer; BPC restarts the service after renewal.

Show the URL later with:
  bpc-subscription-url
DONE
