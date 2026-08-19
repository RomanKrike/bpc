#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
IKE_DIR="${RU_DIR}/ikev2"
TLS_HOST=""
CERT_EMAIL=""
IKE_USER="${BPC_IKEV2_USER:-bpc}"
IKE_POOL="${BPC_IKEV2_POOL:-10.254.0.0/24}"
SWANCTL_MAIN="/etc/swanctl/swanctl.conf"
SWANCTL_DROPIN="/etc/swanctl/conf.d/bpc-ikev2.conf"
SWAN_CERT="/etc/swanctl/x509/bpc-ikev2-cert.pem"
SWAN_CA="/etc/swanctl/x509ca/bpc-ikev2-chain.pem"
SWAN_KEY="/etc/swanctl/private/bpc-ikev2-key.pem"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'USAGE'
Usage: bpc-enable-ikev2 --hostname HOST [--email EMAIL]

Enables a native strongSwan IKEv2 roadwarrior fallback with EAP-MSCHAPv2.
The hostname must resolve directly to the RU node and is used as the IKEv2
server identity. A trusted Let's Encrypt certificate is reused or obtained.

This is an OS-level/manual fallback and is intentionally not inserted into
Clash/Mihomo BPC-AUTO.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostname) TLS_HOST="${2:-}"; shift 2 ;;
    --email) CERT_EMAIL="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-enable-ikev2 as root" >&2
  exit 1
fi
if [[ -z "${TLS_HOST}" ]]; then
  echo "--hostname is required" >&2
  exit 2
fi
if ! [[ "${TLS_HOST}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || [[ "${TLS_HOST}" != *.* ]]; then
  echo "Invalid IKEv2 hostname: ${TLS_HOST}" >&2
  exit 2
fi
if ! [[ "${IKE_USER}" =~ ^[A-Za-z0-9_.@-]{1,64}$ ]]; then
  echo "BPC_IKEV2_USER contains unsupported characters" >&2
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
apt-get install -y --no-install-recommends \
  ca-certificates certbot charon-systemd iproute2 iptables \
  libcharon-extauth-plugins libcharon-extra-plugins \
  libstrongswan-extra-plugins libstrongswan-standard-plugins \
  openssl strongswan-swanctl

resolved_ipv4="$(getent ahostsv4 "${TLS_HOST}" | awk '$2 == "STREAM" {print $1; exit}')"
if [[ -z "${resolved_ipv4}" ]]; then
  echo "IKEv2 hostname does not resolve to IPv4: ${TLS_HOST}" >&2
  exit 3
fi
if [[ "${BPC_RU_HOST}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && \
  [[ "${resolved_ipv4}" != "${BPC_RU_HOST}" ]]; then
  echo "${TLS_HOST} resolves to ${resolved_ipv4}, expected RU endpoint ${BPC_RU_HOST}" >&2
  echo "Use a DNS-only A record pointing directly at the RU node." >&2
  exit 3
fi

cert_leaf="/etc/letsencrypt/live/${TLS_HOST}/cert.pem"
cert_chain="/etc/letsencrypt/live/${TLS_HOST}/chain.pem"
key="/etc/letsencrypt/live/${TLS_HOST}/privkey.pem"
if [[ ! -s "${cert_leaf}" || ! -s "${cert_chain}" || ! -s "${key}" ]]; then
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
if [[ ! -s "${cert_leaf}" || ! -s "${cert_chain}" || ! -s "${key}" ]]; then
  echo "TLS certificate provisioning failed for ${TLS_HOST}" >&2
  exit 3
fi

install -d -m 0700 "${IKE_DIR}"
install -d -m 0755 \
  /etc/swanctl/conf.d /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private

if [[ -f "${IKE_DIR}/enabled" ]]; then
  if [[ ! -s "${IKE_DIR}/runtime.env" ]]; then
    echo "Enabled IKEv2 state has no runtime.env" >&2
    exit 4
  fi
  # shellcheck disable=SC1090,SC1091
  source "${IKE_DIR}/runtime.env"
  echo "BPC IKEv2 is already configured; keeping the EAP credential."
else
  IKE_PASSWORD="$(openssl rand -base64 24 | tr -d '\r\n' | tr '/+' '_-')"
  cat > "${IKE_DIR}/runtime.env" <<STATE
IKEV2_HOST=${TLS_HOST}
IKEV2_USER=${IKE_USER}
IKEV2_PASSWORD=${IKE_PASSWORD}
IKEV2_POOL=${IKE_POOL}
STATE
  chmod 0600 "${IKE_DIR}/runtime.env"
fi

# shellcheck disable=SC1090,SC1091
source "${IKE_DIR}/runtime.env"
# Values below are guaranteed by the root-only runtime.env schema written above.
# shellcheck disable=SC2153
TLS_HOST="${IKEV2_HOST}"
# shellcheck disable=SC2153
IKE_USER="${IKEV2_USER}"
# shellcheck disable=SC2153
IKE_PASSWORD="${IKEV2_PASSWORD}"
# shellcheck disable=SC2153
IKE_POOL="${IKEV2_POOL}"
cert_leaf="/etc/letsencrypt/live/${TLS_HOST}/cert.pem"
cert_chain="/etc/letsencrypt/live/${TLS_HOST}/chain.pem"
key="/etc/letsencrypt/live/${TLS_HOST}/privkey.pem"

if [[ ! -s "${cert_leaf}" || ! -s "${cert_chain}" || ! -s "${key}" ]]; then
  echo "Persisted IKEv2 certificate state is missing for ${TLS_HOST}" >&2
  exit 4
fi
install -m 0644 "${cert_leaf}" "${SWAN_CERT}"
install -m 0644 "${cert_chain}" "${SWAN_CA}"
install -m 0600 "${key}" "${SWAN_KEY}"

if [[ ! -f "${SWANCTL_MAIN}" ]]; then
  printf 'include conf.d/*.conf\n' > "${SWANCTL_MAIN}"
elif ! grep -Eq '^[[:space:]]*include[[:space:]]+conf\.d/\*\.conf[[:space:]]*$' "${SWANCTL_MAIN}"; then
  cp -a "${SWANCTL_MAIN}" "${SWANCTL_MAIN}.bpc-backup"
  printf '\n# BPC managed connection drop-ins\ninclude conf.d/*.conf\n' >> "${SWANCTL_MAIN}"
fi

cat > "${SWANCTL_DROPIN}" <<CONF
connections {
  bpc-ikev2 {
    version = 2
    local_addrs = 0.0.0.0
    pools = bpc-v4
    fragmentation = yes
    dpd_delay = 30s
    reauth_time = 0

    local {
      auth = pubkey
      certs = bpc-ikev2-cert.pem
      id = ${TLS_HOST}
    }
    remote {
      auth = eap-mschapv2
      eap_id = %any
    }
    children {
      bpc-ikev2 {
        local_ts = 0.0.0.0/0
        dpd_action = clear
      }
    }
  }
}

pools {
  bpc-v4 {
    addrs = ${IKE_POOL}
    dns = 1.1.1.1, 8.8.8.8
  }
}

secrets {
  eap-bpc {
    id = ${IKE_USER}
    secret = "${IKE_PASSWORD}"
  }
}
CONF
chmod 0600 "${SWANCTL_DROPIN}"

cat > /etc/sysctl.d/93-bpc-ikev2.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
SYSCTL
sysctl -q -p /etc/sysctl.d/93-bpc-ikev2.conf

cat > /usr/local/sbin/bpc-ikev2-firewall <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RUNTIME_ENV="${BPC_STATE_DIR}/ru-node/ikev2/runtime.env"
ACTION="${1:-up}"

if [[ ! -f "${RUNTIME_ENV}" ]]; then
  echo "IKEv2 runtime metadata is missing" >&2
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
    iptables -C FORWARD -s "${IKEV2_POOL}" -m policy --dir in --pol ipsec -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -s "${IKEV2_POOL}" -m policy --dir in --pol ipsec -j ACCEPT
    iptables -C FORWARD -d "${IKEV2_POOL}" -m policy --dir out --pol ipsec \
      -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -d "${IKEV2_POOL}" -m policy --dir out --pol ipsec \
        -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -C POSTROUTING -s "${IKEV2_POOL}" -o "${DEFAULT_IF}" \
      -m policy --dir out --pol ipsec -j ACCEPT 2>/dev/null || \
      iptables -t nat -I POSTROUTING 1 -s "${IKEV2_POOL}" -o "${DEFAULT_IF}" \
        -m policy --dir out --pol ipsec -j ACCEPT
    iptables -t nat -C POSTROUTING -s "${IKEV2_POOL}" -o "${DEFAULT_IF}" -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -s "${IKEV2_POOL}" -o "${DEFAULT_IF}" -j MASQUERADE
    ;;
  down)
    iptables -D FORWARD -s "${IKEV2_POOL}" -m policy --dir in --pol ipsec -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -d "${IKEV2_POOL}" -m policy --dir out --pol ipsec \
      -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "${IKEV2_POOL}" -o "${DEFAULT_IF}" \
      -m policy --dir out --pol ipsec -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "${IKEV2_POOL}" -o "${DEFAULT_IF}" -j MASQUERADE 2>/dev/null || true
    ;;
  *)
    echo "Usage: bpc-ikev2-firewall [up|down]" >&2
    exit 2
    ;;
esac
SCRIPT
chmod 0755 /usr/local/sbin/bpc-ikev2-firewall

cat > /etc/systemd/system/bpc-ikev2-firewall.service <<'UNIT'
[Unit]
Description=BPC IKEv2 forwarding and NAT
After=network-online.target strongswan.service
Wants=network-online.target
Requires=strongswan.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/bpc-ikev2-firewall up
ExecStop=/usr/local/sbin/bpc-ikev2-firewall down

[Install]
WantedBy=multi-user.target
UNIT

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/bpc-ikev2 <<HOOK
#!/usr/bin/env bash
set -euo pipefail
install -m 0644 /etc/letsencrypt/live/${TLS_HOST}/cert.pem ${SWAN_CERT}
install -m 0644 /etc/letsencrypt/live/${TLS_HOST}/chain.pem ${SWAN_CA}
install -m 0600 /etc/letsencrypt/live/${TLS_HOST}/privkey.pem ${SWAN_KEY}
if systemctl --quiet is-enabled strongswan.service 2>/dev/null; then
  systemctl restart strongswan.service
fi
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/bpc-ikev2
systemctl enable certbot.timer >/dev/null 2>&1 || true

systemctl daemon-reload
systemctl enable strongswan.service >/dev/null
systemctl restart strongswan.service
if ! swanctl --load-all >/dev/null; then
  journalctl -u strongswan.service -n 30 --no-pager >&2 || true
  echo "strongSwan failed to load the BPC IKEv2 configuration" >&2
  exit 5
fi
systemctl enable bpc-ikev2-firewall.service >/dev/null
systemctl restart bpc-ikev2-firewall.service

if ! systemctl --quiet is-active strongswan.service; then
  systemctl status strongswan.service --no-pager >&2 || true
  exit 5
fi
if ! systemctl --quiet is-active bpc-ikev2-firewall.service; then
  echo "BPC IKEv2 firewall service is not active" >&2
  exit 5
fi

cat > "${IKE_DIR}/client-info.txt" <<INFO
BPC IKEv2 client
Server: ${TLS_HOST}
VPN type: IKEv2
Authentication: Username and password (EAP-MSCHAPv2)
Username: ${IKE_USER}
Password: ${IKE_PASSWORD}

Required provider firewall ports:
  UDP/500
  UDP/4500

Windows built-in VPN:
  Provider: Windows (built-in)
  Server name/address: ${TLS_HOST}
  VPN type: IKEv2
  Sign-in type: User name and password

This is a full-tunnel OS-level fallback. Do not run it underneath or above a
corporate VPN unless that nested-VPN arrangement is explicitly supported by
the corporate VPN policy/client.
INFO
chmod 0600 "${IKE_DIR}/client-info.txt"
touch "${IKE_DIR}/enabled"
chmod 0600 "${IKE_DIR}/enabled"

cat <<DONE
BPC IKEv2 fallback is active.
Endpoint: ${TLS_HOST}:500/udp + ${TLS_HOST}:4500/udp
Client details: ${IKE_DIR}/client-info.txt

Credentials are stored root-only and are not printed.
IKEv2 is an OS-level/manual fallback and is not part of the Clash subscription.
DONE
