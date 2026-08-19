#!/usr/bin/env bash
set -euo pipefail

REPO="${BPC_REPO:-RomanKrike/bpc}"
BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
ROLE="ru-node"
REALITY_SERVER_NAME=""
XRAY_PORT="443"
BPC_PUBLIC_HOST=""
WITH_AWG="false"
AWG_PORT="443"
WITH_WG="false"
WG_PORT="51820"

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

Options:
  --role ru-node                 Node role (currently only ru-node)
  --reality-server-name HOST     Required REALITY target hostname
  --port PORT                    Xray TCP listen port (default: 443)
  --public-host HOST             Public VPS IPv4/FQDN (auto-detected by default)
  --with-awg                     Also enable AmneziaWG 2.0
  --awg-port PORT                AmneziaWG UDP listen port (default: 443)
  --with-wg                      Also enable native WireGuard
  --wg-port PORT                 WireGuard UDP listen port (default: 51820)
  -h, --help                     Show this help
USAGE
}

ensure_bootstrap_dns() {
  local dropin server
  local dns_servers="${BPC_DNS_SERVERS:-1.1.1.1 8.8.8.8}"
  local fallback_dns="${BPC_FALLBACK_DNS:-9.9.9.9 1.0.0.1}"

  if getent ahostsv4 github.com >/dev/null 2>&1 && \
    getent ahostsv4 deb.debian.org >/dev/null 2>&1; then
    return 0
  fi

  echo "DNS resolution is unavailable; attempting bootstrap repair."

  if systemctl cat systemd-resolved.service >/dev/null 2>&1; then
    dropin="/etc/systemd/resolved.conf.d/10-bpc-dns.conf"
    install -d -m 0755 "$(dirname "${dropin}")"
    cat > "${dropin}" <<RESOLVED
[Resolve]
DNS=${dns_servers}
FallbackDNS=${fallback_dns}
DNSSEC=allow-downgrade
RESOLVED
    systemctl enable systemd-resolved.service >/dev/null 2>&1 || true
    systemctl restart systemd-resolved.service
    if [[ -e /run/systemd/resolve/resolv.conf ]]; then
      if [[ -e /etc/resolv.conf && ! -L /etc/resolv.conf && \
        ! -e /etc/resolv.conf.bpc-backup ]]; then
        cp -a /etc/resolv.conf /etc/resolv.conf.bpc-backup 2>/dev/null || true
      fi
      ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null || true
    fi
    if command -v resolvectl >/dev/null 2>&1; then
      resolvectl flush-caches >/dev/null 2>&1 || true
    fi
  else
    if [[ -e /etc/resolv.conf && ! -e /etc/resolv.conf.bpc-backup ]]; then
      cp -a /etc/resolv.conf /etc/resolv.conf.bpc-backup 2>/dev/null || true
    fi
    rm -f /etc/resolv.conf 2>/dev/null || true
    {
      echo "# Managed by BPC bootstrap because DNS resolution was unavailable."
      for server in ${dns_servers}; do
        printf 'nameserver %s\n' "${server}"
      done
    } > /etc/resolv.conf
  fi

  for _ in 1 2 3 4 5; do
    if getent ahostsv4 github.com >/dev/null 2>&1 && \
      getent ahostsv4 deb.debian.org >/dev/null 2>&1; then
      echo "DNS bootstrap repair succeeded."
      return 0
    fi
    sleep 1
  done

  echo "DNS bootstrap repair failed." >&2
  echo "Configure working DNS or set BPC_DNS_SERVERS and retry." >&2
  return 3
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)
      ROLE="${2:-}"
      shift 2
      ;;
    --reality-server-name)
      REALITY_SERVER_NAME="${2:-}"
      shift 2
      ;;
    --port)
      XRAY_PORT="${2:-}"
      shift 2
      ;;
    --public-host)
      BPC_PUBLIC_HOST="${2:-}"
      shift 2
      ;;
    --with-awg)
      WITH_AWG="true"
      shift
      ;;
    --awg-port)
      AWG_PORT="${2:-}"
      shift 2
      ;;
    --with-wg)
      WITH_WG="true"
      shift
      ;;
    --wg-port)
      WG_PORT="${2:-}"
      shift 2
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
  echo "Run as root (for example: curl ... | sudo bash -s -- ...)" >&2
  exit 1
fi

if [[ "${ROLE}" != "ru-node" ]]; then
  echo "Unsupported role: ${ROLE}" >&2
  exit 2
fi

if [[ -z "${REALITY_SERVER_NAME}" && ! -f "${BPC_STATE_DIR}/ru-node/config.json" ]]; then
  echo "--reality-server-name is required for a fresh RU-node installation" >&2
  exit 2
fi

for port_spec in "XRAY_PORT:${XRAY_PORT}" "AWG_PORT:${AWG_PORT}" "WG_PORT:${WG_PORT}"; do
  name="${port_spec%%:*}"
  value="${port_spec#*:}"
  if ! [[ "${value}" =~ ^[0-9]+$ ]] || (( value < 1 || value > 65535 )); then
    echo "${name} must be between 1 and 65535" >&2
    exit 2
  fi
done

ensure_bootstrap_dns

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl tar

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
asset_base="https://github.com/${REPO}/releases/latest/download"

curl --fail --location --proto '=https' --tlsv1.2 \
  "${asset_base}/bpc-connect-deploy.tar.gz" -o "${tmp}/bpc-connect-deploy.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 \
  "${asset_base}/SHA256SUMS" -o "${tmp}/SHA256SUMS"

(
  cd "${tmp}"
  checksum_line="$(grep -E '([[:space:]]|\*)bpc-connect-deploy\.tar\.gz$' SHA256SUMS | head -n1 || true)"
  if [[ -z "${checksum_line}" ]]; then
    echo "SHA256SUMS does not contain bpc-connect-deploy.tar.gz" >&2
    exit 3
  fi
  printf '%s\n' "${checksum_line}" | sha256sum --check --strict -
)

mkdir -p "${tmp}/release"
tar -xzf "${tmp}/bpc-connect-deploy.tar.gz" -C "${tmp}/release"

if [[ ! -f "${tmp}/release/VERSION" ]]; then
  echo "Release bundle does not contain VERSION" >&2
  exit 3
fi
version="$(tr -d '[:space:]' < "${tmp}/release/VERSION")"
if ! [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid release version: ${version}" >&2
  exit 3
fi

release_dir="${BPC_ROOT}/releases/${version}"
old_target=""
if [[ -L "${BPC_ROOT}/current" ]]; then
  old_target="$(readlink -f "${BPC_ROOT}/current" || true)"
fi

install -d -m 0755 "${BPC_ROOT}/releases" "${BPC_STATE_DIR}"
if [[ ! -d "${release_dir}" ]]; then
  mv "${tmp}/release" "${release_dir}"
fi
chmod 0755 "${release_dir}/deploy/"*.sh
ln -sfn "${release_dir}" "${BPC_ROOT}/current"
ln -sfn "${BPC_ROOT}/current/deploy/bpc-update.sh" /usr/local/sbin/bpc-update
ln -sfn "${BPC_ROOT}/current/deploy/bpc-status.sh" /usr/local/sbin/bpc-status
ln -sfn "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh" /usr/local/sbin/bpc-ensure-dns
ln -sfn "${BPC_ROOT}/current/deploy/bpc-enable-awg.sh" /usr/local/sbin/bpc-enable-awg
ln -sfn "${BPC_ROOT}/current/deploy/bpc-enable-wg.sh" /usr/local/sbin/bpc-enable-wg

cat > "${BPC_STATE_DIR}/install.env" <<STATE
BPC_ROLE=${ROLE}
BPC_ROOT=${BPC_ROOT}
STATE
chmod 0600 "${BPC_STATE_DIR}/install.env"

rollback_release() {
  if [[ -n "${old_target}" && -d "${old_target}" ]]; then
    ln -sfn "${old_target}" "${BPC_ROOT}/current"
  else
    rm -f "${BPC_ROOT}/current"
  fi
}

if [[ -f "${BPC_STATE_DIR}/ru-node/config.json" ]]; then
  echo "Existing RU-node configuration found; keeping credentials and configuration."
  "${BPC_ROOT}/current/deploy/bpc-migrate.sh"
  if ! "${BPC_ROOT}/current/deploy/bpc-healthcheck.sh"; then
    rollback_release
    echo "Health check failed; restored previous BPC release." >&2
    exit 5
  fi
else
  export REALITY_SERVER_NAME XRAY_PORT BPC_PUBLIC_HOST
  if ! "${BPC_ROOT}/current/deploy/bootstrap-ru-node.sh"; then
    rollback_release
    echo "RU-node bootstrap failed; restored previous BPC release pointer." >&2
    exit 5
  fi
fi

if [[ "${WITH_AWG}" == "true" ]]; then
  "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh"
  AWG_PORT="${AWG_PORT}" "${BPC_ROOT}/current/deploy/bpc-enable-awg.sh"
fi
if [[ "${WITH_WG}" == "true" ]]; then
  "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh"
  WG_PORT="${WG_PORT}" "${BPC_ROOT}/current/deploy/bpc-enable-wg.sh"
fi

cat <<DONE
BPC ${version} installed successfully.

Role: ${ROLE}
Release: ${release_dir}
Current: ${BPC_ROOT}/current

Commands:
  bpc-status
  bpc-update
  bpc-ensure-dns
  bpc-enable-awg
  bpc-enable-wg

VLESS transport configuration:
  ${BPC_STATE_DIR}/ru-node/gateway-transport.yaml
DONE

if [[ -f "${BPC_STATE_DIR}/ru-node/awg/enabled" ]]; then
  cat <<DONE
AmneziaWG Clash Verge Rev profile:
  ${BPC_STATE_DIR}/ru-node/awg/clash-verge.yaml
DONE
fi

if [[ -f "${BPC_STATE_DIR}/ru-node/wg/enabled" ]]; then
  cat <<DONE
WireGuard native client config:
  ${BPC_STATE_DIR}/ru-node/wg/client.conf
WireGuard Clash Verge Rev profile:
  ${BPC_STATE_DIR}/ru-node/wg/clash-verge.yaml
DONE
fi
