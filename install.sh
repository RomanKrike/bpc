#!/usr/bin/env bash
set -euo pipefail

REPO="${BPC_REPO:-RomanKrike/bpc}"
BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
ROLE=""
REALITY_SERVER_NAME=""
XRAY_PORT="443"
BPC_PUBLIC_HOST=""
BPC_NODE_NAME=""
WITH_AWG="false"
AWG_PORT="443"
WITH_WG="false"
WG_PORT="51820"
JOIN_TOKEN=""

usage() {
  cat <<'USAGE'
Usage: install.sh [options]
       install.sh join BPC-...

Options:
  --role ru-node                 Optional legacy RU gateway bootstrap
  --reality-server-name HOST     Required REALITY target hostname
  --port PORT                    Xray TCP listen port (default: 443)
  --public-host HOST             Public VPS IPv4/FQDN (auto-detected by default)
  --node-name NAME               Unified BPC Node name (default: system hostname)
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
    systemctl restart systemd-resolved.service >/dev/null 2>&1 || true
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
  fi

  for _ in 1 2 3 4 5; do
    if getent ahostsv4 github.com >/dev/null 2>&1 && \
      getent ahostsv4 deb.debian.org >/dev/null 2>&1; then
      echo "DNS bootstrap repair succeeded."
      return 0
    fi
    sleep 1
  done

  echo "system resolver repair was insufficient; trying a static fallback." >&2
  if [[ -e /etc/resolv.conf && ! -e /etc/resolv.conf.bpc-backup ]]; then
    cp -a /etc/resolv.conf /etc/resolv.conf.bpc-backup 2>/dev/null || true
  fi
  rm -f /etc/resolv.conf 2>/dev/null || true
  if ! {
    echo "# Managed by BPC bootstrap because DNS resolution was unavailable."
    for server in ${dns_servers}; do
      printf 'nameserver %s\n' "${server}"
    done
  } > /etc/resolv.conf; then
    echo "Unable to write the static DNS fallback to /etc/resolv.conf." >&2
    return 3
  fi

  for _ in 1 2 3; do
    if getent ahostsv4 github.com >/dev/null 2>&1 && \
      getent ahostsv4 deb.debian.org >/dev/null 2>&1; then
      echo "DNS bootstrap repair succeeded with static resolvers."
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
    join)
      if [[ $# -ne 2 || ! "${2:-}" =~ ^BPC-[A-Za-z0-9_-]+\.[0-9a-fA-F]{64}$ ]]; then
        echo "Usage: install.sh join BPC-..." >&2
        exit 2
      fi
      JOIN_TOKEN="$2"
      shift 2
      ;;
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
    --node-name)
      BPC_NODE_NAME="${2:-}"
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

# Reject unsupported hosts before package installation or network changes.
# shellcheck disable=SC1091
source /etc/os-release
case "${ID}:${VERSION_ID}" in
  debian:12|debian:13|ubuntu:24.04) ;;
  *) echo "Unsupported OS: ${ID} ${VERSION_ID}; use Debian 12/13 or Ubuntu 24.04" >&2; exit 2 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) BPC_ARCH="amd64" ;;
  aarch64|arm64) BPC_ARCH="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac
export BPC_ROOT BPC_STATE_DIR

if [[ -n "${JOIN_TOKEN}" && ( -n "${ROLE}" || "${WITH_AWG}" == "true" || "${WITH_WG}" == "true" ) ]]; then
  echo "join cannot be combined with legacy transport bootstrap options" >&2
  exit 2
fi

# A repeat bootstrap resumes the installed release. Updates remain the job of
# bpc-update, with its backup, migration and rollback lifecycle.
if [[ -n "${JOIN_TOKEN}" && -s "${BPC_ROOT}/current/VERSION" && \
      -x "${BPC_ROOT}/current/deploy/bpc.sh" ]]; then
  exec "${BPC_ROOT}/current/deploy/bpc.sh" join "${JOIN_TOKEN}"
fi

if [[ -n "${ROLE}" && "${ROLE}" != "ru-node" ]]; then
  echo "Unsupported legacy install profile: ${ROLE}" >&2
  exit 2
fi

if [[ "${ROLE}" == "ru-node" && -z "${REALITY_SERVER_NAME}" && \
  ! -f "${BPC_STATE_DIR}/ru-node/config.json" ]]; then
  echo "--reality-server-name is required with --role ru-node on a fresh gateway" >&2
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

if [[ -z "${JOIN_TOKEN}" ]]; then
  ensure_bootstrap_dns
elif ! getent ahostsv4 github.com >/dev/null 2>&1; then
  echo "DNS is unavailable; configure a working resolver before retrying join." >&2
  exit 3
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl tar openssl python3 python3-yaml python3-cryptography python3-argon2

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://api.github.com/repos/${REPO}/releases/latest" -o "${tmp}/release.json"
release_tag="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tag_name"])' "${tmp}/release.json")"
if ! [[ "${release_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid stable release tag" >&2
  exit 3
fi
asset_base="https://github.com/${REPO}/releases/download/${release_tag}"

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
if [[ "v${version}" != "${release_tag}" || \
      ! -x "${tmp}/release/bin/bpc-controld-linux-${BPC_ARCH}" || \
      ! -x "${tmp}/release/bin/bpc-agent-relay-linux-${BPC_ARCH}" ]]; then
  echo "Release bundle version or architecture does not match" >&2
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

for spec in \
  "bpc:bpc.sh" \
  "bpc-update:bpc-update.sh" \
  "bpc-status:bpc-status.sh" \
  "bpc-ensure-dns:bpc-ensure-dns.sh" \
  "bpc-render-clash:bpc-render-clash.sh" \
  "bpc-route-target:bpc-route-target.sh" \
  "bpc-enable-subscription:bpc-enable-subscription.sh" \
  "bpc-subscription-url:bpc-subscription-url.sh" \
  "bpc-enable-awg:bpc-enable-awg.sh" \
  "bpc-enable-wg:bpc-enable-wg.sh" \
  "bpc-enable-wgshim:bpc-enable-wgshim.sh" \
  "bpc-agent:bpc-agent.sh" \
  "bpc-node:bpc-node.sh" \
    "bpc-enable-control:bpc-enable-control.sh" \
    "bpc-enable-cluster:bpc-enable-cluster.sh" \
    "bpc-enable-control-replica:bpc-enable-control-replica.sh" \
    "bpc-enable-agent-dataplane:bpc-enable-agent-dataplane.sh" \
  "bpc-enable-mihomo-transports:bpc-enable-mihomo-transports.sh" \
  "bpc-enable-openvpn:bpc-enable-openvpn.sh" \
  "bpc-enable-ikev2:bpc-enable-ikev2.sh" \
  "bpc-enable-ssh-rescue:bpc-enable-ssh-rescue.sh"; do
  name="${spec%%:*}"
  script="${spec#*:}"
  if [[ -f "${BPC_ROOT}/current/deploy/${script}" ]]; then
    ln -sfn "${BPC_ROOT}/current/deploy/${script}" "/usr/local/sbin/${name}"
  fi
done

install_role="${ROLE:-canonical}"
{
  if [[ "${ROLE}" == "ru-node" ]]; then
    echo "BPC_ROLE=ru-node"
  fi
  echo "BPC_ROOT=${BPC_ROOT}"
  echo "BPC_NODE_CONFIG=${BPC_STATE_DIR}/node.yaml"
} > "${BPC_STATE_DIR}/install.env"
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
elif [[ "${ROLE}" == "ru-node" ]]; then
  export REALITY_SERVER_NAME XRAY_PORT BPC_PUBLIC_HOST
  if ! "${BPC_ROOT}/current/deploy/bootstrap-ru-node.sh"; then
    rollback_release
    echo "RU-node bootstrap failed; restored previous BPC release pointer." >&2
    exit 5
  fi
else
  echo "BPC core runtime installed."
  echo "Initialize the first Controller with: bpc init --name <NAME> --roles controller,gateway,relay --hostname <DNS>"
  echo "Or join an existing cluster with: bpc join <TOKEN>"
fi

if [[ "${WITH_AWG}" == "true" ]]; then
  if [[ -x "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh" ]]; then
    "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh"
  fi
  AWG_PORT="${AWG_PORT}" "${BPC_ROOT}/current/deploy/bpc-enable-awg.sh"
fi
if [[ "${WITH_WG}" == "true" ]]; then
  if [[ -x "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh" ]]; then
    "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh"
  fi
  WG_PORT="${WG_PORT}" "${BPC_ROOT}/current/deploy/bpc-enable-wg.sh"
fi

if [[ -s "${BPC_STATE_DIR}/ru-node/gateway-transport.yaml" && \
  -x "${BPC_ROOT}/current/deploy/bpc-render-clash.sh" ]]; then
  "${BPC_ROOT}/current/deploy/bpc-render-clash.sh"
fi

node_model="${BPC_ROOT}/current/deploy/bpc-node-model.py"
if [[ -f "${node_model}" ]]; then
  node_args=(--state-dir "${BPC_STATE_DIR}")
  if [[ -n "${BPC_NODE_NAME}" ]]; then
    node_args+=(--name "${BPC_NODE_NAME}")
  fi
  python3 "${node_model}" "${node_args[@]}" migrate
fi

if [[ -n "${JOIN_TOKEN}" ]]; then
  "${BPC_ROOT}/current/deploy/bpc.sh" join "${JOIN_TOKEN}"
  "${BPC_ROOT}/current/deploy/bpc-healthcheck.sh"
  echo "Node bootstrap completed. Updates are available through bpc-update."
  exit 0
fi

cat <<DONE
BPC ${version} installed successfully.

Install profile: ${install_role}
Release: ${release_dir}
Current: ${BPC_ROOT}/current

Commands:
  bpc init --name <NAME> --roles controller,gateway,relay --hostname <DNS>
  bpc join <TOKEN>
  bpc status
  bpc node status
  bpc node info
  bpc leave
  bpc-status
  bpc-update
  bpc-ensure-dns
  bpc-render-clash
  bpc-route-target
  bpc-enable-subscription
  bpc-subscription-url
  bpc-enable-awg
  bpc-enable-wg
  bpc-enable-wgshim
  bpc-agent
  bpc-enable-control
  bpc-enable-cluster
  bpc-enable-control-replica
  bpc-enable-mihomo-transports
  bpc-enable-openvpn
  bpc-enable-ikev2
  bpc-enable-ssh-rescue

DONE

if [[ -s "${BPC_STATE_DIR}/ru-node/gateway-transport.yaml" ]]; then
  cat <<DONE
VLESS transport configuration:
  ${BPC_STATE_DIR}/ru-node/gateway-transport.yaml
Automatic Clash Verge Rev profile:
  ${BPC_STATE_DIR}/ru-node/clash-verge-auto.yaml
DONE
fi

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
