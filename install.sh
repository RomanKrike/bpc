#!/usr/bin/env bash
set -euo pipefail

REPO="${BPC_REPO:-RomanKrike/bpc}"
BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
ROLE="ru-node"
REALITY_SERVER_NAME=""
XRAY_PORT="443"
BPC_PUBLIC_HOST=""

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

Options:
  --role ru-node                 Node role (currently only ru-node)
  --reality-server-name HOST     Required REALITY target hostname
  --port PORT                    Xray listen port (default: 443)
  --public-host HOST             Public VPS IPv4/FQDN (auto-detected by default)
  -h, --help                     Show this help
USAGE
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

if ! [[ "${XRAY_PORT}" =~ ^[0-9]+$ ]] || (( XRAY_PORT < 1 || XRAY_PORT > 65535 )); then
  echo "--port must be between 1 and 65535" >&2
  exit 2
fi

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

cat <<DONE
BPC ${version} installed successfully.

Role: ${ROLE}
Release: ${release_dir}
Current: ${BPC_ROOT}/current

Commands:
  bpc-status
  bpc-update

Client transport configuration:
  ${BPC_STATE_DIR}/ru-node/gateway-transport.yaml
DONE