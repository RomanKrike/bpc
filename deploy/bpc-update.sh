#!/usr/bin/env bash
set -euo pipefail

REPO="${BPC_REPO:-RomanKrike/bpc}"
BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
BACKUP_DIR="${BPC_BACKUP_DIR:-/var/backups/bpc}"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-update as root" >&2
  exit 1
fi

if [[ ! -L "${BPC_ROOT}/current" || ! -f "${BPC_ROOT}/current/VERSION" ]]; then
  echo "BPC installation was not found at ${BPC_ROOT}/current" >&2
  exit 2
fi

reconcile_command_links() {
  local release_root="$1"
  local spec name script

  for spec in \
    "bpc-update:bpc-update.sh" \
    "bpc-status:bpc-status.sh" \
    "bpc-ensure-dns:bpc-ensure-dns.sh" \
    "bpc-render-clash:bpc-render-clash.sh" \
    "bpc-enable-subscription:bpc-enable-subscription.sh" \
    "bpc-subscription-url:bpc-subscription-url.sh" \
    "bpc-enable-awg:bpc-enable-awg.sh" \
    "bpc-enable-wg:bpc-enable-wg.sh" \
    "bpc-enable-mihomo-transports:bpc-enable-mihomo-transports.sh" \
    "bpc-enable-ssh-rescue:bpc-enable-ssh-rescue.sh"; do
    name="${spec%%:*}"
    script="${spec#*:}"
    if [[ -f "${release_root}/deploy/${script}" ]]; then
      chmod 0755 "${release_root}/deploy/${script}"
      ln -sfn "${release_root}/deploy/${script}" "/usr/local/sbin/${name}"
    fi
  done
}

current_target="$(readlink -f "${BPC_ROOT}/current")"
current_version="$(tr -d '[:space:]' < "${BPC_ROOT}/current/VERSION")"

# Repair command links on every invocation, even when the installed version is
# already the latest. This also exposes commands that were introduced by the
# release being installed by an older updater.
reconcile_command_links "${BPC_ROOT}/current"

if [[ -x "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh" ]]; then
  "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh"
fi

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
latest_version="$(tr -d '[:space:]' < "${tmp}/release/VERSION")"

if [[ "${latest_version}" == "${current_version}" ]]; then
  echo "BPC ${current_version} is already up to date."
  exit 0
fi
if ! [[ "${latest_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid release version: ${latest_version}" >&2
  exit 3
fi

install -d -m 0755 "${BPC_ROOT}/releases" "${BACKUP_DIR}"
new_target="${BPC_ROOT}/releases/${latest_version}"
backup="${BACKUP_DIR}/state-$(date -u +%Y%m%dT%H%M%SZ)-${current_version}.tar.gz"

if [[ -d "${BPC_STATE_DIR}" ]]; then
  tar -C /etc -czf "${backup}" "$(basename "${BPC_STATE_DIR}")"
fi
if [[ ! -d "${new_target}" ]]; then
  mv "${tmp}/release" "${new_target}"
fi
chmod 0755 "${new_target}/deploy/"*.sh

rollback() {
  echo "Update health check failed. Rolling back to BPC ${current_version}." >&2
  ln -sfn "${current_target}" "${BPC_ROOT}/current"
  reconcile_command_links "${BPC_ROOT}/current"
  if [[ -f "${backup}" ]]; then
    rm -rf "${BPC_STATE_DIR}"
    tar -C /etc -xzf "${backup}"
  fi
  "${new_target}/deploy/bpc-migrate.sh" || true
  if [[ -f "${BPC_STATE_DIR}/ru-node/config.json" && -x /usr/local/bin/xray ]]; then
    /usr/local/bin/xray run -test -config "${BPC_STATE_DIR}/ru-node/config.json" >/dev/null || true
    systemctl restart xray || true
  fi
}

ln -sfn "${new_target}" "${BPC_ROOT}/current"
reconcile_command_links "${BPC_ROOT}/current"

"${BPC_ROOT}/current/deploy/bpc-migrate.sh"

if ! "${BPC_ROOT}/current/deploy/bpc-healthcheck.sh"; then
  rollback
  exit 5
fi

if [[ -f "${BPC_STATE_DIR}/ru-node/config.json" ]]; then
  systemctl restart xray
fi
if ! "${BPC_ROOT}/current/deploy/bpc-healthcheck.sh"; then
  rollback
  exit 5
fi

cat <<DONE
BPC updated successfully: ${current_version} -> ${latest_version}
Backup: ${backup}
Current release: ${new_target}
DONE
