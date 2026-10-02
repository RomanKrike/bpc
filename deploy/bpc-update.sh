#!/usr/bin/env bash
set -euo pipefail

REPO="${BPC_REPO:-RomanKrike/bpc}"
BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
BACKUP_DIR="${BPC_BACKUP_DIR:-/var/backups/bpc}"
LOCAL_BUNDLE=""
EXPECTED_SHA=""
if [[ $# -gt 0 ]]; then
  if [[ $# -ne 4 || "$1" != --bundle || "$3" != --sha256 ]]; then
    echo "Usage: bpc-update [--bundle FILE --sha256 TRUSTED_SHA256]" >&2
    exit 2
  fi
  LOCAL_BUNDLE="$2"
  EXPECTED_SHA="$4"
fi

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
    if [[ -f "${release_root}/deploy/${script}" ]]; then
      chmod 0755 "${release_root}/deploy/${script}"
      ln -sfn "${release_root}/deploy/${script}" "/usr/local/sbin/${name}"
    fi
  done
}

umask 077
exec 9>"${BPC_ROOT}/.update.lock"
flock -n 9 || { echo "Another BPC update is running." >&2; exit 3; }

current_target="$(readlink -f "${BPC_ROOT}/current")"
current_version="$(tr -d '[:space:]' < "${BPC_ROOT}/current/VERSION")"

# A mesh candidate must never silently downgrade through the stable channel.
if [[ -z "${LOCAL_BUNDLE}" && -f "${BPC_ROOT}/current/CANDIDATE.json" ]]; then
  echo "Mesh candidate active: supply a pinned --bundle and --sha256." >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
mkdir -p "${tmp}/release"
if [[ -n "${LOCAL_BUNDLE}" ]]; then
  verifier="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../scripts" && pwd)/verify-mesh-candidate.py"
  python3 "${verifier}" "${LOCAL_BUNDLE}" "${EXPECTED_SHA}" --extract "${tmp}/release"
else
reconcile_command_links "${BPC_ROOT}/current"

if [[ -x "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh" ]]; then
  "${BPC_ROOT}/current/deploy/bpc-ensure-dns.sh"
fi

if ! python3 -c 'import yaml' >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends python3 python3-yaml
fi

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
fi

latest_version="$(tr -d '[:space:]' < "${tmp}/release/VERSION")"

if [[ "${latest_version}" == "${current_version}" ]]; then
  if [[ -n "${LOCAL_BUNDLE}" ]] && ! diff -qr --exclude=__pycache__ "${tmp}/release" "${current_target}" >/dev/null; then
    echo "Installed candidate differs from pinned bundle." >&2
    exit 3
  fi
  if [[ -n "${LOCAL_BUNDLE}" ]]; then
    if ! "${BPC_ROOT}/current/deploy/bpc-migrate.sh" || ! "${BPC_ROOT}/current/deploy/bpc-healthcheck.sh"; then
      echo "Installed candidate failed validation; current state retained." >&2
      exit 5
    fi
  fi
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

if [[ -z "${LOCAL_BUNDLE}" && -d "${BPC_STATE_DIR}" ]]; then
  umask 077
  tar -C /etc -czf "${backup}" "$(basename "${BPC_STATE_DIR}")"
fi
if [[ -n "${LOCAL_BUNDLE}" && -d "${new_target}" ]] && ! diff -qr --exclude=__pycache__ "${tmp}/release" "${new_target}" >/dev/null; then
  echo "Candidate version already exists with different contents." >&2
  exit 3
fi
if [[ ! -d "${new_target}" ]]; then
  mv "${tmp}/release" "${new_target}"
fi
chmod 0755 "${new_target}/deploy/"*.sh

rollback() {
  if [[ -n "${LOCAL_BUNDLE}" ]]; then
    echo "Candidate failed validation; active candidate and current state retained." >&2
    echo "Previous release: ${current_target}. Use a compatible pinned candidate to recover." >&2
    return
  fi
  echo "Update health check failed. Rolling back to BPC ${current_version}." >&2
  ln -sfn "${current_target}" "${BPC_ROOT}/current"
  reconcile_command_links "${BPC_ROOT}/current"
  if [[ -f "${backup}" ]]; then
    rm -rf "${BPC_STATE_DIR}"
    tar -C /etc -xzf "${backup}"
  fi

  # Always run the migration logic from the release we just restored. Running
  # the failed/new release migration against an old current symlink can call
  # helpers that do not exist in the rollback target (observed on 0.7.2 -> 0.7.1).
  if [[ -x "${BPC_ROOT}/current/deploy/bpc-migrate.sh" ]]; then
    "${BPC_ROOT}/current/deploy/bpc-migrate.sh" || true
  fi
  if [[ -f "${BPC_STATE_DIR}/ru-node/config.json" && -x /usr/local/bin/xray ]]; then
    /usr/local/bin/xray run -test -config "${BPC_STATE_DIR}/ru-node/config.json" >/dev/null || true
    systemctl restart xray || true
  fi
}

ln -sfn "${new_target}" "${BPC_ROOT}/.current-next"
mv -Tf "${BPC_ROOT}/.current-next" "${BPC_ROOT}/current"
reconcile_command_links "${BPC_ROOT}/current"

if ! "${BPC_ROOT}/current/deploy/bpc-migrate.sh"; then
  echo "Update migration failed." >&2
  rollback
  exit 5
fi

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
State backup (stable updates only): ${backup}
Current release: ${new_target}
DONE
