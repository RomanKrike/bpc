#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
SERVER_DIR="${RU_DIR}/mihomo-server"
RUNTIME_ENV="${SERVER_DIR}/runtime.env"
SERVER_CONFIG="${SERVER_DIR}/config.yaml"
TLS_DIR="${SERVER_DIR}/home/tls"
STAGED_CERT="${TLS_DIR}/fullchain.pem"
STAGED_KEY="${TLS_DIR}/privkey.pem"
SERVICE="bpc-mihomo-transports.service"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-fix-mihomo-tls as root" >&2
  exit 1
fi

if [[ ! -f "${SERVER_DIR}/enabled" ]]; then
  exit 0
fi
if [[ ! -s "${RUNTIME_ENV}" || ! -s "${SERVER_CONFIG}" ]]; then
  echo "Mihomo transport state is incomplete" >&2
  exit 1
fi

# shellcheck disable=SC1090,SC1091
source "${RUNTIME_ENV}"

if [[ ! -s "${TLS_CERT:-}" || ! -s "${TLS_KEY:-}" ]]; then
  echo "Mihomo source TLS certificate or key is missing" >&2
  exit 1
fi

# Mihomo v1.19.29 restricts listener certificate paths to its home directory
# (or explicitly configured SAFE_PATHS). Keep Let's Encrypt as the certificate
# source, but stage root-managed copies inside the Mihomo home instead of
# broadening SAFE_PATHS to /etc/letsencrypt.
install -d -m 0700 "${TLS_DIR}"
install -m 0644 "${TLS_CERT}" "${STAGED_CERT}.new"
install -m 0600 "${TLS_KEY}" "${STAGED_KEY}.new"
mv -f "${STAGED_CERT}.new" "${STAGED_CERT}"
mv -f "${STAGED_KEY}.new" "${STAGED_KEY}"
chown root:root "${STAGED_CERT}" "${STAGED_KEY}"

python3 - "${SERVER_CONFIG}" "${STAGED_CERT}" "${STAGED_KEY}" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
cert = sys.argv[2]
key = sys.argv[3]
text = path.read_text(encoding="utf-8")
cert_count = len(re.findall(r"(?m)^\s*certificate:\s*.*$", text))
key_count = len(re.findall(r"(?m)^\s*private-key:\s*.*$", text))
if cert_count == 0 or key_count == 0:
    raise SystemExit("Mihomo TLS listener fields were not found in config")
text = re.sub(
    r"(?m)^(\s*certificate:)\s*.*$",
    lambda match: f'{match.group(1)} "{cert}"',
    text,
)
text = re.sub(
    r"(?m)^(\s*private-key:)\s*.*$",
    lambda match: f'{match.group(1)} "{key}"',
    text,
)
path.write_text(text, encoding="utf-8")
PY
chmod 0600 "${SERVER_CONFIG}"

if ! /usr/local/bin/bpc-mihomo -t -d "${SERVER_DIR}/home" -f "${SERVER_CONFIG}" >/dev/null; then
  echo "Mihomo configuration validation failed after TLS staging" >&2
  exit 1
fi

install -d -m 0755 /etc/systemd/system/bpc-mihomo-transports.service.d
cat > /etc/systemd/system/bpc-mihomo-transports.service.d/20-bpc-listener-check.conf <<UNIT
[Service]
ExecStartPost=${SCRIPT_DIR}/bpc-check-mihomo-listeners.sh
UNIT
chmod 0644 /etc/systemd/system/bpc-mihomo-transports.service.d/20-bpc-listener-check.conf

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/bpc-mihomo-transports <<HOOK
#!/usr/bin/env bash
set -euo pipefail
${SCRIPT_DIR}/bpc-fix-mihomo-tls.sh
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/bpc-mihomo-transports

systemctl daemon-reload
systemctl restart "${SERVICE}"
if ! systemctl --quiet is-active "${SERVICE}"; then
  systemctl status "${SERVICE}" --no-pager >&2 || true
  journalctl -u "${SERVICE}" -n 40 --no-pager >&2 || true
  exit 1
fi

"${SCRIPT_DIR}/bpc-check-mihomo-listeners.sh"

echo "BPC Mihomo TLS certificates staged inside the Mihomo home; all expected listeners are bound."
