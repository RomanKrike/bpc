#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

install -d -m 0750 /etc/bpc-connect/mihomo /etc/bpc-connect/nftables /var/lib/mihomo/tailscale
install -d -m 0755 /usr/local/lib/bpc-connect

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl nftables python3 python3-venv

cat <<'MSG'
Base gateway prerequisites installed.
Next milestone installs a pinned Mihomo release, renders /etc/bpc-connect/mihomo/config.yaml,
and applies the interface-specific kill switch only after dry-run validation.
MSG
