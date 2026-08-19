#!/usr/bin/env bash
set -euo pipefail

BPC_DNS_PROBE_HOST="${BPC_DNS_PROBE_HOST:-deb.debian.org}"
BPC_DNS_SERVERS="${BPC_DNS_SERVERS:-1.1.1.1 8.8.8.8}"
BPC_FALLBACK_DNS="${BPC_FALLBACK_DNS:-9.9.9.9 1.0.0.1}"
BPC_RESOLVED_DROPIN="${BPC_RESOLVED_DROPIN:-/etc/systemd/resolved.conf.d/10-bpc-dns.conf}"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-ensure-dns as root" >&2
  exit 1
fi

dns_works() {
  getent ahostsv4 "${BPC_DNS_PROBE_HOST}" >/dev/null 2>&1
}

write_static_resolv_conf() {
  local server

  if [[ -e /etc/resolv.conf && ! -e /etc/resolv.conf.bpc-backup ]]; then
    cp -a /etc/resolv.conf /etc/resolv.conf.bpc-backup 2>/dev/null || true
  fi

  {
    echo "# Managed by BPC fallback because DNS resolution was unavailable."
    for server in ${BPC_DNS_SERVERS}; do
      printf 'nameserver %s\n' "${server}"
    done
  } > /etc/resolv.conf
}

if dns_works; then
  echo "DNS resolution: OK"
  exit 0
fi

echo "DNS resolution failed for ${BPC_DNS_PROBE_HOST}; attempting automatic repair."

if systemctl cat systemd-resolved.service >/dev/null 2>&1; then
  install -d -m 0755 "$(dirname "${BPC_RESOLVED_DROPIN}")"
  cat > "${BPC_RESOLVED_DROPIN}" <<RESOLVED
[Resolve]
DNS=${BPC_DNS_SERVERS}
FallbackDNS=${BPC_FALLBACK_DNS}
DNSSEC=allow-downgrade
RESOLVED

  systemctl enable systemd-resolved.service >/dev/null 2>&1 || true
  systemctl restart systemd-resolved.service

  if [[ -e /run/systemd/resolve/resolv.conf ]]; then
    if [[ -e /etc/resolv.conf && ! -L /etc/resolv.conf && ! -e /etc/resolv.conf.bpc-backup ]]; then
      cp -a /etc/resolv.conf /etc/resolv.conf.bpc-backup 2>/dev/null || true
    fi
    ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null || true
  fi

  if command -v resolvectl >/dev/null 2>&1; then
    resolvectl flush-caches >/dev/null 2>&1 || true
  fi

  for _ in 1 2 3 4 5; do
    if dns_works; then
      echo "DNS resolution repaired with systemd-resolved."
      exit 0
    fi
    sleep 1
  done
fi

if [[ -w /etc || -w /etc/resolv.conf ]]; then
  rm -f /etc/resolv.conf 2>/dev/null || true
  if write_static_resolv_conf 2>/dev/null; then
    for _ in 1 2 3; do
      if dns_works; then
        echo "DNS resolution repaired with a static resolv.conf fallback."
        exit 0
      fi
      sleep 1
    done
  fi
fi

echo "Automatic DNS repair failed for ${BPC_DNS_PROBE_HOST}." >&2
echo "Set working resolvers manually or override BPC_DNS_SERVERS and retry." >&2
exit 3
