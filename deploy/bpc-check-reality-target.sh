#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-${REALITY_SERVER_NAME:-www.bing.com}}"
PORT="${2:-${REALITY_DEST_PORT:-443}}"
MAX_CERT_HANDSHAKE="${BPC_REALITY_MAX_CERT_HANDSHAKE:-8192}"
PREFLIGHT_TIMEOUT="${BPC_REALITY_PREFLIGHT_TIMEOUT:-15}"

usage() {
  cat <<'USAGE'
Usage: bpc-check-reality-target [HOST] [PORT]

Checks whether a candidate Xray REALITY target is reachable and rejects known
incompatible targets / oversized TLS Certificate handshake messages.

Defaults:
  HOST  www.bing.com
  PORT  443
USAGE
}

if [[ "${HOST}" == "-h" || "${HOST}" == "--help" ]]; then
  usage
  exit 0
fi

if ! [[ "${HOST}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || [[ "${HOST}" != *.* ]]; then
  echo "REALITY target must be a valid DNS hostname: ${HOST}" >&2
  exit 2
fi
if ! [[ "${PORT}" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
  echo "REALITY target port must be between 1 and 65535" >&2
  exit 2
fi
if ! [[ "${MAX_CERT_HANDSHAKE}" =~ ^[0-9]+$ ]] || (( MAX_CERT_HANDSHAKE < 1024 )); then
  echo "BPC_REALITY_MAX_CERT_HANDSHAKE must be an integer >= 1024" >&2
  exit 2
fi
if ! [[ "${PREFLIGHT_TIMEOUT}" =~ ^[0-9]+$ ]] || (( PREFLIGHT_TIMEOUT < 1 || PREFLIGHT_TIMEOUT > 60 )); then
  echo "BPC_REALITY_PREFLIGHT_TIMEOUT must be between 1 and 60 seconds" >&2
  exit 2
fi

host_lower="${HOST,,}"
if [[ "${host_lower}" == "www.microsoft.com" ]]; then
  cat >&2 <<'ERR'
REALITY target www.microsoft.com is rejected by BPC for the pinned Xray 26.3.27 runtime.
Its TLS Certificate record can exceed the 8192-byte REALITY parser limit and cause:
  REALITY: processed invalid connection ... handshake did not complete successfully
Use www.bing.com or another target that passes this preflight.
Upstream reference: XTLS/Xray-core#6356
ERR
  exit 4
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required for REALITY target preflight" >&2
  exit 3
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo "timeout (coreutils) is required for REALITY target preflight" >&2
  exit 3
fi
if ! getent ahosts "${HOST}" >/dev/null 2>&1; then
  echo "REALITY target does not resolve: ${HOST}" >&2
  exit 3
fi

tls_output="$(mktemp)"
trace_output="$(mktemp)"
trap 'rm -f "${tls_output}" "${trace_output}"' EXIT

if ! timeout "${PREFLIGHT_TIMEOUT}" openssl s_client \
  -connect "${HOST}:${PORT}" \
  -servername "${HOST}" \
  -tls1_3 \
  -brief </dev/null >"${tls_output}" 2>&1; then
  echo "REALITY target TLS handshake failed: ${HOST}:${PORT}" >&2
  sed -n '1,12p' "${tls_output}" >&2
  exit 4
fi

# Chrome-like REALITY handshakes can request certificate status. `-status -msg`
# gives us a conservative signal for targets whose Certificate handshake exceeds
# the 8192-byte buffer used by the pinned REALITY library. The known Microsoft
# case is rejected explicitly above because CDN responses may vary between runs.
timeout "${PREFLIGHT_TIMEOUT}" openssl s_client \
  -connect "${HOST}:${PORT}" \
  -servername "${HOST}" \
  -tls1_3 \
  -status \
  -msg </dev/null >"${trace_output}" 2>&1 || true

cert_hex="$(
  sed -nE 's/.*Handshake \[length ([0-9A-Fa-f]+)\], Certificate.*/\1/p' \
    "${trace_output}" | head -n1
)"

if [[ -n "${cert_hex}" ]]; then
  cert_len=$((16#${cert_hex}))
  if (( cert_len > MAX_CERT_HANDSHAKE )); then
    echo "REALITY target rejected: Certificate handshake ${cert_len} B exceeds ${MAX_CERT_HANDSHAKE} B." >&2
    echo "Choose another target, for example www.bing.com." >&2
    exit 4
  fi
  printf 'REALITY target preflight: OK (%s:%s; Certificate handshake %s B)\n' \
    "${HOST}" "${PORT}" "${cert_len}"
else
  printf 'REALITY target preflight: OK (%s:%s; TLS handshake succeeded, Certificate length unavailable)\n' \
    "${HOST}" "${PORT}"
fi
