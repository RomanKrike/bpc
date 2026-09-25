#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
AGENTS_DIR="${RU_DIR}/agents"
CONTROL_DIR="${RU_DIR}/control"

usage() {
  cat <<'USAGE'
Usage:
  bpc-agent create NAME [--legacy-tunnel TUNNEL] [--ttl SECONDS] [--output FILE]
  bpc-agent publish-update [--version VERSION] [--file FILE]
  bpc-agent list
  bpc-agent revoke NAME

Commands:
  create NAME       Build a prepared Windows bootstrap executable
  publish-update    Publish and sign the Windows agent served by the control plane
  list              List prepared and enrolled devices
  revoke NAME       Revoke registered devices with this device name

Create options:
  --legacy-tunnel TUNNEL
                    Optional compatibility tunnel for the 0.9.x external
                    WireGuard backend. Omit for the self-contained agent path.
  --ttl SECONDS     Enrollment token lifetime (default: 900)
  --output FILE     Optional additional copy of the prepared executable

Publish options:
  --version VERSION Stable semantic version (defaults to current BPC VERSION)
  --file FILE       Agent executable (defaults to current release binary)
USAGE
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    echo "Run bpc-agent as root" >&2
    exit 1
  fi
}

validate_name() {
  local value="$1"
  [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]
}

validate_tunnel() {
  local value="$1"
  [[ -z "${value}" || "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]
}

require_control() {
  if [[ ! -f "${CONTROL_DIR}/enabled" || ! -s "${CONTROL_DIR}/runtime.env" ]]; then
    echo "BPC control plane is not enabled; run bpc-enable-control first" >&2
    exit 3
  fi
  if ! systemctl --quiet is-active bpc-control.service; then
    echo "bpc-control.service is not active" >&2
    exit 3
  fi
}

create_agent() {
  local name="${1:-}"
  shift || true
  local legacy_tunnel=""
  local ttl="900"
  local extra_output=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --legacy-tunnel)
        legacy_tunnel="${2:-}"
        shift 2
        ;;
      --ttl)
        ttl="${2:-}"
        shift 2
        ;;
      --output)
        extra_output="${2:-}"
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

  if ! validate_name "${name}"; then
    echo "Agent NAME must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}" >&2
    exit 2
  fi
  if ! validate_tunnel "${legacy_tunnel}"; then
    echo "--legacy-tunnel must use letters, digits, dot, underscore or dash" >&2
    exit 2
  fi
  if ! [[ "${ttl}" =~ ^[0-9]+$ ]] || (( ttl < 60 || ttl > 86400 )); then
    echo "--ttl must be between 60 and 86400 seconds" >&2
    exit 2
  fi

  require_control
  # shellcheck disable=SC1090,SC1091
  source "${CONTROL_DIR}/runtime.env"

  local generic="${BPC_ROOT}/current/bin/bpc-agent-windows-amd64.exe"
  if [[ ! -s "${generic}" ]]; then
    echo "Windows agent binary is missing: ${generic}" >&2
    exit 3
  fi
  local wintun="${BPC_ROOT}/current/bin/wintun-windows-amd64.dll"
  if [[ ! -s "${wintun}" ]]; then
    echo "Wintun runtime is missing: ${wintun}" >&2
    echo "Update BPC to a release containing the self-contained Windows runtime." >&2
    exit 3
  fi
  if [[ ! -s "${CONTROL_DIR}/update-signing-public.pem" ]]; then
    echo "Update signing public key is missing" >&2
    exit 3
  fi

  local enroll_token
  enroll_token="$(openssl rand -hex 32)"
  local expires
  expires="$(( $(date +%s) + ttl ))"

  install -d -m 0700 "${CONTROL_DIR}/enroll" "${AGENTS_DIR}"
  python3 - "${CONTROL_DIR}/enroll/${enroll_token}.json" "${name}" "${legacy_tunnel}" "${expires}" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = {
    "device": sys.argv[2],
    "legacy_tunnel": sys.argv[3],
    "expires": int(sys.argv[4]),
}
tmp = path.with_suffix(".tmp")
tmp.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY

  local update_public
  update_public="$(base64 -w0 < "${CONTROL_DIR}/update-signing-public.pem")"
  local control_url="https://${CONTROL_HOST}:${CONTROL_PORT}"

  local json
  json="$(python3 - "${name}" "${control_url}" "${enroll_token}" "${update_public}" "${legacy_tunnel}" <<'PY'
import json
import sys

print(json.dumps({
    "version": 2,
    "device": sys.argv[1],
    "control_url": sys.argv[2],
    "enroll_token": sys.argv[3],
    "update_public_key": sys.argv[4],
    "legacy_tunnel": sys.argv[5],
}, sort_keys=True, separators=(",", ":")))
PY
)"

  local encoded
  encoded="$(printf '%s' "${json}" | base64 -w0)"
  local device_dir="${AGENTS_DIR}/${name}"
  local prepared="${device_dir}/bpc-agent-${name}.exe"
  install -d -m 0700 "${device_dir}"

  local tmp
  tmp="$(mktemp "${device_dir}/.agent.XXXXXX")"
  cp "${generic}" "${tmp}"
  {
    printf '\nBPC_AGENT_BOOTSTRAP_V2\n%s\nBPC_AGENT_BOOTSTRAP_END\n' "${encoded}"
    printf '\nBPC_AGENT_WINTUN_V1\n'
    base64 -w0 < "${wintun}"
    printf '\nBPC_AGENT_WINTUN_END\n'
  } >> "${tmp}"
  chmod 0600 "${tmp}"
  mv -f "${tmp}" "${prepared}"

  if [[ -n "${extra_output}" ]]; then
    install -m 0600 "${prepared}" "${extra_output}"
  fi

  cat > "${device_dir}/info.txt" <<INFO
Device: ${name}
Control: ${control_url}
Enrollment expires: ${expires}
Legacy tunnel: ${legacy_tunnel:-none}
Prepared executable: ${prepared}
INFO
  chmod 0600 "${device_dir}/info.txt"

  cat <<DONE
Prepared BPC Windows agent created.

Device: ${name}
Control: ${control_url}
Enrollment token lifetime: ${ttl}s
Legacy tunnel: ${legacy_tunnel:-none}
File: ${prepared}

Copy it to Windows with SCP, for example:
  scp root@${CONTROL_HOST}:${prepared} .

The enrollment token is one-time and is removed after successful registration.
The prepared EXE does not contain the WGShim PSK; runtime secrets are delivered
only after enrollment over the trusted HTTPS control plane.
DONE
}

publish_update() {
  local version=""
  local file=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)
        version="${2:-}"
        shift 2
        ;;
      --file)
        file="${2:-}"
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

  require_control
  # shellcheck disable=SC1090,SC1091
  source "${CONTROL_DIR}/runtime.env"

  if [[ -z "${version}" ]]; then
    version="$(tr -d '[:space:]' < "${BPC_ROOT}/current/VERSION")"
  fi
  if ! [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "--version must be a stable semantic version" >&2
    exit 2
  fi
  if [[ -z "${file}" ]]; then
    file="${BPC_ROOT}/current/bin/bpc-agent-windows-amd64.exe"
  fi
  if [[ ! -s "${file}" ]]; then
    echo "Agent executable is missing: ${file}" >&2
    exit 3
  fi
  if [[ ! -s "${CONTROL_DIR}/update-signing-key.pem" ]]; then
    echo "Update signing private key is missing" >&2
    exit 3
  fi

  install -d -m 0700 "${CONTROL_DIR}/update"
  install -m 0600 "${file}" "${CONTROL_DIR}/update/bpc-agent.exe"
  local sha
  sha="$(sha256sum "${CONTROL_DIR}/update/bpc-agent.exe" | awk '{print $1}')"
  local url="https://${CONTROL_HOST}:${CONTROL_PORT}/v1/update/agent.exe"

  local signing_input="${CONTROL_DIR}/update/.manifest-signing.txt"
  local signature_file="${CONTROL_DIR}/update/.manifest-signature.bin"
  printf '%s\n%s\n%s\n' "${version}" "${sha}" "${url}" > "${signing_input}"
  openssl pkeyutl -sign -rawin     -inkey "${CONTROL_DIR}/update-signing-key.pem"     -in "${signing_input}"     -out "${signature_file}"
  local signature
  signature="$(base64 -w0 < "${signature_file}")"
  rm -f "${signing_input}" "${signature_file}"

  python3 - "${CONTROL_DIR}/update/manifest.json" "${version}" "${url}" "${sha}" "${signature}" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = {
    "version": sys.argv[2],
    "url": sys.argv[3],
    "sha256": sys.argv[4],
    "signature": sys.argv[5],
}
tmp = path.with_suffix(".tmp")
tmp.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY

  cat <<DONE
BPC Agent update published.

Version: ${version}
SHA256: ${sha}
URL: ${url}
Manifest: ${CONTROL_DIR}/update/manifest.json
DONE
}

list_agents() {
  echo "Prepared packages:"
  if [[ -d "${AGENTS_DIR}" ]]; then
    local dir
    local found="false"
    for dir in "${AGENTS_DIR}"/*; do
      [[ -d "${dir}" ]] || continue
      found="true"
      if [[ -s "${dir}/info.txt" ]]; then
        cat "${dir}/info.txt"
      else
        printf 'Device: %s\n' "$(basename "${dir}")"
      fi
      echo
    done
    if [[ "${found}" != "true" ]]; then
      echo "  none"
    fi
  else
    echo "  none"
  fi

  echo "Registered devices:"
  if [[ -d "${CONTROL_DIR}/devices" ]]; then
    python3 - "${CONTROL_DIR}/devices" <<'PY'
import json
import sys
from pathlib import Path

files = sorted(Path(sys.argv[1]).glob("*.json"))
if not files:
    print("  none")
for path in files:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    print(
        f"  {value.get('device', '?')}: id={value.get('device_id', '?')} "
        f"revoked={bool(value.get('revoked', False))} "
        f"version={value.get('last_version', '?')} "
        f"last_seen={value.get('last_seen', '?')}"
    )
PY
  else
    echo "  none"
  fi
}

revoke_agent() {
  local name="${1:-}"
  if ! validate_name "${name}"; then
    echo "A valid device NAME is required" >&2
    exit 2
  fi
  require_control
  python3 - "${CONTROL_DIR}" "${name}" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
name = sys.argv[2]
count = 0
for path in (root / "devices").glob("*.json"):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    if value.get("device") != name or bool(value.get("revoked", False)):
        continue
    value["revoked"] = True
    token = str(value.get("device_token", ""))
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    if token:
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        (root / "tokens" / f"{token_hash}.json").unlink(missing_ok=True)
    count += 1
print(f"Revoked devices: {count}")
if count == 0:
    raise SystemExit(4)
PY
}

require_root
command="${1:-}"
case "${command}" in
  create)
    shift
    create_agent "$@"
    ;;
  publish-update)
    shift
    publish_update "$@"
    ;;
  list)
    shift
    if [[ $# -ne 0 ]]; then
      usage >&2
      exit 2
    fi
    list_agents
    ;;
  revoke)
    shift
    revoke_agent "$@"
    ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    echo "Unknown command: ${command}" >&2
    usage >&2
    exit 2
    ;;
esac
