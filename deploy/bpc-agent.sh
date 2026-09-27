#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
CONTROL_DIR="${BPC_STATE_DIR}/control"
AGENTS_DIR="${CONTROL_DIR}/agents"

usage() {
  cat <<'USAGE'
Usage:
  bpc-agent create NAME [--ttl SECONDS] [--output FILE]
  bpc-agent publish-update [--version VERSION] [--file FILE]
  bpc-agent list

Device route policy is managed with:
  bpc access list|grant|revoke

Device revocation is managed with:
  bpc device revoke DEVICE
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
  local ttl="900"
  local extra_output=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
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
  if ! [[ "${ttl}" =~ ^[0-9]+$ ]] || (( ttl < 60 || ttl > 86400 )); then
    echo "--ttl must be between 60 and 86400 seconds" >&2
    exit 2
  fi

  require_control
  # shellcheck disable=SC1090,SC1091
  source "${CONTROL_DIR}/runtime.env"

  local generic="${BPC_ROOT}/current/bin/bpc-agent-windows-amd64.exe"
  local wintun="${BPC_ROOT}/current/bin/wintun-windows-amd64.dll"
  if [[ ! -s "${generic}" || ! -s "${wintun}" ]]; then
    echo "Windows Agent runtime is incomplete in the current release" >&2
    exit 3
  fi
  if [[ ! -s "${CONTROL_DIR}/update-signing-public.pem" ]]; then
    echo "Update signing public key is missing" >&2
    exit 3
  fi

  local download_token expires update_public control_url json encoded
  download_token="$(openssl rand -hex 32)"
  expires="$(( $(date +%s) + ttl ))"
  update_public="$(base64 -w0 < "${CONTROL_DIR}/update-signing-public.pem")"
  control_url="https://${CONTROL_HOST}:${CONTROL_PORT}"

  json="$(python3 - "${name}" "${control_url}" "${update_public}" "${BPC_STATE_DIR}/cluster/controllers" <<'PY'
import json
import sys
from pathlib import Path

primary = sys.argv[2].rstrip("/")
urls = [primary]
seen = {primary}
members = Path(sys.argv[4])
if members.is_dir():
    for path in sorted(members.glob("*.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict) or record.get("state") == "revoked":
            continue
        value = str(record.get("public_url", "")).strip().rstrip("/")
        if value.startswith("https://") and value not in seen:
            seen.add(value)
            urls.append(value)

print(json.dumps({
    "version": 3,
    "device": sys.argv[1],
    "control_url": primary,
    "control_urls": urls,
    "update_public_key": sys.argv[3],
}, sort_keys=True, separators=(",", ":")))
PY
)"
  encoded="$(printf '%s' "${json}" | base64 -w0)"

  local device_dir="${AGENTS_DIR}/${name}"
  local prepared="${device_dir}/bpc-agent-${name}.exe"
  install -d -m 0700 "${CONTROL_DIR}/downloads" "${AGENTS_DIR}" "${device_dir}"
  local tmp
  tmp="$(mktemp "${device_dir}/.agent.XXXXXX")"
  cp "${generic}" "${tmp}"
  {
    printf '\nBPC_AGENT_BOOTSTRAP_V3\n%s\nBPC_AGENT_BOOTSTRAP_END\n' "${encoded}"
    printf '\nBPC_AGENT_WINTUN_V1\n'
    base64 -w0 < "${wintun}"
    printf '\nBPC_AGENT_WINTUN_END\n'
  } >> "${tmp}"
  chmod 0600 "${tmp}"
  mv -f "${tmp}" "${prepared}"

  local download_name="bpc-agent-${name}.exe"
  local download_binary="${CONTROL_DIR}/downloads/${download_token}.exe"
  local download_metadata="${CONTROL_DIR}/downloads/${download_token}.json"
  local download_url="${control_url}/v1/bootstrap/${download_token}/${download_name}"
  install -m 0600 "${prepared}" "${download_binary}"
  python3 - "${download_metadata}" "${name}" "${download_name}" "${expires}" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = {"device": sys.argv[2], "filename": sys.argv[3], "expires": int(sys.argv[4])}
tmp = path.with_suffix(".tmp")
tmp.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY

  if [[ -n "${extra_output}" ]]; then
    install -m 0600 "${prepared}" "${extra_output}"
  fi

  cat > "${device_dir}/info.txt" <<INFO
Device: ${name}
Control: ${control_url}
Bootstrap download expires: ${expires}
Prepared executable: ${prepared}
Download URL: ${download_url}
INFO
  chmod 0600 "${device_dir}/info.txt"

  cat <<DONE
Prepared BPC Windows agent created.

Device: ${name}
Control: ${control_url}
Bootstrap download lifetime: ${ttl}s
File: ${prepared}
Download URL:
  ${download_url}
DONE
}

publish_update() {
  local version=""
  local file=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version) version="${2:-}"; shift 2 ;;
      --file) file="${2:-}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
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
  if [[ ! -s "${file}" || ! -s "${CONTROL_DIR}/update-signing-key.pem" ]]; then
    echo "Agent executable or update signing key is missing" >&2
    exit 3
  fi

  install -d -m 0700 "${CONTROL_DIR}/update"
  install -m 0600 "${file}" "${CONTROL_DIR}/update/bpc-agent.exe"
  local sha url signing_input signature_file signature
  sha="$(sha256sum "${CONTROL_DIR}/update/bpc-agent.exe" | awk '{print $1}')"
  url="https://${CONTROL_HOST}:${CONTROL_PORT}/v1/update/agent.exe"
  signing_input="${CONTROL_DIR}/update/.manifest-signing.txt"
  signature_file="${CONTROL_DIR}/update/.manifest-signature.bin"
  printf '%s\n%s\n%s\n' "${version}" "${sha}" "${url}" > "${signing_input}"
  openssl pkeyutl -sign -rawin -inkey "${CONTROL_DIR}/update-signing-key.pem"     -in "${signing_input}" -out "${signature_file}"
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

  echo "BPC Agent update published: ${version} ${sha}"
}

list_agents() {
  echo "Prepared packages:"
  if [[ -d "${AGENTS_DIR}" ]]; then
    local dir found="false"
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
    [[ "${found}" == "true" ]] || echo "  none"
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
        f"  {value.get('name', value.get('device', '?'))}: "
        f"id={value.get('id', value.get('device_id', '?'))} "
        f"revoked={bool(value.get('revoked', False))} "
        f"version={value.get('last_version', '?')} "
        f"last_seen={value.get('last_seen', '?')}"
    )
PY
  else
    echo "  none"
  fi
}

deprecated_command() {
  cat >&2 <<'MSG'
WARNING:
This pre-canonical BPC Agent administration command is disabled.
Use "bpc access ..." for route policy and "bpc device revoke ..." for revocation.
MSG
  exit 2
}

require_root
command="${1:-}"
case "${command}" in
  create) shift; create_agent "$@" ;;
  publish-update) shift; publish_update "$@" ;;
  list) shift; [[ $# -eq 0 ]] || { usage >&2; exit 2; }; list_agents ;;
  routes|revoke) deprecated_command ;;
  -h|--help|help|"") usage ;;
  *) echo "Unknown bpc-agent command: ${command}" >&2; usage >&2; exit 2 ;;
esac
