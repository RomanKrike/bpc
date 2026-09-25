#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
WGSHIM_DIR="${RU_DIR}/wgshim"
AGENTS_DIR="${RU_DIR}/agents"
SUB_DIR="${RU_DIR}/subscription"

usage() {
  cat <<'USAGE'
Usage:
  bpc-agent create NAME --tunnel TUNNEL [--output FILE]
  bpc-agent list

Commands:
  create NAME       Build a prepared Windows agent executable for one device
  list              List prepared agent packages

Create options:
  --tunnel TUNNEL   Existing WireGuard for Windows tunnel name (required)
  --output FILE     Optional additional copy of the prepared executable
  -h, --help        Show this help

The prepared executable contains the WGShim client credential and must be
handled like a private VPN configuration. BPC 0.9.0 still uses the single-client
WGShim server introduced in 0.8.0, so only one WGShim agent should be active at
a time.
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
  [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]
}

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

create_agent() {
  local name="${1:-}"
  shift || true
  local tunnel=""
  local extra_output=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tunnel)
        tunnel="${2:-}"
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
  if ! validate_tunnel "${tunnel}"; then
    echo "--tunnel is required and must use letters, digits, dot, underscore or dash" >&2
    exit 2
  fi
  if [[ ! -f "${WGSHIM_DIR}/enabled" || ! -s "${WGSHIM_DIR}/runtime.env" || ! -s "${WGSHIM_DIR}/client.key" ]]; then
    echo "WGShim is not enabled; run bpc-enable-wgshim first" >&2
    exit 3
  fi
  if [[ ! -s "${RU_DIR}/client.env" ]]; then
    echo "RU-node client.env is missing" >&2
    exit 3
  fi

  # shellcheck disable=SC1090,SC1091
  source "${WGSHIM_DIR}/runtime.env"
  # shellcheck disable=SC1090,SC1091
  source "${RU_DIR}/client.env"

  local generic="${BPC_ROOT}/current/bin/bpc-agent-windows-amd64.exe"
  if [[ ! -s "${generic}" ]]; then
    echo "Windows agent binary is missing: ${generic}" >&2
    echo "Update BPC to 0.9.0 or newer and retry." >&2
    exit 3
  fi

  local psk
  psk="$(tr -d '\r\n' < "${WGSHIM_DIR}/client.key")"
  if ! [[ "${psk}" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    echo "WGShim client key is invalid" >&2
    exit 3
  fi

  local server="${BPC_RU_HOST}:${WGSHIM_PORT:-24443}"
  local listen="127.0.0.1:${WGSHIM_LOCAL_PORT:-24081}"
  local target="${WGSHIM_TARGET_HOST}:${WGSHIM_TARGET_PORT}"
  local padding_min="${WGSHIM_PADDING_MIN:-0}"
  local padding_max="${WGSHIM_PADDING_MAX:-31}"

  local json
  json="$(printf '{"version":1,"device":%s,"tunnel":%s,"server":%s,"listen":%s,"target":%s,"padding_min":%s,"padding_max":%s,"psk":%s}' \
    "$(json_escape "${name}")" \
    "$(json_escape "${tunnel}")" \
    "$(json_escape "${server}")" \
    "$(json_escape "${listen}")" \
    "$(json_escape "${target}")" \
    "${padding_min}" \
    "${padding_max}" \
    "$(json_escape "${psk}")")"

  local encoded
  encoded="$(printf '%s' "${json}" | base64 -w0)"

  local device_dir="${AGENTS_DIR}/${name}"
  local prepared="${device_dir}/bpc-agent-${name}.exe"
  install -d -m 0700 "${AGENTS_DIR}" "${device_dir}"

  local tmp
  tmp="$(mktemp "${device_dir}/.agent.XXXXXX")"
  trap 'rm -f "${tmp:-}"' RETURN
  cp "${generic}" "${tmp}"
  printf '\nBPC_AGENT_BOOTSTRAP_V1\n%s\nBPC_AGENT_BOOTSTRAP_END\n' "${encoded}" >> "${tmp}"
  chmod 0600 "${tmp}"
  mv -f "${tmp}" "${prepared}"
  trap - RETURN

  if [[ -n "${extra_output}" ]]; then
    install -m 0600 "${prepared}" "${extra_output}"
  fi

  local old_download="${device_dir}/download.token"
  if [[ -s "${old_download}" ]]; then
    local previous_token
    previous_token="$(tr -d '\r\n' < "${old_download}")"
    if [[ "${previous_token}" =~ ^[0-9a-f]{48}$ ]]; then
      rm -f "${SUB_DIR}/agents/${previous_token}.exe"
    fi
  fi

  local download_url=""
  if [[ -f "${SUB_DIR}/enabled" && -s "${SUB_DIR}/runtime.env" ]] && systemctl --quiet is-active bpc-subscription.service; then
    # shellcheck disable=SC1090,SC1091
    source "${SUB_DIR}/runtime.env"
    local download_token
    download_token="$(openssl rand -hex 24)"
    install -d -m 0700 "${SUB_DIR}/agents"
    install -m 0600 "${prepared}" "${SUB_DIR}/agents/${download_token}.exe"
    printf '%s\n' "${download_token}" > "${old_download}"
    chmod 0600 "${old_download}"
    download_url="https://${SUBSCRIPTION_HOST}:${SUBSCRIPTION_PORT}/agent/${download_token}.exe"

    # Existing 0.8.x service definitions point at /opt/bpc/current, so a restart
    # is sufficient to load the 0.9.0 HTTP handler that serves agent packages.
    systemctl restart bpc-subscription.service
  fi

  cat > "${device_dir}/info.txt" <<INFO
Device: ${name}
Tunnel: ${tunnel}
WGShim server: ${server}
WGShim target: ${target}
Prepared executable: ${prepared}
INFO
  chmod 0600 "${device_dir}/info.txt"

  cat <<DONE
Prepared BPC Windows agent created.

Device: ${name}
Tunnel: ${tunnel}
File: ${prepared}
DONE
  if [[ -n "${download_url}" ]]; then
    cat <<DONE
Download URL:
  ${download_url}
DONE
  else
    cat <<DONE
HTTPS publishing is unavailable because the BPC subscription service is not active.
Copy the file with SCP instead.
DONE
  fi
  cat <<'DONE'

On Windows, run the downloaded EXE. It requests Administrator elevation,
installs itself under ProgramData, starts at boot, runs WGShim internally and
repoints the selected existing WireGuard tunnel to the local WGShim endpoint.
DONE
}

list_agents() {
  if [[ ! -d "${AGENTS_DIR}" ]]; then
    echo "No prepared agents."
    return 0
  fi
  local found="false"
  local dir
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
    echo "No prepared agents."
  fi
}

require_root
command="${1:-}"
case "${command}" in
  create)
    shift
    create_agent "$@"
    ;;
  list)
    shift
    if [[ $# -ne 0 ]]; then
      usage >&2
      exit 2
    fi
    list_agents
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
