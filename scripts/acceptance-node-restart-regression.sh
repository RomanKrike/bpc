#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
PERSIST_DIR="${BPC_ACCEPTANCE_DIR:-/var/lib/bpc-acceptance}"
ACTION="${1:-}"
REPORT="${BPC_ACCEPTANCE_REPORT:-/tmp/bpc-restart-regression.json}"

usage() {
  cat <<'USAGE'
Usage:
  acceptance-node-restart-regression.sh control
  acceptance-node-restart-regression.sh transport
  acceptance-node-restart-regression.sh update
  acceptance-node-restart-regression.sh prepare-reboot
  acceptance-node-restart-regression.sh verify-reboot

Checks BPC identity, Access/routes and live WireGuard peer state across
control/transport restarts, updates and a two-phase real Node reboot.

Environment:
  BPC_STATE_DIR          canonical BPC state (default /etc/bpc-connect)
  BPC_ACCEPTANCE_DIR     persistent reboot baseline directory
  BPC_ACCEPTANCE_REPORT  report path for non-reboot stages
  BPC_UPDATE_COMMAND     update command (default: bpc-update)
USAGE
}

[[ -n "${ACTION}" ]] || { usage >&2; exit 2; }
if [[ ${EUID} -ne 0 ]]; then
  echo "Run acceptance restart regression as root." >&2
  exit 1
fi

control_config="${BPC_STATE_DIR}/control/config.json"
runtime_env="${BPC_STATE_DIR}/ru-node/agent/runtime.env"

detect_interface() {
  python3 - "${control_config}" "${runtime_env}" <<'PY'
import json
import sys
from pathlib import Path

config = Path(sys.argv[1])
runtime = Path(sys.argv[2])
if config.is_file():
    try:
        value = json.loads(config.read_text(encoding="utf-8"))
        interface = str(value.get("wireguard_interface", "")).strip()
        if interface:
            print(interface)
            raise SystemExit(0)
    except (OSError, ValueError, json.JSONDecodeError):
        pass
if runtime.is_file():
    for line in runtime.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and key == "AGENT_WG_INTERFACE" and value.strip():
            print(value.strip())
            raise SystemExit(0)
raise SystemExit("unable to determine BPC WireGuard interface")
PY
}

WG_INTERFACE="$(detect_interface)"

wait_active() {
  local service="$1"
  local limit="${2:-40}"
  for ((i=0; i<limit; i++)); do
    if systemctl --quiet is-active "${service}"; then
      return 0
    fi
    sleep 0.25
  done
  systemctl status "${service}" --no-pager >&2 || true
  return 1
}

snapshot() {
  local output="$1"
  install -d -m 0700 "$(dirname "${output}")"
  python3 - "${BPC_STATE_DIR}" "${WG_INTERFACE}" "${output}" <<'PY'
import json
import subprocess
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
interface = sys.argv[2]
output = Path(sys.argv[3])

def read_json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}

def records(directory, projection=None):
    result = []
    if not directory.is_dir():
        return result
    for path in sorted(directory.glob("*.json")):
        value = read_json(path)
        if not value:
            continue
        result.append(projection(value) if projection else value)
    return result

def device_view(value):
    return {
        "id": str(value.get("id", value.get("device_id", ""))),
        "user_id": str(value.get("user_id", "")),
        "wireguard_public_key": str(value.get("wireguard_public_key", "")),
        "wireguard_address": str(value.get("wireguard_address", "")),
        "enabled": bool(value.get("enabled", True)),
        "revoked": bool(value.get("revoked", False)),
    }

node_public = ""
node_pub_path = root / "identity" / "node.pub"
if node_pub_path.is_file():
    node_public = node_pub_path.read_text(encoding="utf-8").strip()

control = root / "control"
config = read_json(control / "config.json")
overlay_public = str(config.get("wireguard_server_public_key", "")).strip()

wg = subprocess.run(
    ["wg", "show", interface, "dump"],
    check=False,
    capture_output=True,
    text=True,
)
if wg.returncode != 0:
    raise SystemExit(wg.stderr.strip() or f"wg show {interface} dump failed")
peers = []
for index, line in enumerate(wg.stdout.splitlines()):
    fields = line.split("\t")
    if index == 0 or len(fields) < 4:
        continue
    peers.append({
        "public_key": fields[0],
        "endpoint": fields[2],
        "allowed_ips": fields[3],
    })
peers.sort(key=lambda item: item["public_key"])

payload = {
    "generated_at": int(time.time()),
    "wireguard_interface": interface,
    "node_public_key": node_public,
    "overlay_public_key": overlay_public,
    "devices": records(control / "devices", device_view),
    "access": records(control / "access"),
    "routes": records(control / "routes"),
    "wg_peers": peers,
}
output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
output.chmod(0o600)
PY
}

compare_snapshots() {
  local before="$1"
  local after="$2"
  local report="$3"
  python3 - "${before}" "${after}" "${report}" "${ACTION}" <<'PY'
import json
import sys
from pathlib import Path

before = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
after = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
report_path = Path(sys.argv[3])
action = sys.argv[4]

checks = {}
checks["wireguard_interface_unchanged"] = before["wireguard_interface"] == after["wireguard_interface"]
checks["node_identity_unchanged"] = before["node_public_key"] == after["node_public_key"]
checks["overlay_identity_unchanged"] = before["overlay_public_key"] == after["overlay_public_key"]
checks["devices_unchanged"] = before["devices"] == after["devices"]
checks["access_unchanged"] = before["access"] == after["access"]
checks["routes_unchanged"] = before["routes"] == after["routes"]

before_peers = {item["public_key"]: item for item in before["wg_peers"]}
after_peers = {item["public_key"]: item for item in after["wg_peers"]}
checks["peer_set_unchanged"] = set(before_peers) == set(after_peers)
checks["peer_allowed_ips_unchanged"] = checks["peer_set_unchanged"] and all(
    before_peers[key]["allowed_ips"] == after_peers[key]["allowed_ips"]
    for key in before_peers
)
checks["learned_endpoints_not_lost"] = checks["peer_set_unchanged"] and all(
    not before_peers[key]["endpoint"]
    or before_peers[key]["endpoint"] == "(none)"
    or (
        bool(after_peers[key]["endpoint"])
        and after_peers[key]["endpoint"] != "(none)"
    )
    for key in before_peers
)

success = all(checks.values())
report = {
    "action": action,
    "success": success,
    "checks": checks,
    "before": before,
    "after": after,
}
report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
report_path.chmod(0o600)
print(json.dumps({"action": action, "success": success, "checks": checks}, indent=2))
raise SystemExit(0 if success else 1)
PY
}

run_stage() {
  local command="$1"
  shift
  local before after
  before="$(mktemp)"
  after="$(mktemp)"
  trap 'rm -f "${before:-}" "${after:-}"' RETURN
  snapshot "${before}"
  "${command}" "$@"
  wait_active "wg-quick@${WG_INTERFACE}.service"
  snapshot "${after}"
  compare_snapshots "${before}" "${after}" "${REPORT}"
}

case "${ACTION}" in
  control)
    systemctl cat bpc-control.service >/dev/null
    before="$(mktemp)"
    after="$(mktemp)"
    trap 'rm -f "${before}" "${after}"' EXIT
    snapshot "${before}"
    systemctl restart bpc-control.service
    wait_active bpc-control.service
    wait_active "wg-quick@${WG_INTERFACE}.service"
    snapshot "${after}"
    compare_snapshots "${before}" "${after}" "${REPORT}"
    ;;
  transport)
    before="$(mktemp)"
    after="$(mktemp)"
    trap 'rm -f "${before}" "${after}"' EXIT
    snapshot "${before}"
    systemctl restart bpc-agent-relay.service
    wait_active bpc-agent-relay.service
    wait_active "wg-quick@${WG_INTERFACE}.service"
    snapshot "${after}"
    compare_snapshots "${before}" "${after}" "${REPORT}"
    ;;
  update)
    before="$(mktemp)"
    after="$(mktemp)"
    trap 'rm -f "${before}" "${after}"' EXIT
    snapshot "${before}"
    update_command="${BPC_UPDATE_COMMAND:-bpc-update}"
    "${update_command}"
    wait_active "wg-quick@${WG_INTERFACE}.service"
    if systemctl cat bpc-agent-relay.service >/dev/null 2>&1; then
      wait_active bpc-agent-relay.service
    fi
    if systemctl cat bpc-control.service >/dev/null 2>&1; then
      wait_active bpc-control.service
    fi
    snapshot "${after}"
    compare_snapshots "${before}" "${after}" "${REPORT}"
    ;;
  prepare-reboot)
    install -d -m 0700 "${PERSIST_DIR}"
    snapshot "${PERSIST_DIR}/before-reboot.json"
    printf '%s\n' "${WG_INTERFACE}" > "${PERSIST_DIR}/wireguard-interface"
    chmod 0600 "${PERSIST_DIR}/wireguard-interface"
    echo "Reboot baseline saved to ${PERSIST_DIR}/before-reboot.json"
    echo "After the real Node reboot run:"
    echo "  sudo $0 verify-reboot"
    ;;
  verify-reboot)
    before="${PERSIST_DIR}/before-reboot.json"
    [[ -s "${before}" ]] || {
      echo "No reboot baseline found at ${before}" >&2
      exit 3
    }
    if [[ -s "${PERSIST_DIR}/wireguard-interface" ]]; then
      WG_INTERFACE="$(tr -d '\r\n' < "${PERSIST_DIR}/wireguard-interface")"
    fi
    wait_active "wg-quick@${WG_INTERFACE}.service"
    if systemctl cat bpc-node.service >/dev/null 2>&1; then
      wait_active bpc-node.service
    fi
    if systemctl cat bpc-agent-relay.service >/dev/null 2>&1; then
      wait_active bpc-agent-relay.service
    fi
    # Give startup local reconciliation a short bounded window to restore peers.
    for _ in {1..40}; do
      if [[ "$(wg show "${WG_INTERFACE}" peers | wc -w)" -ge             "$(python3 - "${before}" <<'PY'
import json
import sys
print(len(json.load(open(sys.argv[1], encoding="utf-8"))["wg_peers"]))
PY
)" ]]; then
        break
      fi
      sleep 0.25
    done
    after="${PERSIST_DIR}/after-reboot.json"
    snapshot "${after}"
    compare_snapshots "${before}" "${after}" "${REPORT}"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
