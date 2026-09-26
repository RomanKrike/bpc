#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
CONTROL_DIR="${RU_DIR}/control"
NODE_MODEL="${BPC_ROOT}/current/deploy/bpc-node-model.py"

usage() {
  cat <<'USAGE'
Usage:
  bpc-node status
  bpc-node info
  bpc-node gateway create NAME --route CIDR [--route CIDR ...] [--grant DEVICE ...] [--output FILE]
  bpc-node gateway grant NAME DEVICE [DEVICE ...]
  bpc-node gateway ungrant NAME DEVICE [DEVICE ...]
  bpc-node gateway list
  bpc-node gateway remove NAME

BP Gateway exposes selected LAN subnets to BP Connect through BP Network.
The first implementation is relay-routed and remains split-tunnel.
USAGE
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    echo "Run bpc-node as root" >&2
    exit 1
  fi
}

require_control() {
  if [[ ! -f "${CONTROL_DIR}/enabled" || ! -s "${CONTROL_DIR}/config.json" ]]; then
    echo "BPC control plane is not enabled; run bpc-enable-control first" >&2
    exit 3
  fi
  if ! systemctl --quiet is-active bpc-control.service; then
    echo "bpc-control.service is not active" >&2
    exit 3
  fi
}

validate_name() {
  [[ "${1:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]
}

require_node_model() {
  if [[ ! -f "${NODE_MODEL}" ]]; then
    echo "BPC node model helper is missing: ${NODE_MODEL}" >&2
    exit 3
  fi
}

node_status() {
  require_node_model
  exec python3 "${NODE_MODEL}" --state-dir "${BPC_STATE_DIR}" status
}

node_info() {
  require_node_model
  exec python3 "${NODE_MODEL}" --state-dir "${BPC_STATE_DIR}" info
}

restart_control() {
  systemctl restart bpc-control.service
  if ! systemctl --quiet is-active bpc-control.service; then
    systemctl status bpc-control.service --no-pager >&2 || true
    exit 5
  fi
}

gateway_create() {
  local name="${1:-}"
  shift || true
  if ! validate_name "${name}"; then
    echo "Gateway NAME must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}" >&2
    exit 2
  fi

  local output=""
  local -a routes=()
  local -a grants=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --route)
        [[ $# -ge 2 ]] || { echo "--route requires CIDR" >&2; exit 2; }
        routes+=("$2")
        shift 2
        ;;
      --grant)
        [[ $# -ge 2 ]] || { echo "--grant requires DEVICE" >&2; exit 2; }
        validate_name "$2" || { echo "Invalid device name: $2" >&2; exit 2; }
        grants+=("$2")
        shift 2
        ;;
      --output)
        [[ $# -ge 2 ]] || { echo "--output requires FILE" >&2; exit 2; }
        output="$2"
        shift 2
        ;;
      *)
        echo "Unknown gateway create option: $1" >&2
        exit 2
        ;;
    esac
  done
  if (( ${#routes[@]} == 0 )); then
    echo "At least one --route CIDR is required" >&2
    exit 2
  fi

  require_control
  command -v wg >/dev/null 2>&1 || { echo "wg is required on the BP Relay" >&2; exit 3; }

  local template="${BPC_ROOT}/current/deploy/bp-gateway-install.sh.tpl"
  if [[ ! -s "${template}" ]]; then
    echo "BP Gateway installer template is missing: ${template}" >&2
    exit 3
  fi

  local routes_csv grants_csv installer
  routes_csv="$(IFS=,; printf '%s' "${routes[*]}")"
  grants_csv="$(IFS=,; printf '%s' "${grants[*]}")"

  installer="$(python3 - "${CONTROL_DIR}" "${template}" "${name}" "${routes_csv}" "${grants_csv}" <<'PY'
import base64
import ipaddress
import json
import os
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

root = Path(sys.argv[1])
template_path = Path(sys.argv[2])
name = sys.argv[3]
raw_routes = [item for item in sys.argv[4].split(",") if item]
grant_names = [item for item in sys.argv[5].split(",") if item]

def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path} does not contain a JSON object")
    return value

def save(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

config = load(root / "config.json")
overlay = ipaddress.ip_network(str(config["wireguard_subnet"]), strict=False)
server_ip = ipaddress.ip_interface(str(config["wireguard_server_address"])).ip

routes: list[str] = []
seen_routes: set[str] = set()
for raw in raw_routes:
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise SystemExit(f"Invalid gateway route {raw!r}: {exc}")
    if network.version != 4:
        raise SystemExit(f"Only IPv4 gateway routes are supported: {raw}")
    if network.prefixlen == 0:
        raise SystemExit("0.0.0.0/0 is not allowed for BP Gateway routes")
    if network.overlaps(overlay):
        raise SystemExit(f"Gateway route {network} overlaps BP Network overlay {overlay}")
    canonical = str(network)
    if canonical not in seen_routes:
        seen_routes.add(canonical)
        routes.append(canonical)

records: list[tuple[Path, dict]] = []
used: set[ipaddress.IPv4Address] = set()
for path in sorted((root / "devices").glob("*.json")):
    try:
        value = load(path)
    except Exception:
        continue
    records.append((path, value))
    if bool(value.get("revoked", False)):
        continue
    raw_address = str(value.get("wireguard_address", "")).strip()
    if raw_address:
        try:
            used.add(ipaddress.ip_interface(raw_address).ip)
        except ValueError:
            pass
    if value.get("role") == "gateway":
        if value.get("device") == name:
            raise SystemExit(f"Active BP Gateway {name!r} already exists")
        for advertised in value.get("advertised_routes", []):
            existing = ipaddress.ip_network(str(advertised), strict=False)
            for route in routes:
                candidate = ipaddress.ip_network(route, strict=False)
                if candidate.overlaps(existing):
                    raise SystemExit(
                        f"Gateway route {candidate} overlaps {existing} "
                        f"advertised by {value.get('device', '?')}"
                    )

grant_targets: list[tuple[Path, dict]] = []
for grant_name in grant_names:
    matches = [
        item for item in records
        if item[1].get("device") == grant_name
        and item[1].get("role") != "gateway"
        and not bool(item[1].get("revoked", False))
    ]
    if not matches:
        raise SystemExit(f"No active BP Connect device named {grant_name!r}")
    grant_targets.extend(matches)

gateway_ip = next(
    (candidate for candidate in overlay.hosts() if candidate != server_ip and candidate not in used),
    None,
)
if gateway_ip is None:
    raise SystemExit("BP Network address pool is exhausted")
gateway_address = f"{gateway_ip}/32"

private_key = subprocess.run(
    ["wg", "genkey"], check=True, capture_output=True, text=True
).stdout.strip()
public_key = subprocess.run(
    ["wg", "pubkey"],
    input=private_key + "\n",
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
wgshim_psk = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
device_id = uuid.uuid4().hex
now = int(time.time())

device = {
    "device_id": device_id,
    "device": name,
    "role": "gateway",
    "static": True,
    "public_key": "",
    "wireguard_public_key": public_key,
    "wireguard_address": gateway_address,
    "wgshim_psk": wgshim_psk,
    "managed_routes": [],
    "advertised_routes": routes,
    "created": now,
    "last_seen": 0,
    "last_version": "static-linux",
    "revoked": False,
}
save(root / "devices" / f"{device_id}.json", device)

key_dir = Path(str(config["wgshim_key_dir"]))
key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
key_path = key_dir / f"{device_id}.key"
key_path.write_text(wgshim_psk + "\n", encoding="utf-8")
os.chmod(key_path, 0o600)

for path, value in grant_targets:
    current = value.get("managed_routes", [])
    if not isinstance(current, list):
        current = []
    merged: list[str] = []
    seen: set[str] = set()
    for raw in [*current, *routes]:
        try:
            canonical = str(ipaddress.ip_network(str(raw), strict=False))
        except ValueError:
            continue
        if canonical not in seen:
            seen.add(canonical)
            merged.append(canonical)
    value["managed_routes"] = merged
    save(path, value)

node_dir = root / "nodes" / name
node_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
template = template_path.read_text(encoding="utf-8")
values = {
    "NAME": name,
    "RELAY": str(config["wgshim_server"]),
    "TCP_RELAY": str(config.get("wgshim_tcp_server", config["wgshim_server"])),
    "OVERLAY": str(overlay),
    "SERVER_OVERLAY_IP": str(server_ip),
    "GATEWAY_ADDRESS": gateway_address,
    "SERVER_PUBLIC_KEY": str(config["wireguard_server_public_key"]),
    "GATEWAY_PRIVATE_KEY": private_key,
    "WGSHIM_PSK": wgshim_psk,
    "MTU": str(config["wireguard_mtu"]),
    "KEEPALIVE": str(config["wireguard_keepalive"]),
    "PADDING_MIN": str(config["padding_min"]),
    "PADDING_MAX": str(config["padding_max"]),
    "ROUTES_CSV": ",".join(routes),
}
for key, value in values.items():
    template = template.replace(f"@@{key}@@", value)
if "@@" in template:
    raise SystemExit("BP Gateway installer template contains unresolved placeholders")

installer = node_dir / "install.sh"
installer.write_text(template, encoding="utf-8")
os.chmod(installer, 0o700)
save(node_dir / "metadata.json", {
    "device_id": device_id,
    "wireguard_address": gateway_address,
    "advertised_routes": routes,
})
print(installer)
PY
)"

  restart_control
  if [[ -n "${output}" ]]; then
    install -m 0700 "${installer}" "${output}"
  fi

  echo "BP Gateway created: ${name}"
  echo "Routes: ${routes_csv}"
  if (( ${#grants[@]} > 0 )); then
    echo "Granted to: ${grants[*]}"
  else
    echo "Granted to: nobody yet"
  fi
  echo "Installer: ${installer}"
  [[ -z "${output}" ]] || echo "Installer copy: ${output}"
}

gateway_access() {
  local mode="$1"
  local name="${2:-}"
  shift 2 || true
  if ! validate_name "${name}" || [[ $# -eq 0 ]]; then
    echo "Usage: bpc-node gateway ${mode} NAME DEVICE [DEVICE ...]" >&2
    exit 2
  fi
  local device
  for device in "$@"; do
    validate_name "${device}" || { echo "Invalid device name: ${device}" >&2; exit 2; }
  done
  require_control

  local devices_csv
  devices_csv="$(IFS=,; printf '%s' "$*")"
  python3 - "${CONTROL_DIR}" "${name}" "${mode}" "${devices_csv}" <<'PY'
import ipaddress
import json
import os
import secrets
import sys
from pathlib import Path

root = Path(sys.argv[1])
gateway_name = sys.argv[2]
mode = sys.argv[3]
names = [item for item in sys.argv[4].split(",") if item]

def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def save(path: Path, value: dict) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

records = []
for path in sorted((root / "devices").glob("*.json")):
    try:
        records.append((path, load(path)))
    except Exception:
        continue

gateways = [
    value for _, value in records
    if value.get("device") == gateway_name
    and value.get("role") == "gateway"
    and not bool(value.get("revoked", False))
]
if len(gateways) != 1:
    raise SystemExit(f"Expected one active BP Gateway named {gateway_name!r}")
routes = {
    str(ipaddress.ip_network(str(route), strict=False))
    for route in gateways[0].get("advertised_routes", [])
}

updated = 0
for device_name in names:
    matches = [
        (path, value) for path, value in records
        if value.get("device") == device_name
        and value.get("role") != "gateway"
        and not bool(value.get("revoked", False))
    ]
    if not matches:
        raise SystemExit(f"No active BP Connect device named {device_name!r}")
    for path, value in matches:
        current = value.get("managed_routes", [])
        if not isinstance(current, list):
            current = []
        canonical = []
        seen = set()
        for raw in current:
            try:
                route = str(ipaddress.ip_network(str(raw), strict=False))
            except ValueError:
                continue
            if route not in seen:
                seen.add(route)
                canonical.append(route)
        if mode == "grant":
            for route in sorted(routes):
                if route not in seen:
                    canonical.append(route)
        else:
            canonical = [route for route in canonical if route not in routes]
        value["managed_routes"] = canonical
        save(path, value)
        updated += 1

print(f"Updated {updated} device(s). Routes apply within the next Agent config sync.")
PY
}

gateway_list() {
  require_control
  python3 - "${CONTROL_DIR}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
found = False
for path in sorted((root / "devices").glob("*.json")):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    if value.get("role") != "gateway":
        continue
    found = True
    print(
        f"{value.get('device', '?')}: "
        f"address={value.get('wireguard_address', '?')} "
        f"revoked={bool(value.get('revoked', False))} "
        f"routes={','.join(map(str, value.get('advertised_routes', []))) or '-'}"
    )
if not found:
    print("No BP Gateway nodes.")
PY
}

gateway_remove() {
  local name="${1:-}"
  if ! validate_name "${name}" || [[ $# -ne 1 ]]; then
    echo "Usage: bpc-node gateway remove NAME" >&2
    exit 2
  fi
  require_control

  python3 - "${CONTROL_DIR}" "${name}" <<'PY'
import ipaddress
import json
import os
import secrets
import sys
from pathlib import Path

root = Path(sys.argv[1])
name = sys.argv[2]

def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def save(path: Path, value: dict) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

records = []
for path in sorted((root / "devices").glob("*.json")):
    try:
        records.append((path, load(path)))
    except Exception:
        continue

matches = [
    (path, value) for path, value in records
    if value.get("device") == name
    and value.get("role") == "gateway"
    and not bool(value.get("revoked", False))
]
if len(matches) != 1:
    raise SystemExit(f"Expected one active BP Gateway named {name!r}")

gateway_path, gateway = matches[0]
routes = {
    str(ipaddress.ip_network(str(route), strict=False))
    for route in gateway.get("advertised_routes", [])
}
gateway["revoked"] = True
save(gateway_path, gateway)

config = load(root / "config.json")
device_id = str(gateway.get("device_id", ""))
if device_id:
    (Path(str(config["wgshim_key_dir"])) / f"{device_id}.key").unlink(missing_ok=True)

for path, value in records:
    if value.get("role") == "gateway" or bool(value.get("revoked", False)):
        continue
    current = value.get("managed_routes", [])
    if not isinstance(current, list):
        continue
    filtered = []
    for raw in current:
        try:
            route = str(ipaddress.ip_network(str(raw), strict=False))
        except ValueError:
            continue
        if route not in routes:
            filtered.append(route)
    if filtered != current:
        value["managed_routes"] = filtered
        save(path, value)

print(f"Revoked BP Gateway {name}.")
PY

  restart_control
}

require_root
scope="${1:-}"
command="${2:-}"
case "${scope}" in
  status)
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    node_status
    ;;
  info)
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    node_info
    ;;
esac

if [[ "${scope}" != "gateway" ]]; then
  usage
  [[ -z "${scope}" || "${scope}" == "-h" || "${scope}" == "--help" || "${scope}" == "help" ]] && exit 0
  exit 2
fi

case "${command}" in
  create)
    shift 2
    gateway_create "$@"
    ;;
  grant|ungrant)
    shift 2
    gateway_access "${command}" "$@"
    ;;
  list)
    shift 2
     [[ $# -eq 0 ]] || { usage >&2; exit 2; }
    gateway_list
    ;;
  remove)
    shift 2
    gateway_remove "$@"
    ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    echo "Unknown gateway command: ${command}" >&2
    usage >&2
    exit 2
    ;;
esac
