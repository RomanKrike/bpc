#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
OUT_DIR="${2:-dist-release}"

if ! [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Usage: $0 <semver-version> [output-dir]" >&2
  exit 2
fi

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$(mkdir -p "${OUT_DIR}" && cd "${OUT_DIR}" && pwd)"
staging="$(mktemp -d)"
trap 'rm -rf "${staging}"' EXIT

for path in config deploy docs scripts src pyproject.toml README.md LICENSE install.sh go.mod go.sum cmd internal; do
  cp -a "${ROOT_DIR}/${path}" "${staging}/"
done
find "${staging}" -type d -name __pycache__ -prune -exec rm -rf {} +
printf '%s\n' "${VERSION}" > "${staging}/VERSION"

if ! command -v go >/dev/null 2>&1; then
  echo "Go is required to build BPC WGShim release binaries" >&2
  exit 3
fi

mkdir -p "${staging}/bin"
WINTUN_VERSION="0.14.1"
WINTUN_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
WINTUN_ZIP="${staging}/wintun-${WINTUN_VERSION}.zip"
if ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  echo "curl and python3 are required to package the Windows BPC Agent runtime" >&2
  exit 3
fi
if [[ -n "${BPC_WINTUN_ARCHIVE:-}" ]]; then
  cp "${BPC_WINTUN_ARCHIVE}" "${WINTUN_ZIP}"
else
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip" -o "${WINTUN_ZIP}"
fi
printf '%s  %s\n' "${WINTUN_SHA256}" "${WINTUN_ZIP}" | sha256sum --check --strict -
python3 - "${WINTUN_ZIP}" "${staging}/bin" <<'PY'
import sys
import zipfile
from pathlib import Path

archive = Path(sys.argv[1])
destination = Path(sys.argv[2])
with zipfile.ZipFile(archive) as zf:
    dll = zf.read("wintun/bin/amd64/wintun.dll")
    license_text = zf.read("wintun/LICENSE.txt")
(destination / "wintun-windows-amd64.dll").write_bytes(dll)
(destination / "wintun-prebuilt-license.txt").write_bytes(license_text)
PY
rm -f "${WINTUN_ZIP}"

(
  cd "${ROOT_DIR}"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o "${staging}/bin/bpc-wgshim-linux-amd64" ./cmd/bpc-wgshim
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o "${staging}/bin/bpc-wgshim-linux-arm64" ./cmd/bpc-wgshim
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o "${staging}/bin/bpc-agent-relay-linux-amd64" ./cmd/bpc-agent-relay
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o "${staging}/bin/bpc-agent-relay-linux-arm64" ./cmd/bpc-agent-relay
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o "${staging}/bin/bpc-controld-linux-amd64" ./cmd/bpc-controld
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o "${staging}/bin/bpc-controld-linux-arm64" ./cmd/bpc-controld
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o "${staging}/bin/bpc-routed-node-linux-amd64" ./cmd/bpc-routed-node
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o "${staging}/bin/bpc-routed-node-linux-arm64" ./cmd/bpc-routed-node
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o "${staging}/bin/bpc-wgshim-windows-amd64.exe" ./cmd/bpc-wgshim
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" -o "${staging}/bin/bpc-agent-windows-amd64.exe" ./cmd/bpc-agent
)
chmod 0755 "${staging}/bin/bpc-wgshim-linux-amd64" "${staging}/bin/bpc-wgshim-linux-arm64" \
  "${staging}/bin/bpc-agent-relay-linux-amd64" "${staging}/bin/bpc-agent-relay-linux-arm64" \
  "${staging}/bin/bpc-controld-linux-amd64" "${staging}/bin/bpc-controld-linux-arm64" \
  "${staging}/bin/bpc-routed-node-linux-amd64" "${staging}/bin/bpc-routed-node-linux-arm64"
cp "${staging}/bin/"* "${OUT_DIR}/"

if [[ -n "${BPC_CANDIDATE_SOURCE_SHA:-}" ]]; then
  python3 - "${staging}" "${VERSION}" "${BPC_CANDIDATE_SOURCE_SHA}" "$(go version)" <<'PYINFO'
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1])
files = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
         for p in sorted(root.rglob("*")) if p.is_file()}
(root / "CANDIDATE.json").write_text(json.dumps({
    "schema": 1, "channel": "mesh-test", "version": sys.argv[2],
    "source_sha": sys.argv[3], "go_toolchain": sys.argv[4],
    "live_acceptance": "pending", "files": files,
}, sort_keys=True, indent=2) + "\n")
PYINFO
fi

versioned="${OUT_DIR}/bpc-connect-${VERSION}-deploy.tar.gz"
stable="${OUT_DIR}/bpc-connect-deploy.tar.gz"
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
  tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
    -C "${staging}" -cf - . | gzip -n > "${versioned}"
else
  tar -C "${staging}" -czf "${versioned}" .
fi
cp "${versioned}" "${stable}"
cp "${ROOT_DIR}/install.sh" "${OUT_DIR}/install.sh"

mapfile -t artifacts < <(
  find "${OUT_DIR}" -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | sort
)
if (( ${#artifacts[@]} == 0 )); then
  echo "No release artifacts were created" >&2
  exit 3
fi
(
  cd "${OUT_DIR}"
  sha256sum "${artifacts[@]}"
) > "${OUT_DIR}/SHA256SUMS"

printf 'Created %s\n' "${versioned}"
printf 'Created %s\n' "${stable}"
printf 'Created %s\n' "${OUT_DIR}/SHA256SUMS"
