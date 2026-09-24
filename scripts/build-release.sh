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

for path in config deploy docs scripts src pyproject.toml README.md LICENSE install.sh go.mod cmd internal; do
  cp -a "${ROOT_DIR}/${path}" "${staging}/"
done
printf '%s\n' "${VERSION}" > "${staging}/VERSION"

if ! command -v go >/dev/null 2>&1; then
  echo "Go is required to build BPC WGShim release binaries" >&2
  exit 3
fi

mkdir -p "${staging}/bin"
(
  cd "${ROOT_DIR}"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
    -o "${staging}/bin/bpc-wgshim-linux-amd64" ./cmd/bpc-wgshim
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" \
    -o "${staging}/bin/bpc-wgshim-linux-arm64" ./cmd/bpc-wgshim
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
    -o "${staging}/bin/bpc-wgshim-windows-amd64.exe" ./cmd/bpc-wgshim
)
chmod 0755 "${staging}/bin/bpc-wgshim-linux-amd64" "${staging}/bin/bpc-wgshim-linux-arm64"
cp "${staging}/bin/"* "${OUT_DIR}/"

versioned="${OUT_DIR}/bpc-connect-${VERSION}-deploy.tar.gz"
stable="${OUT_DIR}/bpc-connect-deploy.tar.gz"
tar -C "${staging}" -czf "${versioned}" .
cp "${versioned}" "${stable}"

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
