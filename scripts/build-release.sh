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

for path in config deploy docs scripts src pyproject.toml README.md LICENSE install.sh; do
  cp -a "${ROOT_DIR}/${path}" "${staging}/"
done
printf '%s\n' "${VERSION}" > "${staging}/VERSION"

versioned="${OUT_DIR}/bpc-connect-${VERSION}-deploy.tar.gz"
stable="${OUT_DIR}/bpc-connect-deploy.tar.gz"
tar -C "${staging}" -czf "${versioned}" .
cp "${versioned}" "${stable}"

(
  cd "${OUT_DIR}"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' \
    | sort \
    | xargs -r sha256sum > SHA256SUMS
)

printf 'Created %s\n' "${versioned}"
printf 'Created %s\n' "${stable}"
printf 'Created %s\n' "${OUT_DIR}/SHA256SUMS"
