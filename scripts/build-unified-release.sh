#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:?Usage: build-unified-release.sh VERSION OUT}"
OUT="$(mkdir -p "${2:?Output directory required}" && cd "${2}" && pwd)"
bridge="$(mktemp -d)"
trap 'rm -rf "${bridge}"' EXIT
bash "${ROOT}/scripts/build-release.sh" "${VERSION}" "${OUT}"
sha="$(sha256sum "${OUT}/bpc-connect-deploy.tar.gz" | cut -d ' ' -f 1)"
python3 "${ROOT}/scripts/verify-mesh-candidate.py" \
  "${OUT}/bpc-connect-deploy.tar.gz" "${sha}" --stable-from "${VERSION}"
# Old installed updaters accept only the mesh-test manifest. This artifact
# installs the compatible updater once; it never masquerades as stable.
bash "${ROOT}/scripts/build-mesh-candidate.sh" "${bridge}"
cp "${bridge}/bpc-connect-deploy.tar.gz" "${OUT}/bpc-connect-mesh-transition.tar.gz"
(
  cd "${OUT}"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | sort | xargs -r sha256sum
) > "${OUT}/SHA256SUMS"
