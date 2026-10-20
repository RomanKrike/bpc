#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-mesh-candidate}"
cd "${ROOT}"
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "Commit tracked changes before building a pinned candidate." >&2
  exit 2
fi
safe_base="60ca86e6b0154766107ec009a97a7fa5c7fa1426"
if ! git merge-base --is-ancestor "${safe_base}" HEAD; then
  echo "Candidate must contain the completed Raft replay migration (${safe_base})." >&2
  exit 2
fi
sha="$(git rev-parse HEAD)"
epoch="$(git show -s --format=%ct HEAD)"
OUT="$(mkdir -p "${OUT}" && cd "${OUT}" && pwd)"
if [[ -n "$(find "${OUT}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "Candidate output directory must be empty." >&2
  exit 2
fi
source_dir="$(mktemp -d)"
trap 'rm -rf "${source_dir}"' EXIT
git archive "${sha}" | tar -x -C "${source_dir}"
version="$(python3 - "${source_dir}/pyproject.toml" <<'PY'
import sys, tomllib
from pathlib import Path
print(tomllib.loads(Path(sys.argv[1]).read_text())["project"]["version"])
PY
)"
export BPC_CANDIDATE_SOURCE_SHA="${sha}" SOURCE_DATE_EPOCH="${epoch}"
bash "${source_dir}/scripts/build-release.sh" "${version}-mesh.${sha}" "${OUT}"
python3 "${source_dir}/scripts/verify-mesh-candidate.py" \
  "${OUT}/bpc-connect-deploy.tar.gz" \
  "$(sha256sum "${OUT}/bpc-connect-deploy.tar.gz" | cut -d ' ' -f 1)"
