#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"

"${SCRIPT_DIR}/bpc-enable-mihomo-transports-core.sh" "$@"
"${SCRIPT_DIR}/bpc-fix-mihomo-tls.sh"
