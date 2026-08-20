#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

"${SCRIPT_DIR}/bpc-enable-mihomo-transports-core.sh" "$@"
"${SCRIPT_DIR}/bpc-fix-mihomo-tls.sh"
