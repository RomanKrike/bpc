#!/usr/bin/env bash
set -euo pipefail
python -m bpc_connect.cli render config/gateway.example.yaml -o build/mihomo/config.yaml
printf 'Rendered build/mihomo/config.yaml\n'
