#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
ru_dir="${BPC_STATE_DIR}/ru-node"
config="${ru_dir}/config.json"

# Nothing to migrate on nodes that do not have an RU Xray configuration.
if [[ ! -f "${config}" ]]; then
  exit 0
fi

xray_service_user="$(systemctl show -p User --value xray.service 2>/dev/null || true)"
xray_service_user="${xray_service_user:-root}"
if ! id "${xray_service_user}" >/dev/null 2>&1; then
  echo "Xray service user does not exist: ${xray_service_user}" >&2
  exit 1
fi
xray_service_group="$(id -gn "${xray_service_user}")"

chown root:"${xray_service_group}" "${ru_dir}"
chmod 0750 "${ru_dir}"
chown root:"${xray_service_group}" "${config}"
chmod 0640 "${config}"

# Client-side credentials never need to be readable by the Xray daemon.
for secret_file in "${ru_dir}/client.env" "${ru_dir}/gateway-transport.yaml"; do
  if [[ -f "${secret_file}" ]]; then
    chown root:root "${secret_file}"
    chmod 0600 "${secret_file}"
  fi
done
