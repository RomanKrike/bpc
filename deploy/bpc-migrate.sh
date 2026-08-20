#!/usr/bin/env bash
set -euo pipefail

BPC_ROOT="${BPC_ROOT:-/opt/bpc}"
BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
ru_dir="${BPC_STATE_DIR}/ru-node"
config="${ru_dir}/config.json"
client_env="${ru_dir}/client.env"
gateway_transport="${ru_dir}/gateway-transport.yaml"

# Migration hooks are executed by older updaters after they switch
# /opt/bpc/current. Reconcile commands here as well so a release can expose new
# commands even when the updater that installed it did not know their names.
if [[ -d "${BPC_ROOT}/current/deploy" ]]; then
  for spec in \
    "bpc-update:bpc-update.sh" \
    "bpc-status:bpc-status.sh" \
    "bpc-ensure-dns:bpc-ensure-dns.sh" \
    "bpc-render-clash:bpc-render-clash.sh" \
    "bpc-enable-subscription:bpc-enable-subscription.sh" \
    "bpc-subscription-url:bpc-subscription-url.sh" \
    "bpc-enable-awg:bpc-enable-awg.sh" \
    "bpc-enable-wg:bpc-enable-wg.sh" \
    "bpc-enable-mihomo-transports:bpc-enable-mihomo-transports.sh" \
    "bpc-enable-openvpn:bpc-enable-openvpn.sh" \
    "bpc-enable-ikev2:bpc-enable-ikev2.sh" \
    "bpc-enable-ssh-rescue:bpc-enable-ssh-rescue.sh"; do
    name="${spec%%:*}"
    script="${spec#*:}"
    if [[ -f "${BPC_ROOT}/current/deploy/${script}" ]]; then
      chmod 0755 "${BPC_ROOT}/current/deploy/${script}"
      ln -sfn "${BPC_ROOT}/current/deploy/${script}" "/usr/local/sbin/${name}"
    fi
  done
fi

# Nothing else to migrate on nodes that do not have an RU Xray configuration.
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
for secret_file in "${client_env}" "${gateway_transport}"; do
  if [[ -f "${secret_file}" ]]; then
    chown root:root "${secret_file}"
    chmod 0600 "${secret_file}"
  fi
done

# `client.env` is the source consumed by the aggregate Clash renderer. Keep the
# older generated gateway fragment aligned with its REALITY server name as well.
# This also repairs nodes where the target was changed manually while diagnosing
# the Xray 26.3.27 / www.microsoft.com Certificate-size incompatibility.
if [[ -f "${client_env}" && -f "${gateway_transport}" ]]; then
  reality_server_name="$(sed -n 's/^BPC_REALITY_SERVER_NAME=//p' "${client_env}" | head -n1)"
  if [[ "${reality_server_name}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] && \
    [[ "${reality_server_name}" == *.* ]]; then
    sed -i -E "s|^    servername:.*$|    servername: ${reality_server_name}|" "${gateway_transport}"
    chown root:root "${gateway_transport}"
    chmod 0600 "${gateway_transport}"
  fi

  if [[ "${reality_server_name,,}" == "www.microsoft.com" ]]; then
    echo "WARNING: www.microsoft.com is a known incompatible REALITY target for Xray 26.3.27." >&2
    echo "Use a compatible target such as www.bing.com; see XTLS/Xray-core#6356." >&2
  fi
fi

# BPC 0.6.0/0.7.0 generated the Mihomo client fragments with literal escaped
# quote characters around credentials. Generic password transports tolerated
# the malformed scalar until authentication, while Shadowsocks 2022 rejected
# it immediately because its key must be valid Base64. Repair only BPC-managed
# transport fragments; credentials themselves are not changed or regenerated.
if [[ -f "${ru_dir}/mihomo-server/enabled" ]]; then
  for transport in hy2 tuic anytls shadowtls trojan mieru trusttunnel; do
    profile="${ru_dir}/${transport}/clash-verge.yaml"
    if [[ -s "${profile}" ]] && grep -Fq '\"' "${profile}"; then
      sed -i 's/\\"/"/g' "${profile}"
      chown root:root "${profile}"
      chmod 0600 "${profile}"
    fi
  done
fi

# Mihomo v1.19.29 refuses TLS listener certificate paths outside its home unless
# they are explicitly added to SAFE_PATHS. Older BPC releases referenced
# /etc/letsencrypt/live directly, so TLS-based listeners silently failed to bind
# while the Mihomo process itself remained healthy. Stage the existing
# certificate/key inside Mihomo home, rewrite only BPC-managed listener paths,
# install a post-start socket check, and restart without rotating credentials.
if [[ -f "${ru_dir}/mihomo-server/enabled" ]]; then
  mihomo_tls_fix="${BPC_ROOT}/current/deploy/bpc-fix-mihomo-tls.sh"
  if [[ ! -f "${mihomo_tls_fix}" ]]; then
    echo "Mihomo TLS repair helper is missing: ${mihomo_tls_fix}" >&2
    exit 1
  fi
  chmod 0755 "${mihomo_tls_fix}" \
    "${BPC_ROOT}/current/deploy/bpc-check-mihomo-listeners.sh"
  "${mihomo_tls_fix}"
fi

# Rebuild the aggregate client profile from the transports already enabled on
# the node. This also reconciles optional manual Clash fallbacks such as OpenVPN
# and SSH rescue without rotating any credentials.
if [[ -x "${BPC_ROOT}/current/deploy/bpc-render-clash.sh" ]]; then
  "${BPC_ROOT}/current/deploy/bpc-render-clash.sh"
fi

# The subscription service executes the server from /opt/bpc/current. Restart
# it after a release switch so enabled endpoints immediately use the new code.
if [[ -f "${ru_dir}/subscription/enabled" ]] && \
  systemctl --quiet is-enabled bpc-subscription.service 2>/dev/null; then
  systemctl restart bpc-subscription.service
fi
