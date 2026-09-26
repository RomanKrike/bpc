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
    "bpc:bpc.sh" \
    "bpc-update:bpc-update.sh" \
    "bpc-status:bpc-status.sh" \
    "bpc-ensure-dns:bpc-ensure-dns.sh" \
    "bpc-render-clash:bpc-render-clash.sh" \
    "bpc-route-target:bpc-route-target.sh" \
    "bpc-enable-subscription:bpc-enable-subscription.sh" \
    "bpc-subscription-url:bpc-subscription-url.sh" \
    "bpc-enable-awg:bpc-enable-awg.sh" \
    "bpc-enable-wg:bpc-enable-wg.sh" \
    "bpc-enable-wgshim:bpc-enable-wgshim.sh" \
    "bpc-agent:bpc-agent.sh" \
    "bpc-node:bpc-node.sh" \
    "bpc-enable-control:bpc-enable-control.sh" \
    "bpc-enable-agent-dataplane:bpc-enable-agent-dataplane.sh" \
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

node_model="${BPC_ROOT}/current/deploy/bpc-node-model.py"
if [[ -f "${node_model}" ]]; then
  if ! python3 -c 'import yaml' >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends python3 python3-yaml
  fi
  python3 "${node_model}" --state-dir "${BPC_STATE_DIR}" migrate
fi

node_enrollment="${BPC_ROOT}/current/deploy/bpc_node_enrollment.py"
if [[ -s "${BPC_STATE_DIR}/enrollment.json" && -f "${node_enrollment}" ]]; then
  python3 "${node_enrollment}" --state-dir "${BPC_STATE_DIR}" runtime-install
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

# Enabled transport firewall units are runtime prerequisites. A VPS reboot or
# an interrupted maintenance operation can leave a oneshot RemainAfterExit unit
# inactive even though the transport container/interface is still present.
# Re-assert those units idempotently before the release health check.
repair_firewall_service() {
  local marker="$1"
  local service="$2"

  [[ -f "${marker}" ]] || return 0
  if ! systemctl cat "${service}" >/dev/null 2>&1; then
    echo "WARNING: enabled transport is missing firewall unit: ${service}" >&2
    return 0
  fi
  systemctl enable "${service}" >/dev/null 2>&1 || true
  if ! systemctl --quiet is-active "${service}"; then
    if ! systemctl restart "${service}"; then
      echo "WARNING: failed to reactivate ${service}; health check will report it." >&2
    fi
  fi
}

repair_firewall_service "${ru_dir}/awg/enabled" "bpc-awg-firewall.service"
repair_firewall_service "${ru_dir}/wg/enabled" "bpc-wg-firewall.service"

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

# Mihomo Hysteria2 currently rejects valid clients when
# ignore-client-bandwidth=true (MetaCubeX/mihomo#2792). Older BPC releases used
# that setting, producing a healthy QUIC/TLS exchange followed by authentication
# failure/timeout. Repair only the BPC-managed HY2 listener; credentials and the
# client profile do not change.
if [[ -f "${ru_dir}/mihomo-server/enabled" && -s "${ru_dir}/mihomo-server/config.yaml" ]]; then
  if grep -Fq 'ignore-client-bandwidth: true' "${ru_dir}/mihomo-server/config.yaml"; then
    sed -i 's/ignore-client-bandwidth: true/ignore-client-bandwidth: false/' \
      "${ru_dir}/mihomo-server/config.yaml"
    chmod 0600 "${ru_dir}/mihomo-server/config.yaml"
  fi
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

# BPC <=0.10.8 assigned the same 10.253.0.0/24 subnet to both the
# OpenVPN fallback (bpcovpn) and the self-contained Agent overlay (bpcag0).
# Linux can then route Agent return traffic through bpcovpn even though the
# Agent handshake succeeds. Move only the legacy default OpenVPN subnet to the
# dedicated 10.250.0.0/24 range. Credentials and client profiles remain valid
# because the OpenVPN client does not hard-code its assigned tunnel address.
if [[ -f "${ru_dir}/openvpn/enabled" && -s "${ru_dir}/openvpn/runtime.env" ]]; then
  openvpn_runtime="${ru_dir}/openvpn/runtime.env"
  legacy_openvpn_subnet="$(sed -n 's/^OPENVPN_SUBNET=//p' "${openvpn_runtime}" | head -n1)"
  legacy_openvpn_network="$(sed -n 's/^OPENVPN_SERVER_NETWORK=//p' "${openvpn_runtime}" | head -n1)"

  if [[ "${legacy_openvpn_subnet}" == "10.253.0.0/24" &&         "${legacy_openvpn_network}" == "10.253.0.0" ]]; then
    echo "Migrating BPC OpenVPN subnet 10.253.0.0/24 -> 10.250.0.0/24 to avoid Agent collision."

    # Stop the firewall before changing runtime.env so ExecStop removes rules
    # for the old subnet rather than attempting to remove the new ones.
    if systemctl cat bpc-openvpn-firewall.service >/dev/null 2>&1; then
      systemctl stop bpc-openvpn-firewall.service || true
    fi
    if systemctl cat openvpn-server@bpc.service >/dev/null 2>&1; then
      systemctl stop openvpn-server@bpc.service || true
    fi

    sed -i       -e 's|^OPENVPN_SUBNET=10\.253\.0\.0/24$|OPENVPN_SUBNET=10.250.0.0/24|'       -e 's|^OPENVPN_SERVER_NETWORK=10\.253\.0\.0$|OPENVPN_SERVER_NETWORK=10.250.0.0|'       "${openvpn_runtime}"
    chmod 0600 "${openvpn_runtime}"

    for openvpn_config in "${ru_dir}/openvpn/server.conf" /etc/openvpn/server/bpc.conf; do
      if [[ -s "${openvpn_config}" ]]; then
        sed -i           's|^server 10\.253\.0\.0 255\.255\.255\.0$|server 10.250.0.0 255.255.255.0|'           "${openvpn_config}"
        chmod 0600 "${openvpn_config}"
      fi
    done

    if systemctl cat openvpn-server@bpc.service >/dev/null 2>&1; then
      systemctl restart openvpn-server@bpc.service
    fi
    if systemctl cat bpc-openvpn-firewall.service >/dev/null 2>&1; then
      systemctl restart bpc-openvpn-firewall.service
    fi
  fi
fi

# BPC 0.7.4 generated an OpenVPN TLS server config without an explicit DH
# policy. OpenVPN 2.6 refuses to start such a server with "You must define DH
# file (--dh)". Modern ECDH negotiation does not require a finite-field DH file,
# so repair BPC-managed configs with "dh none" before the release health check.
if [[ -f "${ru_dir}/openvpn/enabled" ]]; then
  openvpn_changed="false"
  for openvpn_config in "${ru_dir}/openvpn/server.conf" /etc/openvpn/server/bpc.conf; do
    if [[ -s "${openvpn_config}" ]] && ! grep -Eq '^dh[[:space:]]+' "${openvpn_config}"; then
      sed -i '/^tls-version-min[[:space:]]/i dh none' "${openvpn_config}"
      chmod 0600 "${openvpn_config}"
      openvpn_changed="true"
    fi
  done
  if [[ "${openvpn_changed}" == "true" ]] && systemctl cat openvpn-server@bpc.service >/dev/null 2>&1; then
    systemctl restart openvpn-server@bpc.service
  fi
fi

# Refresh the WGShim executable from the newly selected release without
# rotating the existing PSK or changing its target. This keeps an enabled
# low-latency relay aligned with the BPC release across normal updates.
if [[ -f "${ru_dir}/wgshim/enabled" ]]; then
  case "$(uname -m)" in
    x86_64|amd64) wgshim_arch="amd64" ;;
    aarch64|arm64) wgshim_arch="arm64" ;;
    *)
      echo "Unsupported architecture for enabled WGShim: $(uname -m)" >&2
      exit 1
      ;;
  esac
  wgshim_binary="${BPC_ROOT}/current/bin/bpc-wgshim-linux-${wgshim_arch}"
  if [[ ! -x "${wgshim_binary}" ]]; then
    echo "Enabled WGShim release binary is missing: ${wgshim_binary}" >&2
    exit 1
  fi
  install -m 0755 "${wgshim_binary}" /usr/local/bin/bpc-wgshim
  if systemctl cat bpc-wgshim.service >/dev/null 2>&1; then
    systemctl restart bpc-wgshim.service
  fi
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

# Repair the self-contained Agent data plane independently from the control
# plane. A failed first-time bpc-enable-control can leave agent/enabled behind
# before control/enabled is written; release health checks must not roll back
# before the new release gets a chance to repair that partial state.
if [[ -f "${ru_dir}/agent/enabled" ]] && \
  [[ -x "${BPC_ROOT}/current/deploy/bpc-enable-agent-dataplane.sh" ]]; then
  "${BPC_ROOT}/current/deploy/bpc-enable-agent-dataplane.sh"
fi

# Reconcile both fully-enabled and interrupted control-plane installations.
# The interrupted case is identified by an enabled systemd unit plus the
# generated runtime/config state, even when control/enabled was never reached.
control_should_reconcile="false"
if [[ -f "${ru_dir}/control/enabled" ]]; then
  control_should_reconcile="true"
elif systemctl --quiet is-enabled bpc-control.service 2>/dev/null && \
  [[ -s "${ru_dir}/control/runtime.env" && -s "${ru_dir}/control/config.json" ]]; then
  control_should_reconcile="true"
fi

if [[ "${control_should_reconcile}" == "true" ]] && \
  [[ -x "${BPC_ROOT}/current/deploy/bpc-enable-control.sh" ]]; then
  "${BPC_ROOT}/current/deploy/bpc-enable-control.sh"
fi
