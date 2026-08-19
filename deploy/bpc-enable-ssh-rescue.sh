#!/usr/bin/env bash
set -euo pipefail

BPC_STATE_DIR="${BPC_STATE_DIR:-/etc/bpc-connect}"
RU_DIR="${BPC_STATE_DIR}/ru-node"
SSH_DIR="${RU_DIR}/ssh-rescue"
SSH_USER="${BPC_SSH_RESCUE_USER:-bpc-rescue}"
SSH_PORT="${BPC_SSH_RESCUE_PORT:-22}"
SSHD_DROPIN="/etc/ssh/sshd_config.d/90-bpc-rescue.conf"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run bpc-enable-ssh-rescue as root" >&2
  exit 1
fi
if ! [[ "${SSH_PORT}" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
  echo "BPC_SSH_RESCUE_PORT must be between 1 and 65535" >&2
  exit 2
fi
if ! [[ "${SSH_USER}" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]]; then
  echo "BPC_SSH_RESCUE_USER is not a valid system username" >&2
  exit 2
fi

client_env="${RU_DIR}/client.env"
if [[ ! -f "${client_env}" ]]; then
  echo "RU-node client.env is missing; install the RU node first" >&2
  exit 2
fi
BPC_RU_HOST="$(sed -n 's/^BPC_RU_HOST=//p' "${client_env}" | head -n1)"
if [[ -z "${BPC_RU_HOST}" ]]; then
  echo "BPC_RU_HOST is missing from client.env" >&2
  exit 2
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends openssh-client openssh-server

if ! command -v sshd >/dev/null 2>&1; then
  echo "OpenSSH server is unavailable after package installation" >&2
  exit 3
fi

install -d -m 0700 "${SSH_DIR}"
if ! id "${SSH_USER}" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "/var/lib/${SSH_USER}" \
    --shell /usr/sbin/nologin "${SSH_USER}"
fi
user_home="$(getent passwd "${SSH_USER}" | cut -d: -f6)"
if [[ -z "${user_home}" || ! -d "${user_home}" ]]; then
  echo "Unable to determine rescue user home directory" >&2
  exit 3
fi

client_key="${SSH_DIR}/client.key"
client_pub="${SSH_DIR}/client.key.pub"
if [[ ! -f "${SSH_DIR}/enabled" ]]; then
  umask 077
  ssh-keygen -q -t ed25519 -N '' -C 'bpc-rescue' -f "${client_key}"
else
  if [[ ! -s "${client_key}" || ! -s "${client_pub}" ]]; then
    echo "Enabled SSH rescue state is incomplete" >&2
    exit 4
  fi
fi

install -d -o "${SSH_USER}" -g "${SSH_USER}" -m 0700 "${user_home}/.ssh"
public_key="$(tr -d '\r\n' < "${client_pub}")"
printf 'restrict,port-forwarding %s\n' "${public_key}" > "${user_home}/.ssh/authorized_keys"
chown "${SSH_USER}:${SSH_USER}" "${user_home}/.ssh/authorized_keys"
chmod 0600 "${user_home}/.ssh/authorized_keys"

install -d -m 0755 /etc/ssh/sshd_config.d
previous_dropin=""
if [[ -f "${SSHD_DROPIN}" ]]; then
  previous_dropin="$(cat "${SSHD_DROPIN}")"
fi
cat > "${SSHD_DROPIN}" <<CONF
Match User ${SSH_USER}
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    AllowTcpForwarding yes
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
    GatewayPorts no
CONF
chmod 0644 "${SSHD_DROPIN}"

restore_dropin() {
  if [[ -n "${previous_dropin}" ]]; then
    printf '%s\n' "${previous_dropin}" > "${SSHD_DROPIN}"
  else
    rm -f "${SSHD_DROPIN}"
  fi
}

if ! sshd -t; then
  restore_dropin
  sshd -t || true
  echo "Generated SSH rescue configuration failed sshd validation; restored prior state" >&2
  exit 4
fi

ssh_service=""
for candidate in ssh.service sshd.service; do
  if systemctl cat "${candidate}" >/dev/null 2>&1; then
    ssh_service="${candidate}"
    break
  fi
done
if [[ -z "${ssh_service}" ]]; then
  restore_dropin
  echo "Unable to locate the OpenSSH systemd service" >&2
  exit 4
fi
if ! systemctl reload "${ssh_service}"; then
  restore_dropin
  if sshd -t; then
    systemctl reload "${ssh_service}" || true
  fi
  echo "OpenSSH reload failed; restored prior configuration" >&2
  exit 5
fi

host_pub=""
for host_key in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub /etc/ssh/ssh_host_rsa_key.pub; do
  if [[ -s "${host_key}" ]]; then
    read -r host_type host_data _ < "${host_key}"
    host_pub="${host_type} ${host_data}"
    break
  fi
done
if [[ -z "${host_pub}" ]]; then
  echo "No SSH host public key is available" >&2
  exit 5
fi

private_key="$(cat "${client_key}")"
profile="${SSH_DIR}/clash-verge.yaml"
cat > "${profile}" <<PROFILE
proxies:
  - name: BPC-RU-SSH-RESCUE
    type: ssh
    server: ${BPC_RU_HOST}
    port: ${SSH_PORT}
    username: ${SSH_USER}
    private-key: |-
$(printf '%s\n' "${private_key}" | sed 's/^/      /')
    host-key:
      - "${host_pub}"
PROFILE
chmod 0600 "${client_key}" "${client_pub}" "${profile}"

cat > "${SSH_DIR}/runtime.env" <<STATE
SSH_RESCUE_USER=${SSH_USER}
SSH_RESCUE_PORT=${SSH_PORT}
SSH_RESCUE_SERVICE=${ssh_service}
STATE
chmod 0600 "${SSH_DIR}/runtime.env"
touch "${SSH_DIR}/enabled"
chmod 0600 "${SSH_DIR}/enabled"

cat <<DONE
BPC SSH rescue transport is ready.
Endpoint: ${BPC_RU_HOST}:${SSH_PORT}/tcp
User: ${SSH_USER}
Client profile: ${profile}

The rescue account has no password, no shell/TTY and no agent/X11 forwarding.
Only SSH TCP forwarding is allowed. This transport is manual rescue and is not
part of BPC-AUTO because Mihomo's SSH outbound does not provide UDP transport.
DONE
