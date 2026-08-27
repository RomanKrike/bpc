# Changelog

## 0.7.4

### Fixed
- Disable Mihomo Hysteria2 `ignore-client-bandwidth` mode because current Mihomo builds can reject valid HY2 clients during authentication when it is enabled (MetaCubeX/mihomo#2792).
- Repair existing BPC Hysteria2 listeners during migration by switching only `ignore-client-bandwidth: true` to `false` without rotating credentials or changing the subscription profile.

## 0.7.3

### Fixed
- Re-activate enabled AWG and WireGuard firewall/NAT oneshot services during migration when they are unexpectedly inactive, preventing false update failures after reboot or interrupted maintenance.
- Run rollback migration logic from the restored release instead of the failed new release, avoiding missing-helper errors when rolling back across versions.
- Treat migration failure as an update failure and enter the normal rollback path instead of leaving the new release selected with partially migrated state.

## 0.7.2

### Fixed
- Stage Let's Encrypt certificate and private-key copies inside the Mihomo home directory so TLS listeners comply with Mihomo v1.19.29 `SAFE_PATHS` restrictions.
- Repair existing Hysteria2, TUIC, AnyTLS, Trojan and TrustTunnel listeners during migration without rotating transport credentials or changing the subscription URL.
- Refresh the staged TLS material automatically after certificate renewal before restarting the Mihomo transport service.
- Add a systemd post-start listener check so a running Mihomo process cannot be reported healthy when individual protocol listeners failed to bind.

## 0.7.1

### Fixed
- Normalize generated Mihomo client-profile credential quoting so passwords are valid YAML scalars instead of containing literal `\"` characters.
- Repair existing Hysteria2, TUIC, AnyTLS, Shadowsocks/ShadowTLS, Trojan, Mieru and TrustTunnel client fragments during migration without rotating credentials.
- Fix Shadowsocks 2022 client startup failure `decode key: illegal base64 data at input byte 0` caused by the escaped quote prefix around its Base64 key.
- Validate the generated aggregate Clash profile with the pinned Mihomo core during BPC health checks so client-side configuration errors are caught before an update is accepted.

## 0.7.0

### Added
- `bpc-enable-openvpn` for a dedicated OpenVPN fallback with a private BPC CA, client certificate, `tls-crypt`, forwarding/NAT service, native `.ovpn` profile and Mihomo client profile.
- OpenVPN UDP/1194 by default with optional TCP mode through `BPC_OPENVPN_PROTO=tcp`; TCP mode uses the correct `tcp-server` / `tcp-client` OpenVPN roles.
- `bpc-enable-ikev2 --hostname HOST` for a native strongSwan IKEv2 roadwarrior fallback using EAP-MSCHAPv2, a trusted Let's Encrypt server identity, a private client address pool and forwarding/NAT rules.
- Root-only Windows IKEv2 connection details under `/etc/bpc-connect/ru-node/ikev2/client-info.txt`.
- Health and status reporting for OpenVPN and IKEv2 without exposing private credentials.

### Changed
- When OpenVPN is enabled, the Clash subscription exposes it only through the manual `BPC-ROUTE` selector alongside SSH rescue; `BPC-AUTO` remains limited to the primary health-checked transports.
- IKEv2 is intentionally OS-level and remains outside the Clash subscription and `BPC-AUTO`.
- The OpenVPN server disables time-based renegotiation with `reneg-sec 0` as a compatibility mitigation for the current Mihomo OpenVPN rekey limitation.

### Security
- OpenVPN private CA/client keys and IKEv2 EAP credentials remain root-only and are never printed by `bpc-status`.
- IKEv2 loads the Let's Encrypt leaf certificate, intermediate chain and private key into separate strongSwan credential stores and refreshes them after certificate renewal.
- IKEv2 client documentation explicitly warns against unsupported nested use with a corporate VPN.

## 0.6.0

### Added
- Optional RU-node Mihomo transport pack, pinned to Mihomo v1.19.29 and verified against the SHA-256 digest published on the official GitHub Release.
- Hysteria2 with Salamander obfuscation on UDP/8443 by default.
- TUIC v5 on UDP/10443 by default.
- AnyTLS on TCP/10443 by default; TCP and UDP intentionally reuse the numeric port without conflict.
- Shadowsocks 2022 with ShadowTLS v2 on TCP/9443 by default.
- Trojan on TCP/12443, Mieru on TCP/2999 and TrustTunnel HTTP2/HTTP3 on TCP+UDP/11443 by default.
- `bpc-enable-mihomo-transports --hostname HOST` to provision all supported Mihomo server listeners, trusted TLS, random root-only credentials, client fragments and a persistent systemd service.
- `bpc-enable-ssh-rescue` to provision a key-only, forwarding-only OpenSSH account and a manual Mihomo SSH rescue proxy.
- Health and status reporting for the new transport pack and SSH rescue channel.

### Changed
- `BPC-AUTO` can now fail over across AWG, WireGuard, Hysteria2, TUIC, VLESS/REALITY, AnyTLS, ShadowTLS, Trojan, Mieru and TrustTunnel when those transports are enabled.
- SSH rescue is deliberately excluded from automatic failover because Mihomo SSH is TCP-only; when enabled the aggregate profile exposes `BPC-ROUTE` for an explicit manual switch from `BPC-AUTO` to SSH rescue.
- Secure Clash subscription automatically serves the newly rendered multi-protocol profile without changing the subscription URL.

### Security
- Multi-protocol credentials and generated client profiles remain root-only under `/etc/bpc-connect/ru-node` and are never printed by status commands.
- TLS listeners reuse or obtain a trusted Let's Encrypt certificate; certificate renewal restarts the Mihomo transport service.
- SSH rescue disables password authentication, shell/TTY, agent forwarding and X11 forwarding for the dedicated account while allowing only TCP forwarding.

## 0.5.1

### Fixed
- Fresh RU-node provisioning now preflights the selected REALITY target before generating credentials or installing Xray runtime state.
- Reject `www.microsoft.com` for the pinned Xray 26.3.27 runtime because its TLS Certificate record can exceed the REALITY parser's 8192-byte limit and cause `handshake did not complete successfully`.
- Reject other REALITY targets when the observed TLS Certificate handshake exceeds the configured compatibility limit.
- Migration now keeps the generated `gateway-transport.yaml` REALITY server name aligned with `client.env`, repairing nodes where the target was changed manually during diagnosis.

### Changed
- Direct RU-node bootstrap defaults to `www.bing.com` when `REALITY_SERVER_NAME` is omitted.
- Installation examples now use `www.bing.com` as the tested REALITY target.

## 0.5.0

### Added
- Tokenized HTTPS endpoint for the generated aggregate Clash Verge Rev profile.
- `bpc-enable-subscription --hostname HOST` to obtain a trusted Let's Encrypt certificate, generate a 256-bit secret URL token and start the subscription service on TCP/8443 by default.
- `bpc-subscription-url` to print the secret subscription URL on demand.
- Automatic certificate renewal through `certbot.timer` with a deploy hook that restarts the subscription service after renewal.
- Subscription health/status reporting without exposing the secret URL token.

### Security
- Subscription profiles are served only over TLS and only from the exact tokenized path.
- Request paths are not written to the subscription service logs because the path contains the access token.
- Subscription state and token files remain root-only under `/etc/bpc-connect/ru-node/subscription`.

## 0.4.1

### Fixed
- `bpc-render-clash` no longer changes ownership or permissions of `/etc/bpc-connect/ru-node` while generating the aggregate Clash profile.
- Prevent an update-time Xray restart failure caused by the renderer making the RU-node state directory root-only.
- Health checks now report the specific failing component before automatic rollback.

## 0.4.0

### Added
- Root-only aggregate Clash Verge Rev profile at `/etc/bpc-connect/ru-node/clash-verge-auto.yaml`.
- `bpc-render-clash` command for rebuilding the aggregate client profile without rotating transport credentials.
- Client-side Mihomo health checks with automatic failover across AWG, WireGuard and VLESS/REALITY.
- Configurable transport order through `BPC_CLASH_TRANSPORT_ORDER` and health-check tuning through `BPC_CLASH_HEALTH_*` environment variables.

### Changed
- Default automatic client preference is AmneziaWG -> WireGuard -> VLESS/REALITY.
- Existing RU nodes automatically receive the aggregate profile during migration to 0.4.0.

## 0.3.1

### Added
- `bpc-ensure-dns` command with automatic `systemd-resolved` repair and a static `resolv.conf` fallback when name resolution is unavailable.
- DNS diagnostics in `bpc-status`.
- WireGuard and AmneziaWG peer handshake/traffic diagnostics in `bpc-status`.

### Fixed
- Fresh installs now repair broken DNS before package and release downloads.
- RU-node public endpoint detection prefers the public source IPv4 and no longer silently falls back to the machine hostname.
- AWG, WireGuard and update flows repair DNS before network-dependent package/download operations.

## 0.3.0

### Added
- Native WireGuard transport on UDP/51820 alongside VLESS/REALITY and AmneziaWG.
- `bpc-enable-wg` command and `--with-wg` / `--wg-port` installer options.
- Dedicated `bpcwg0` interface and `10.252.0.0/24` transport subnet.
- Persistent `wg-quick` systemd service, IPv4 forwarding, NAT and WireGuard health checks.
- Root-only native WireGuard client configuration and ready-to-import Clash Verge Rev profile.
- Native WireGuard support in the BPC gateway transport model and Mihomo fallback renderer.

## 0.2.1

### Fixed
- Reconcile installed BPC command symlinks before the same-version updater exit, allowing commands introduced by a new release to self-heal after an upgrade performed by an older updater.

## 0.2.0

### Added
- Optional AmneziaWG 2.0 transport on UDP/443 alongside Xray VLESS/REALITY on TCP/443.
- Pinned official AmneziaWG userspace runtime with generated server/client keys and a persistent container.
- RU-node IPv4 forwarding, NAT and AmneziaWG health checks.
- Ready-to-import Clash Verge Rev AWG2 profile and native AmneziaWG client configuration.
- `bpc-enable-awg` command and `--with-awg` / `--awg-port` installer options.

## 0.1.1

### Fixed
- Allow the Xray systemd service user to traverse the RU-node configuration directory and read `config.json`.
- Keep client credentials and generated Mihomo transport fragments root-only.

## 0.1.0

### Added
- Initial BPC Connect repository structure.
- Mihomo gateway config generator.
- VLESS/REALITY, AmneziaWG and Tailscale outbound models.
- Fail-closed validation and nftables kill-switch template.
- CI, linting, unit tests and deployment bundle validation.
- Automated Debian RU exit-node bootstrap for Xray VLESS + REALITY.
- RU node Xray server renderer and REALITY short-ID validation.
- Automatic generation of root-only client credentials and Mihomo transport fragments.
- One-command installation from the latest GitHub Release.
- Immutable versioned releases under `/opt/bpc/releases` with `/opt/bpc/current` activation.
- `bpc-status` health/status command.
- `bpc-update` with state backup, health checks and automatic rollback.
- Automatic GitHub Release publication after successful CI on `main`.
