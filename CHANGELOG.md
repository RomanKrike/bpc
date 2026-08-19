# Changelog

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
- `bpc-enable-awg` command and `--with-awg` installer option.

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
