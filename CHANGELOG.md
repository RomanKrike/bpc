# Changelog

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
