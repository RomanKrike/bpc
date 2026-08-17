# Changelog

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
