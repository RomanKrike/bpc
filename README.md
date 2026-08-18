# BPC Connect

Fail-closed multi-transport connectivity bridge for the first BPC milestone: **Georgia -> Russia -> corporate VPN / home infrastructure**.

## Current scope

- Russian exit node based on Xray VLESS + REALITY.
- Optional AmneziaWG 2.0 transport on the same RU node.
- Mihomo gateway config generator.
- Ordered fallback model for VLESS/REALITY, AmneziaWG and Tailscale.
- Config generator with safety validation.
- Fail-closed policy: no automatic DIRECT route from the work gateway.
- Versioned deployment bundles, one-command install and safe updates with rollback.
- GitHub Actions CI, tests and automatic GitHub Releases.

This repository intentionally separates the BPC underlay from the corporate VPN. The corporate VPN remains on the work laptop; BPC provides it with a Russian egress path.

## One-command RU node install

On a clean Debian 13 VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh \
  | sudo bash -s -- --role ru-node --reality-server-name YOUR_REALITY_TARGET
```

To provision both transports immediately:

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh \
  | sudo bash -s -- \
      --role ru-node \
      --reality-server-name YOUR_REALITY_TARGET \
      --with-awg
```

Optional parameters:

```text
--port 443
--public-host 203.0.113.10
--awg-port 443
```

Xray uses TCP while AmneziaWG uses UDP, so both can listen on port 443 simultaneously. The provider firewall must permit the corresponding protocol/port.

The installer downloads the latest GitHub Release deployment bundle, verifies it against the published `SHA256SUMS`, installs it under `/opt/bpc/releases/<version>`, provisions the RU node on first install, and preserves generated credentials under `/etc/bpc-connect`.

After installation:

```bash
sudo bpc-status
sudo bpc-update
```

Enable AWG2 later on an existing node:

```bash
sudo bpc-update
sudo bpc-enable-awg
sudo bpc-status
```

`bpc-update` downloads the latest release, backs up `/etc/bpc-connect`, atomically switches `/opt/bpc/current`, validates managed services, and rolls back to the previous release if the health check fails.

Generated client files:

```text
/etc/bpc-connect/ru-node/gateway-transport.yaml
/etc/bpc-connect/ru-node/awg/client.conf
/etc/bpc-connect/ru-node/awg/clash-verge.yaml
```

The AWG files contain private client credentials and must be treated as secrets.

See `docs/install-update.md`, `docs/ru-node.md` and `docs/amneziawg.md`.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check .
```

Validate and render the example:

```bash
bpc-connect validate config/gateway.example.yaml
bpc-connect render config/gateway.example.yaml -o build/mihomo/config.yaml
```

## Security

- Never commit production UUIDs, private keys, Tailscale auth keys, Mihomo API secrets or real infrastructure credentials.
- Treat generated gateway, Xray and AmneziaWG configurations as secrets.
- The work gateway must fail closed: transport failure must not expose the work laptop directly through the Georgia ISP.
- Release checksums detect corrupted or mismatched artifacts; stronger signed-release verification can be added in a later milestone.
