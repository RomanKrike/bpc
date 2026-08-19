# BPC Connect

Fail-closed multi-transport connectivity bridge for the first BPC milestone: **Georgia -> Russia -> corporate VPN / home infrastructure**.

## Current scope

- Russian exit node based on Xray VLESS + REALITY.
- Optional AmneziaWG 2.0 transport on UDP/443.
- Optional native WireGuard transport on UDP/51820.
- Mihomo gateway config generator.
- Automatic Clash Verge Rev failover profile for AWG, WireGuard and VLESS/REALITY.
- Optional tokenized HTTPS subscription endpoint for the aggregate Clash profile.
- REALITY target compatibility preflight before fresh Xray provisioning.
- Config generator with safety validation.
- Fail-closed policy: no automatic DIRECT route from the work gateway.
- Versioned deployment bundles, one-command install and safe updates with rollback.
- Automatic DNS preflight/repair for Debian RU nodes when resolver configuration is broken.
- GitHub Actions CI, tests and automatic GitHub Releases.

This repository intentionally separates the BPC underlay from the corporate VPN. The corporate VPN remains on the work laptop; BPC provides it with a Russian egress path.

## RU node network layout

```text
TCP/443    -> Xray VLESS + REALITY
UDP/443    -> AmneziaWG 2.0
UDP/51820  -> native WireGuard
TCP/8443   -> optional HTTPS Clash subscription
TCP/80     -> Let's Encrypt HTTP-01 validation/renewal when subscription is enabled
```

The transports are independent. Enabling or disabling one does not replace the others.

The generated aggregate Clash profile uses Mihomo's `fallback` group. The default order is:

```text
AmneziaWG -> WireGuard -> VLESS/REALITY
```

Mihomo continuously health-checks the transports and selects the first healthy option in that order. There is no `DIRECT` fallback, so if all BPC transports are unavailable the profile fails closed.

## One-command RU node install

On a clean Debian 13 VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh \
  | sudo bash -s -- --role ru-node --reality-server-name www.bing.com
```

To provision all currently implemented RU transports immediately:

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh \
  | sudo bash -s -- \
      --role ru-node \
      --reality-server-name www.bing.com \
      --with-awg \
      --with-wg
```

Optional parameters:

```text
--port 443
--public-host 203.0.113.10
--awg-port 443
--wg-port 51820
```

The provider firewall must permit each enabled protocol/port.

The installer downloads the latest GitHub Release deployment bundle, verifies it against the published `SHA256SUMS`, installs it under `/opt/bpc/releases/<version>`, provisions the RU node on first install, and preserves generated credentials under `/etc/bpc-connect`.

Before generating credentials, the RU bootstrap checks that the selected REALITY target resolves, completes a TLS 1.3 handshake, and does not expose a Certificate handshake larger than the pinned REALITY parser limit. `www.microsoft.com` is explicitly rejected for the pinned Xray 26.3.27 runtime because its TLS Certificate record can exceed the 8192-byte REALITY limit and cause `handshake did not complete successfully`; see [XTLS/Xray-core#6356](https://github.com/XTLS/Xray-core/issues/6356). `www.bing.com` is the tested BPC recommendation for this runtime.

If DNS resolution is unavailable, the installer first attempts to repair `systemd-resolved` with public resolvers. If `systemd-resolved` is unavailable, BPC can install a static `/etc/resolv.conf` fallback and preserves the previous file as `/etc/resolv.conf.bpc-backup` when possible. Resolver defaults can be overridden with `BPC_DNS_SERVERS` and `BPC_FALLBACK_DNS`.

For RU-node endpoint discovery, BPC first checks the IPv4 source address selected by the default route and then public IPv4 lookup services. It no longer silently writes the local machine hostname as the client endpoint. If a usable public endpoint cannot be detected, install with `--public-host` explicitly.

After installation:

```bash
sudo bpc-status
sudo bpc-update
sudo bpc-ensure-dns
sudo bpc-render-clash
```

Enable additional transports later on an existing node:

```bash
sudo bpc-update
sudo bpc-enable-awg
sudo bpc-enable-wg
sudo bpc-render-clash
sudo bpc-status
```

`bpc-update` downloads the latest release, backs up `/etc/bpc-connect`, atomically switches `/opt/bpc/current`, validates managed services, and rolls back to the previous release if the health check fails.

`bpc-status` reports local service health plus DNS state and the latest WireGuard/AmneziaWG peer handshake and traffic counters when those transports are enabled.

`bpc-render-clash` creates a root-only aggregate profile at `/etc/bpc-connect/ru-node/clash-verge-auto.yaml`. Existing installations automatically receive this profile during migration. The default preference can be overridden, for example:

```bash
BPC_CLASH_TRANSPORT_ORDER="wg awg vless" sudo -E bpc-render-clash
```

Health-check behavior can be tuned through `BPC_CLASH_HEALTH_URL`, `BPC_CLASH_HEALTH_INTERVAL`, `BPC_CLASH_HEALTH_TIMEOUT` and `BPC_CLASH_MAX_FAILED_TIMES`.

## Secure Clash subscription

Create a DNS A record such as `sub.example.com` pointing to the RU node and permit inbound TCP/80 and TCP/8443. Then enable the subscription endpoint:

```bash
sudo bpc-enable-subscription --hostname sub.example.com
```

BPC obtains a trusted Let's Encrypt certificate through HTTP-01, generates a 256-bit random URL token, starts a hardened HTTPS service on TCP/8443, and serves the current aggregate profile from exactly one secret URL path. The aggregate profile is read on every request, so later `bpc-render-clash` updates are available immediately without copying files to the client.

Show the secret URL later with:

```bash
sudo bpc-subscription-url
```

`bpc-status` intentionally hides the token. Request paths are not written to the subscription service logs. The token and runtime state are root-only under `/etc/bpc-connect/ru-node/subscription`.

Let's Encrypt renewal is handled by `certbot.timer`. TCP/80 must remain reachable for HTTP-01 renewals unless certificate management is replaced with another supported method.

Generated client files:

```text
/etc/bpc-connect/ru-node/gateway-transport.yaml
/etc/bpc-connect/ru-node/clash-verge-auto.yaml
/etc/bpc-connect/ru-node/awg/client.conf
/etc/bpc-connect/ru-node/awg/clash-verge.yaml
/etc/bpc-connect/ru-node/wg/client.conf
/etc/bpc-connect/ru-node/wg/clash-verge.yaml
/etc/bpc-connect/ru-node/subscription/token
/etc/bpc-connect/ru-node/subscription/runtime.env
```

The aggregate Clash profile, AWG profile, WireGuard client files and subscription URL contain or grant access to private credentials and must be treated as secrets.

See `docs/install-update.md`, `docs/ru-node.md`, `docs/amneziawg.md`, `docs/wireguard.md` and `docs/subscription.md`.

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

- Never commit production UUIDs, private keys, WireGuard PSKs, Tailscale auth keys, Mihomo API secrets, subscription URLs or real infrastructure credentials.
- Treat generated gateway, Xray, AmneziaWG, WireGuard and aggregate Clash configurations as secrets.
- Treat the tokenized subscription URL like a password; anyone holding it can download the client profile and its credentials.
- The work gateway must fail closed: transport failure must not expose the work laptop directly through the Georgia ISP.
- Release checksums detect corrupted or mismatched artifacts; stronger signed-release verification can be added in a later milestone.
