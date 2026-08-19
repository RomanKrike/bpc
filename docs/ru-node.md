# Russian exit node

`deploy/bootstrap-ru-node.sh` provisions the first BPC Connect server transport: VLESS + REALITY on Xray.

## Goal

The RU node is an application-level Russian egress proxy for the Georgia gateway. The corporate VPN remains on the work laptop. Mihomo on the Georgia gateway sends the laptop traffic through VLESS/REALITY to this node; Xray's `freedom` outbound then opens the destination connection from the Russian VPS.

## Requirements

- Debian 13 VPS with a public IPv4 address.
- Root access.
- A free TCP listen port (443 is preferred when available).
- A REALITY target hostname that is reachable from the RU VPS and suitable for TLS forwarding.

For the pinned Xray 26.3.27 runtime, BPC recommends `www.bing.com`. Do not use `www.microsoft.com`: its TLS Certificate record can exceed the 8192-byte limit in the REALITY parser and cause `handshake did not complete successfully` even though ordinary `curl`/TLS access to Microsoft works. See [XTLS/Xray-core#6356](https://github.com/XTLS/Xray-core/issues/6356).

## Deploy

```bash
REALITY_SERVER_NAME=www.bing.com \
XRAY_PORT=443 \
XRAY_VERSION=v26.3.27 \
sudo -E bash ./deploy/bootstrap-ru-node.sh
```

If `REALITY_SERVER_NAME` is omitted when running the bootstrap script directly, it defaults to `www.bing.com`.

Set `BPC_PUBLIC_HOST` if you want to force the public IP/FQDN written into the generated client files. Otherwise the bootstrap tries to discover the public IPv4 address.

The bootstrap:

1. installs the minimal dependencies;
2. runs `bpc-check-reality-target.sh` to verify DNS/TLS compatibility and reject oversized Certificate handshakes;
3. installs a pinned Xray release with the official XTLS installer;
4. generates a VLESS UUID, X25519 REALITY key pair, and 8-byte short ID;
5. renders `/etc/bpc-connect/ru-node/config.json`;
6. validates it with `xray run -test` before restart;
7. installs a systemd override and starts Xray;
8. writes client-side values to `/etc/bpc-connect/ru-node/client.env`;
9. writes a ready-to-merge Mihomo transport fragment to `/etc/bpc-connect/ru-node/gateway-transport.yaml`.

The target preflight uses a TLS 1.3 probe and inspects the Certificate handshake length. `www.microsoft.com` is explicitly rejected for the pinned runtime because CDN responses can vary between probes; other targets are rejected when the observed Certificate handshake exceeds `BPC_REALITY_MAX_CERT_HANDSHAKE` (8192 bytes by default).

All generated credential/configuration files are root-only and must never be committed.

## Firewall

The bootstrap deliberately does not replace the host firewall. Permit the selected `XRAY_PORT` in the VPS provider firewall and/or existing host firewall. Existing SSH and production firewall rules are left untouched.

## Verify

```bash
systemctl status xray --no-pager
ss -ltnp | grep ':443'
/usr/local/bin/xray run -test -config /etc/bpc-connect/ru-node/config.json
cat /etc/bpc-connect/ru-node/client.env
cat /etc/bpc-connect/ru-node/gateway-transport.yaml
```

Before using the node for work, run the end-to-end tests from the gateway and verify that the observed public IP is the RU VPS address.
