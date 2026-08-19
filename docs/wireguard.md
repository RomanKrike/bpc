# Native WireGuard transport

BPC can run a standard kernel WireGuard transport alongside Xray VLESS/REALITY and AmneziaWG.

## Default layout

```text
UDP/51820
bpcwg0
10.252.0.1/24  RU node
10.252.0.2/32  generated client
MTU 1380
PersistentKeepalive 25
```

The default interface and subnet are intentionally separate from AmneziaWG (`awg0`, `10.251.0.0/24`).

## Enable on an existing RU node

Update BPC first, then enable the transport:

```bash
sudo bpc-update
sudo bpc-enable-wg
sudo bpc-status
```

Use a different UDP port if required:

```bash
sudo WG_PORT=51821 bpc-enable-wg
```

On first enable, BPC installs `wireguard-tools`, verifies kernel WireGuard support, generates server/client keys plus a preshared key, provisions `bpcwg0`, enables IPv4 forwarding and adds persistent forwarding/NAT rules.

Repeated `bpc-enable-wg` runs keep the existing keys and endpoint.

## Generated client files

Native WireGuard configuration:

```text
/etc/bpc-connect/ru-node/wg/client.conf
```

Ready-to-import Clash Verge Rev profile:

```text
/etc/bpc-connect/ru-node/wg/clash-verge.yaml
```

Internal BPC transport fragment:

```text
/etc/bpc-connect/ru-node/wg/transport.yaml
```

All files containing client keys are mode `0600` and must not be committed to a public repository or pasted into issue trackers.

## Server status

```bash
bpc-status
wg show bpcwg0
systemctl status wg-quick@bpcwg0 --no-pager
systemctl status bpc-wg-firewall --no-pager
ss -lunp | grep ':51820'
```

Before a client connects, `wg show bpcwg0` will not show `latest handshake`; this is normal. After a successful client connection it should show a recent handshake and transfer counters.

## Packet-path diagnostics

To determine whether UDP reaches the VPS at all:

```bash
tcpdump -ni eth0 udp port 51820 -vv
```

If the client attempts to connect but no packets appear, the failure is upstream of the guest WireGuard service: client network, transit path, provider edge firewall/anti-DDoS, or hypervisor networking.

If packets appear but `wg show bpcwg0` has no handshake, investigate keys, peer configuration and WireGuard interoperability.

## Removal / disablement

The current milestone does not include a destructive `bpc-disable-wg` command. To stop the transport without deleting credentials:

```bash
systemctl disable --now bpc-wg-firewall.service
systemctl disable --now wg-quick@bpcwg0.service
```

The generated credentials remain under `/etc/bpc-connect/ru-node/wg` so the same peer identity can be restored later.
