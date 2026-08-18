# AmneziaWG 2.0 transport

BPC can run AmneziaWG 2.0 beside the Xray RU transport on the same VPS:

```text
TCP/443 -> Xray VLESS + REALITY
UDP/443 -> AmneziaWG 2.0
```

The initial AWG2 profile deliberately uses only the base AWG2 obfuscation parameters. CPS/I1-I5 signatures are deferred until the base transport has passed an end-to-end interoperability test with the target Mihomo build.

## Enable on an existing RU node

Upgrade BPC first, then enable the transport:

```bash
sudo bpc-update
sudo bpc-enable-awg
sudo bpc-status
```

The VPS/provider firewall must allow inbound UDP/443. If another service already owns UDP/443, select another port on first enable:

```bash
sudo AWG_PORT=8443 bpc-enable-awg
```

A repeated `bpc-enable-awg` run preserves the original keys, port and runtime image.

## Runtime

The v0.2.0 implementation uses a pinned official AmneziaWG userspace image and creates a persistent container named `bpc-awg`. BPC also enables IPv4 forwarding and installs an idempotent systemd-managed forwarding/NAT rule set for the AWG subnet.

Server state is stored under:

```text
/etc/bpc-connect/ru-node/awg/
```

Important files:

```text
awg0.conf          server configuration
client.conf        native AmneziaWG client configuration
clash-verge.yaml   ready-to-import Clash Verge Rev profile
transport.yaml     BPC internal transport representation
runtime.env        non-secret runtime metadata
enabled            transport marker
```

Treat everything in this directory as root-only because the client/server configuration files contain private keys.

## Clash Verge Rev test

Copy `clash-verge.yaml` to the Windows machine using a trusted channel and import it as a profile in Clash Verge Rev.

For the proxy-only test keep:

```text
TUN Mode: OFF
System Proxy: OFF
Mixed Port: 7897
```

Select `BPC-RUSSIA -> BPC-RU-AWG-01`, then test in Windows PowerShell:

```powershell
curl.exe --proxy socks5h://127.0.0.1:7897 https://ifconfig.me
```

The result should be the public IPv4 address of the RU VPS.

After the client test, inspect the server handshake without exposing keys:

```bash
docker exec bpc-awg awg show awg0
```

A successful connection should show a recent handshake and increasing transfer counters.

## Diagnostics

```bash
bpc-status
docker ps --filter name=bpc-awg
docker logs --tail 100 bpc-awg
docker exec bpc-awg awg show awg0
systemctl status bpc-awg-firewall.service --no-pager
ss -lunp | grep ':443'
```
