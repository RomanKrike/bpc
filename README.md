# BP Connect

Fail-closed multi-transport connectivity bridge for the first BPC milestone: **Georgia -> Russia -> corporate VPN / home infrastructure**.

## Current scope

- Russian exit node based on Xray VLESS + REALITY.
- Optional AmneziaWG 2.0 transport on UDP/443.
- Optional native WireGuard transport on UDP/51820.
- Optional Mihomo server transport pack: Hysteria2, TUIC v5, AnyTLS, Shadowsocks 2022 + ShadowTLS, Trojan, Mieru and TrustTunnel.
- Optional OpenVPN UDP/TCP fallback with both native and Mihomo client profiles.
- Optional native strongSwan IKEv2 fallback for OS-level recovery.
- Optional key-only SSH rescue transport for manual TCP fallback.
- Automatic Clash Verge Rev failover profile across enabled primary UDP/TCP proxy transports.
- Manual `BPC-ROUTE` selector for transports that should not participate in automatic failover.
- `BPC-MANUAL` selector for forcing any enabled primary transport during protocol testing.
- Server-managed selective underlay routing for exact VPN/WireGuard endpoint IPv4 addresses.
- Experimental WGShim low-latency authenticated UDP wrapper for an existing WireGuard endpoint, without Clash/Mihomo in the data path.
- Optional tokenized HTTPS subscription endpoint for the aggregate Clash profile.
- REALITY target compatibility preflight before fresh Xray provisioning.
- Config generator with safety validation.
- Fail-closed policy: no automatic DIRECT route from the work gateway.
- Versioned deployment bundles, one-command install and safe updates with rollback.
- Automatic DNS preflight/repair for Debian RU nodes when resolver configuration is broken.
- GitHub Actions CI, tests and automatic GitHub Releases.

This repository intentionally separates the BPC underlay from the corporate VPN. The corporate VPN remains on the work laptop; BPC provides it with a Russian egress path.


## Unified Node model

Server-side BPC is modeled as one `Node`. `controller`, `gateway`, `relay`
and `site_router` are independent capabilities, so one machine can run several
of them at once.

```text
ru-01 = controller + gateway + relay
```

Canonical domain state is rooted at `/etc/bpc-connect/`:

```text
node.yaml
identity/
cluster/
control/
runtime/
transports/
compat/
backups/
```

Controller state is now canonical at `/etc/bpc-connect/control/`. Historical
transport state under `/etc/bpc-connect/ru-node/` remains compatibility input
for existing installations; new core code does not use it as the domain model.

Inspect Node state with:

```bash
sudo bpc node status
sudo bpc node info
```

Stage 4.5 also adds backup-first canonical migration and explicit network
ownership. Unknown or external WireGuard interfaces, routes and firewall state
are not migration targets. See [docs/architecture.md](docs/architecture.md).

## One-command Node Join

On an existing distributed Controller, create a scoped invitation:

```bash
bpc node create --name ru-02 --preset public-node --host ru-02.blinpi.ru
bpc node create --name home-01 --preset site-router --route 192.168.88.0/24
```

Run the generated installation command as root on Debian 12/13 or Ubuntu 24.04:

```bash
curl -fsSL https://github.com/RomanKrike/bpc/releases/latest/download/install.sh | bash -s -- join 'BPC-...'
```

Bootstrap verifies the release checksum, creates the local identity, enrolls the
Node and configures its assigned capabilities. Public Controller provisioning
resumes interrupted steps and waits for Raft catch-up and voter promotion.
Private site routers need no public endpoint; their routes are advertised through
outbound control connections. Site-router dataplane work remains separate.

Legacy `bpc node token create` and an installed `bpc join` remain supported.

Useful commands:

```bash
bpc status
bpc node info
bpc node list       # on the Controller
bpc leave
```

Join tokens are single-use, expiring and capability-scoped. See
[docs/node-join.md](docs/node-join.md) for the enrollment protocol, filesystem
permissions and replay/duplicate-identity protection. See
[public Node acceptance](docs/public-node-acceptance.md) for validation commands
and the distinction between automated process coverage and VPS acceptance.

## User and Device identity

Stage 3 adds controller-owned User authentication and per-device identity for
BP Connect. User passwords are Argon2id hashes and are never transport keys.
New clients generate their Ed25519 Device private key locally and register only
the public key after password login.

Controller administration:

~~~bash
bpc user add roman
bpc user disable roman
bpc device list
bpc device revoke <DEVICE_ID_OR_UNIQUE_NAME>
~~~

New prepared Windows clients contain no password or enrollment secret. On first
install they prompt for the BPC username/password, register the local Device,
then use 10-minute access credentials plus rotating, device-key-bound refresh
credentials so the password is not required on every connection.

Device revoke also removes the WireGuard peer and WGShim key, so a revoked
Device loses both control-plane authorization and the data-plane path.

See [docs/identity.md](docs/identity.md) for the API, credential lifecycle,
compatibility behavior and future TOTP/Passkey/OIDC extension points.

## Access and routes

Stage 4 adds default-deny Access rules for Users and Devices. The same policy
drives the routes published to BP Connect and the server-side `BPC-ACCESS`
firewall chain on the BPC Node.

~~~bash
bpc access list
bpc access grant --user roman 192.168.88.0/24
bpc access revoke --user other 192.168.88.0/24
~~~

`deny` has deterministic priority over overlapping `allow` rules, and Device
revoke has higher priority than either. Access changes reconcile the Node
firewall without restarting BPC; clients receive the route change on their next
normal config sync.

See [docs/access.md](docs/access.md) for rule semantics, Device overrides,
legacy `managed_routes` compatibility and enforcement details.

## RU node network layout

```text
TCP/443       -> Xray VLESS + REALITY
UDP/443       -> AmneziaWG 2.0
UDP/51820     -> native WireGuard
UDP/24443     -> optional WGShim low-latency WireGuard wrapper
UDP/8443      -> Hysteria2
TCP/8443      -> optional HTTPS Clash subscription
UDP/10443     -> TUIC v5
TCP/10443     -> AnyTLS
TCP/9443      -> Shadowsocks 2022 + ShadowTLS v2
TCP/12443     -> Trojan
TCP/2999      -> Mieru
TCP+UDP/11443 -> TrustTunnel HTTP2/HTTP3
UDP/1194      -> optional OpenVPN fallback (TCP is also supported when selected)
UDP/500+4500  -> optional native IKEv2/IPsec fallback
TCP/22        -> optional SSH rescue (existing OpenSSH service)
TCP/80        -> Let's Encrypt HTTP-01 validation/renewal
```

TCP and UDP are separate namespaces, so Hysteria2 can share numeric port 8443 with the HTTPS subscription and TUIC can share numeric port 10443 with AnyTLS.

The generated aggregate Clash profile uses Mihomo's `fallback` group. The default automatic order prefers censorship-resistant TCP transports before UDP/WireGuard:

```text
VLESS/REALITY -> AnyTLS -> ShadowTLS -> Trojan -> Hysteria2 -> TUIC
              -> Mieru -> TrustTunnel -> AmneziaWG -> WireGuard
```

Only transports that are actually enabled are included. Mihomo continuously health-checks them and selects the first healthy option. There is no `DIRECT` fallback, so if all automatic BPC transports are unavailable the profile fails closed.

OpenVPN and SSH rescue are intentionally not inserted into `BPC-AUTO`. The aggregate profile always exposes `BPC-MANUAL` for forcing one primary transport and `BPC-ROUTE`, which defaults to `BPC-AUTO` and can switch to `BPC-MANUAL` plus any enabled OpenVPN/SSH rescue fallback. IKEv2 is an OS-level transport and never appears in Clash.

## Install and initialize a BPC Node

Install the runtime on a clean Debian/Ubuntu server:

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh | sudo bash
```

Initialize the first Controller explicitly:

```bash
bpc init \
  --name ru-01 \
  --roles controller,gateway,relay \
  --hostname sub.example.com
```

Or join an existing Controller with a one-time token:

```bash
bpc join BPC-<controller-envelope>.<one-time-secret>
```

The historical `--role ru-node` installer remains available for compatibility
with existing deployments, but `ru-node` is not a canonical Node type.

Stage 4.5 migration can also be run explicitly:

```bash
bpc state migrate
```

It inventories links, routes, rules, WireGuard and firewall state before copying
BPC-owned Controller state to the canonical location. It does not intentionally
modify external network objects.

Common commands:

```bash
sudo bpc status
sudo bpc node status
sudo bpc node info
sudo bpc-update
sudo bpc-status
```

Existing transport enablement commands remain available. Their historical
`ru-node/` state directories are compatibility runtime until transport storage
is migrated in a later stage.

See [docs/install-update.md](docs/install-update.md) for the canonical filesystem,
ownership rules, migration backup/report format and rollback behavior.

## Selective underlay routing

BPC can route only the external endpoint of another VPN through the Russian BPC exit while leaving normal Windows traffic direct. This is intended for cases such as a native WireGuard or corporate VPN that is filtered on the direct Georgia -> Russia path.

For example, to carry only a WireGuard endpoint at `176.32.35.91` through BPC:

```bash
sudo bpc-route-target add 176.32.35.91
```

The command stores the endpoint under `/etc/bpc-connect/ru-node/route-targets.txt` and immediately rebuilds the aggregate Clash profile. If the HTTPS subscription is enabled, the existing subscription URL serves the new profile automatically; refresh that profile in Clash Verge Rev and enable TUN mode.

With one or more route targets, BPC renders policy rules equivalent to:

```yaml
rules:
  - IP-CIDR,176.32.35.91/32,BPC-ROUTE,no-resolve
  - MATCH,DIRECT
```

This means the selected VPN endpoint remains fail-closed through BPC, while unrelated traffic exits directly instead of being sent through the Russian VPS. BPC does not require a local Clash `Script.js`, a hand-edited `route-address`, or persistent Windows routes.

Manage targets with:

```bash
sudo bpc-route-target add 176.32.35.91
sudo bpc-route-target list
sudo bpc-route-target remove 176.32.35.91
sudo bpc-route-target clear
```

`clear` restores the normal full-tunnel fail-closed profile where `MATCH` uses `BPC-ROUTE`.

## Self-contained Windows BPC Agent

The Windows Agent uses a per-Device WireGuard peer and WGShim key, embeds Wintun
and userspace WireGuard, runs as a native Windows service, synchronizes
Controller configuration and supports signed updates.

Enable trusted HTTPS and the Controller on the primary Node, then prepare an
installer:

```bash
sudo bpc-agent create pc004
```

On first install BP Connect asks for the BPC User credentials, creates Device
and WireGuard private keys locally and sends only the required public material
and proof-of-possession to the Controller.

Administration uses the canonical Device and Access model:

```bash
sudo bpc-agent list
sudo bpc device list
sudo bpc device revoke pc004
sudo bpc access grant --device pc004 192.168.88.0/24
sudo bpc access revoke --device pc004 192.168.88.0/24
```

The old `bpc-agent routes` and `bpc-agent revoke` write paths are disabled.
Historical Device route/static-token fields remain readable only through the
compatibility layer.

The BPC Agent WireGuard interface is mutated only after BPC ownership is proven;
a pre-existing interface with the same name is not automatically adopted.

## Routed sites and legacy BP Gateway compatibility

Pre-Stage-4.5 releases represented a routed site as a special BP Gateway Device
record. That write model is retired.

The following historical mutation commands are disabled:

```text
bpc-node gateway create
bpc-node gateway grant
bpc-node gateway ungrant
bpc-node gateway remove
```

Existing records can still be inspected:

```bash
sudo bpc-node gateway list
```

The canonical model is a normal BPC Node with the `site_router` capability and
Node-owned `advertised_routes`:

```text
Node(site_router)
        |
        +-- advertised_routes
        |
        v
Controller routing policy
```

Stage 4.5 does not implement the replacement site-router/MikroTik data plane.
Existing BP Gateway installer/upgrade scripts remain compatibility assets for
already deployed gateways, not the basis for new provisioning.

## WGShim low-latency WireGuard wrapper

WGShim is an experimental, latency-oriented BPC transport for carrying an
existing WireGuard UDP endpoint through the RU node without putting the packet
flow through Clash/Mihomo, TCP, DNS policy or the proxy selector stack.

The intended path is:

```text
WireGuard for Windows
  Endpoint = 127.0.0.1:24081
        |
        v
bpc-wgshim-windows-amd64.exe
        |
        | authenticated/encrypted outer UDP
        v
BPC RU node:24443/udp
        |
        | normal UDP
        v
existing WireGuard endpoint
```

Provision the RU node with the existing WireGuard endpoint as the fixed target:

```bash
sudo bpc-enable-wgshim --target 176.32.35.91:24081
sudo bpc-status
```

The command creates a root-only PSK and Windows instructions under
`/etc/bpc-connect/ru-node/wgshim/`, installs `bpc-wgshim.service`, and listens
on UDP/24443 by default. Permit that UDP port in the VPS provider firewall.

On Windows, securely copy `client.key` from the server and download the
matching `bpc-wgshim-windows-amd64.exe` from the BPC GitHub Release. Start it
using the exact command recorded in `client.txt`, then point the normal
WireGuard peer at:

```ini
Endpoint = 127.0.0.1:24081
MTU = 1360
```

The MTU value is a conservative first-test value and can be tuned after the
path is verified. WGShim does not replace or alter WireGuard cryptography.
Instead, each complete WireGuard datagram is placed inside an additional
authenticated encrypted UDP envelope. The outer framing uses independent
directional keys, a fresh random nonce, and configurable random padding. There
is no intentional per-data-packet timing delay because this mode is designed
for RDP/Moonlight and other latency-sensitive traffic.

WGShim does not claim to be undetectable against advanced statistical or active
traffic analysis. Its purpose is to remove the ordinary WireGuard wire format
from the outer path with minimal processing and routing overhead.

BPC 0.8.0 WGShim supports one active client per server instance. It is separate
from `BPC-AUTO` and the Clash subscription; Clash Verge is not required for
WGShim operation.

## Mihomo multi-protocol transport pack

Create or reuse a DNS A record pointing directly to the RU node. The same trusted hostname used by the secure Clash subscription can be reused. Then run:

```bash
sudo bpc-enable-mihomo-transports --hostname sub.example.com
```

BPC pins the official Mihomo v1.19.29 server binary, downloads it from the MetaCubeX GitHub Release, verifies the asset against GitHub's published SHA-256 digest, generates independent random credentials for every listener, validates the complete Mihomo server configuration and starts `bpc-mihomo-transports.service`.

The command creates Hysteria2, TUIC v5, AnyTLS, Shadowsocks 2022 + ShadowTLS v2, Trojan, Mieru and TrustTunnel client fragments under `/etc/bpc-connect/ru-node/<transport>/clash-verge.yaml`. Credentials and profiles are root-only. Re-running the command preserves existing credentials.

Default ports can be overridden during first provisioning with `--hy2-port`, `--tuic-port`, `--anytls-port`, `--shadowtls-port`, `--trojan-port`, `--mieru-port` and `--trust-port`.

The TLS listeners use a trusted Let's Encrypt certificate. If the selected certificate already exists, BPC reuses it. Otherwise TCP/80 must be reachable for the initial HTTP-01 issuance and future renewals.

## OpenVPN fallback

Enable the default UDP/1194 OpenVPN fallback with:

```bash
sudo bpc-enable-openvpn
```

The command creates a private BPC OpenVPN CA, separate server/client certificates, a `tls-crypt` key, a persistent `openvpn-server@bpc.service`, forwarding/NAT rules, a native `/etc/bpc-connect/ru-node/openvpn/client.ovpn` profile and a Mihomo `BPC-RU-OPENVPN-01` profile. All private material remains root-only.

TCP mode is optional:

```bash
sudo BPC_OPENVPN_PROTO=tcp BPC_OPENVPN_PORT=1194 bpc-enable-openvpn
```

BPC disables time-based OpenVPN renegotiation with `reneg-sec 0`. This mitigates the current Mihomo v1.19.29 server-initiated rekey problem documented in [MetaCubeX/mihomo#3085](https://github.com/MetaCubeX/mihomo/issues/3085). OpenVPN therefore remains a manual `BPC-ROUTE` option rather than a default automatic transport until the upstream client behavior is fixed and revalidated.

## Native IKEv2 fallback

Create or reuse a direct DNS A record for the RU node, permit UDP/500 and UDP/4500, then run:

```bash
sudo bpc-enable-ikev2 --hostname sub.example.com
```

BPC installs the `charon-systemd` strongSwan service and an EAP-MSCHAPv2 roadwarrior connection. The server authenticates with the trusted Let's Encrypt certificate for the selected hostname; BPC loads the leaf certificate, intermediate chain and private key separately. A random username/password credential is stored root-only in:

```text
/etc/bpc-connect/ru-node/ikev2/client-info.txt
```

That file contains the Windows built-in VPN fields needed to create an IKEv2 connection. `bpc-status` never prints the password.

IKEv2 is a full-tunnel OS-level fallback, not a Clash proxy. Do not stack it with a corporate VPN unless the corporate VPN client and policy explicitly support that nested arrangement.

## SSH rescue

Enable the manual rescue channel with:

```bash
sudo bpc-enable-ssh-rescue
```

BPC creates a dedicated `bpc-rescue` system account with a generated Ed25519 client key. Password authentication, shell/TTY, X11 and agent forwarding are disabled for the account; TCP forwarding remains enabled. The current SSH host public key is pinned into the generated Mihomo client fragment.

Because SSH does not carry UDP in Mihomo, it is never inserted into `BPC-AUTO`. It is available only through the manual `BPC-ROUTE` selector.

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

Generated client/state files include:

```text
/etc/bpc-connect/ru-node/gateway-transport.yaml
/etc/bpc-connect/ru-node/clash-verge-auto.yaml
/etc/bpc-connect/ru-node/awg/client.conf
/etc/bpc-connect/ru-node/awg/clash-verge.yaml
/etc/bpc-connect/ru-node/wg/client.conf
/etc/bpc-connect/ru-node/wg/clash-verge.yaml
/etc/bpc-connect/ru-node/mihomo-server/config.yaml
/etc/bpc-connect/ru-node/mihomo-server/runtime.env
/etc/bpc-connect/ru-node/hy2/clash-verge.yaml
/etc/bpc-connect/ru-node/tuic/clash-verge.yaml
/etc/bpc-connect/ru-node/anytls/clash-verge.yaml
/etc/bpc-connect/ru-node/shadowtls/clash-verge.yaml
/etc/bpc-connect/ru-node/trojan/clash-verge.yaml
/etc/bpc-connect/ru-node/mieru/clash-verge.yaml
/etc/bpc-connect/ru-node/trusttunnel/clash-verge.yaml
/etc/bpc-connect/ru-node/openvpn/client.ovpn
/etc/bpc-connect/ru-node/openvpn/clash-verge.yaml
/etc/bpc-connect/ru-node/ikev2/client-info.txt
/etc/bpc-connect/ru-node/ssh-rescue/client.key
/etc/bpc-connect/ru-node/ssh-rescue/clash-verge.yaml
/etc/bpc-connect/ru-node/subscription/token
/etc/bpc-connect/ru-node/subscription/runtime.env
```

The aggregate Clash profile, transport profiles, OpenVPN credentials, IKEv2 client credential file, SSH private key and subscription URL contain or grant access to private credentials and must be treated as secrets.

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

- Never commit production UUIDs, private keys, WireGuard PSKs, transport passwords, OpenVPN private material, IKEv2 credentials, SSH rescue keys, Mihomo API secrets, subscription URLs or real infrastructure credentials.
- Treat generated gateway, Xray, AmneziaWG, WireGuard, Mihomo transport, OpenVPN and aggregate Clash configurations as secrets.
- Treat the tokenized subscription URL like a password; anyone holding it can download the client profile and its credentials.
- The work gateway must fail closed: transport failure must not expose the work laptop directly through the Georgia ISP.
- Release checksums detect corrupted or mismatched artifacts; stronger signed-release verification can be added in a later milestone.
