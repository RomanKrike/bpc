# Test plan

## CI

- Parse and validate source configuration.
- Render Mihomo YAML.
- Verify strict TUN routing.
- Verify no DIRECT route exists.
- Verify transport priority order.
- Verify VLESS XUDP and AWG configuration are emitted.
- Lint Python and shell scripts.
- Build wheel/sdist.

## Real-network E2E (next milestone)

- Georgia -> RU VLESS/REALITY TCP/UDP.
- Georgia -> RU AWG.
- Georgia -> RU Tailscale direct.
- Georgia -> RU DERP fallback.
- External IP is Russian.
- DNS leak test.
- MTU discovery and fragmentation checks.
- Long-lived TCP test.
- UDP test.
- Forced transport failure and automatic recovery.
- All transports down -> no direct Internet from work LAN.
- Parovoz and Yarko VPN handshake, DNS, internal services, reconnect and stability.
