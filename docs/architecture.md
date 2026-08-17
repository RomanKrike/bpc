# BPC Connect v0.1 architecture

## Goal

Provide a fail-closed path from a work LAN in Georgia to a Russian exit so a corporate VPN can run on the work laptop without sharing a routing table with BPC transports.

## Data plane

```text
Work laptop
    |
    | Ethernet/Wi-Fi
    v
GE Gateway (Mihomo TUN)
    |
    +-- VLESS + REALITY ------+
    +-- AmneziaWG ------------+--> RU Exit --> Russian Internet --> corporate VPN endpoint
    +-- Tailscale / DERP -----+
```

The corporate VPN remains installed only on the work laptop. BPC changes the underlay, not the corporate overlay.

## Safety invariant

The work gateway is **fail closed**. There is no `DIRECT` member in `BPC-RUSSIA`, and no direct fallback rule. A separate nftables layer will additionally prevent forwarding from the work LAN to the Georgia WAN outside the controlled tunnel path.

## Milestones

1. Repository, renderer, CI and fail-closed tests.
2. RU VLESS/REALITY node + GE gateway deployment.
3. AWG secondary transport.
4. Tailscale/DERP emergency transport.
5. HOME routes and independent home fallback.
6. Real GE <-> RU E2E tests and corporate VPN validation.
