# BPC Connect architecture

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
    +-- AmneziaWG 2.0 --------+
    +-- WireGuard ------------+--> RU Exit --> Russian Internet --> corporate VPN endpoint
    +-- Tailscale / DERP -----+
```

The corporate VPN remains installed only on the work laptop. BPC changes the underlay, not the corporate overlay.

## RU-node transport isolation

```text
TCP/443    Xray VLESS/REALITY
UDP/443    AmneziaWG 2.0, awg0, 10.251.0.0/24
UDP/51820  native WireGuard, bpcwg0, 10.252.0.0/24
```

The transports use independent protocol stacks, interfaces, credentials and state directories. A failure in one transport must not require deleting or rotating another transport.

## Safety invariant

The work gateway is **fail closed**. There is no `DIRECT` member in `BPC-RUSSIA`, and no direct fallback rule. A separate nftables layer will additionally prevent forwarding from the work LAN to the Georgia WAN outside the controlled tunnel path.

## Milestones

1. Repository, renderer, CI and fail-closed tests.
2. RU VLESS/REALITY node + GE gateway deployment.
3. AWG secondary transport.
4. Native WireGuard control/fallback transport.
5. Tailscale/DERP emergency transport.
6. HOME routes and independent home fallback.
7. Real GE <-> RU E2E tests and corporate VPN validation.
