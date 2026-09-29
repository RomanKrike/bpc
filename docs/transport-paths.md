# Transport paths (development)

Runtime `paths` describe routes to an overlay peer; they are not a new domain
entity. `wgshim_server` and `wgshim_servers` remain supported. Explicit paths
currently require the same WireGuard peer as the existing profile:

```json
{"paths": [
  {"node": "ru-01", "endpoint": "ru-01.example:24444"},
  {"node": "ru-02", "endpoint": "ru-02.example:24444"}
]}
```

Public Nodes now adopt one canonical cluster overlay WireGuard identity. A Node
is eligible for automatic path discovery only when an authenticated heartbeat
reports an active relay and the same overlay public key. The endpoint hostname
still comes from the controller-issued Node invitation; heartbeat data supplies
the actual local UDP port pool. Node DNS metadata alone is not treated as proof
of overlay compatibility.

Device identity, overlay address, Access policy and routed resources remain
controller state and do not change when the selected transport path changes.
The canonical overlay private key is replicated only in controller state and is
never returned in Device runtime configuration.

A UDP-port switch inside one Public Node leaves the embedded WireGuard peer
untouched. A switch between different Public Nodes keeps the Wintun interface,
overlay address and routes alive, but reapplies the peer with
`replace_peers=true` so wireguard-go discards the responder-specific ephemeral
session state and can immediately establish a fresh handshake through the newly
selected Node.

WGShim uses the existing authenticated probe wire format. Internal transport
status includes each path's reachability, smoothed RTT and jitter, rolling probe
loss (32 samples), last success, cumulative failures and ACTIVE/STANDBY state.
The default selector requires an improvement of 10 ms in the Agent, five seconds
of stability, penalizes recent failures and applies a ten-second recovery
cooldown. Two fully failed rounds mark a path unreachable for health telemetry.
If the active path loses one complete authenticated probe round while an already
warm standby remains healthy, traffic moves to that standby immediately after
the failed round. Standby probes run before failure.

A selected new path is VERIFYING until return data arrives. If traffic was sent
but no return data arrives within two seconds, a reachable previous path is
restored. Idle tunnels do not trigger this rollback. Probes alone do not confirm
that the overlay destination is usable. Old endpoints remain available as
standbys; changing selection does not recreate the overlay interface.

The Agent supervises transport and overlay separately. Controller metadata does
not restart either. Changing the configured path pool currently restarts the
transport listener, while preserving the overlay. Switching within an existing
pool keeps both running. Cross-node rehandshake notifications use a one-element
latest-value mailbox: rapid failover/recovery can coalesce obsolete intermediate
events, but the newest selected Public Node is not silently dropped.

Replicated Device and Access state is applied to gateway dataplanes both during
Node heartbeat and through a local systemd path watcher. Changes under
`control/devices`, `control/access` or `control/config.json` therefore do not
wait for the normal heartbeat interval before the standby Node updates its
WireGuard peers, WGShim keys and Access firewall. The BPC Node systemd sandbox
explicitly permits AF_NETLINK with CAP_NET_ADMIN for these local reconciliations.

## Independent Public Node acceptance

`TestIndependentPublicNodeFailover` uses two independent userspace WireGuard
responders. They share the same canonical static overlay identity and Device peer
material, but they do not share ephemeral WireGuard session state. Each responder
sits behind its own WGShim relay.

The test warms both authenticated paths, establishes traffic through the first
responder, stops that Public Node path, then performs the same cross-node
`replace_peers=true` rehandshake used by the Windows Agent. CI requires the path
switch to occur within 1.5 seconds. It verifies that the client overlay identity
and AllowedIPs are unchanged, an already-open UDP application socket continues
through the second responder, and a new TCP connection succeeds after the
handoff.

This proves independent responder handoff in the userspace acceptance topology.
It does not prove preservation of an already-established TCP flow whose remote
endpoint or NAT/conntrack state lives on the failed VPS. BPC does not currently
replicate Linux conntrack/NAT state between Public Nodes.

## Measured relay-path acceptance

Run:

```bash
BPC_PATH_REPORT=/tmp/bpc-path-report.json go test ./internal/wgshim \
  -run TestWireGuardPathFailoverTraffic -count=1 -v
```

The test uses actual userspace WireGuard, two WGShim UDP relays and a userspace
IP stack. It simultaneously runs ICMP, UDP, a TCP stream and a persistent small
TCP exchange, then stops the active relay. The test socket bind uses ordinary
localhost UDP without privileged platform offload options. It is test-only.

[Recorded measurement](acceptance/relay-failover-localhost.json) contains the
observed switch delay, traffic gaps and loss. TCP counts are application messages,
not TCP packets or retransmissions. Ping uses independent ICMP exchanges with a
100 ms timeout; UDP sends every 20 ms. A dependency's PingConn readiness behavior
requires isolated exchanges to avoid an unread queue suppressing notifications.

Both relays in this older measurement lead to ONE surviving WireGuard
destination; use the independent Public Node acceptance above for the
two-responder case. Linux conntrack/NAT state is still not replicated between
Nodes, so flows that depend on gateway-local state may not survive an independent
gateway failure. Production multi-VPS acceptance, systemd restart, reboot and
Windows Wintun measurements are still outstanding; this is not yet a zero-loss
failover claim.
