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
untouched. Cross-node migration keeps Wintun, its address and routes alive.
For a healthy old path the Agent initiates a new WireGuard handshake without
removing the existing peer or ephemeral session. During verification, WGShim
sends encrypted WireGuard data to both responders and sends handshakes only to
the selected new responder. Only the responder with the matching ephemeral key
can accept those data packets; WireGuard replay protection prevents duplicate
application delivery. Return transport data from the new path ends the overlap.
Handshake replies and WGShim probes alone do not end it.

An already-failed old path uses the immediate `replace_peers=true` rehandshake.
There is no working old session to preserve in that case. WireGuard's existing
handshake rate limit remains enforced. If a recent rekey prevents immediate
planned negotiation, the bounded verification timeout can roll selection back;
BPC does not bypass the crypto implementation's rate limits.

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
pool keeps both running. If one configured hostname cannot be resolved at
startup, resolvable paths continue operating and the missing path is reported as
failed. DNS is retried periodically; when it recovers, WGShim rebuilds only the
transport path pool while preserving the current active endpoint as the initial
choice. The recovered Node therefore returns as a standby instead of silently
stealing an established cross-node session. The WireGuard overlay is not
recreated.

Cross-node rehandshake notifications use a one-element latest-value mailbox:
rapid failover/recovery can coalesce obsolete intermediate events, but the newest
selected Public Node is not silently dropped.

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

### Persistent flows through independent gateways

```bash
BPC_ROUTED_PATH_REPORT=/tmp/bpc-routed-report.json go test ./internal/wgshim \
  -run TestIndependentNodesPreserveRoutedTCP -count=1 -v
```

This test stops both the active relay and its independent WireGuard responder.
Both gateways reach one surviving destination TCP/IP stack outside either Node.
The test LAN returns packets through the most recent ingress gateway; this is an
explicit routing assumption, not a production route-convergence measurement.
No NAT or WireGuard ephemeral state is copied between gateways.

[Recorded measurement](acceptance/independent-routed-failover-localhost.json):
selection changed in 649 ms; 6 ICMP exchanges and 33 UDP datagrams were lost.
Both pre-existing TCP sockets survived without reconnecting: the stream had a
maximum 3,632 ms response gap and the RDP-like exchange an 855 ms gap. The largest
UDP response gap was 681 ms. These are single-run localhost observations, not
latency guarantees. TCP counts represent application messages, not packet loss.
The overlay address and WireGuard profile remained unchanged. Separate
Controller-side acceptance now changes Public Node availability while asserting
that the controller-issued Device record, Access record, overlay address,
canonical peer key and Access-derived AllowedIPs remain unchanged. Together the
tests cover the transport handoff and the control-plane identity invariants,
while real VPS timing remains an operational measurement.

### Healthy make-before-break acceptance

```bash
BPC_MIGRATION_REPORT=/tmp/bpc-migration-report.json go test -race ./internal/wgshim \
  -run TestIndependentNodesMakeBeforeBreak -count=1 -v
```

Two independent gateway responders reach a shared routed application stack.
The test raises the old path's authenticated probe RTT while leaving its data
path working, then delays the new responder's handshake reply by 800 ms.
The existing peer must remain intact, the new responder must confirm transport
data, and the UDP response gap must stay below 600 ms during negotiation. Existing
TCP sockets are never reopened. This specifically tests overlap, unlike an
emergency failure test where the old gateway is already unavailable.

[Recorded race-enabled measurement](acceptance/healthy-migration-localhost.json):
no lost ICMP exchanges or UDP datagrams; both existing TCP sockets survived.
The largest UDP response gap was 204 ms and the TCP stream gap 206 ms. Selection
waited 5.42 seconds, including the configured five-second stability interval;
that is a decision delay, not an application outage. This is a localhost test
with an injected handshake delay, not a claim of zero-loss VPS migration.

### Real Windows / Public Node measurement

The repository includes `scripts/acceptance-public-node-failover.ps1`. On an
installed Windows Agent it samples live transport telemetry and ICMP while an
active Public Node relay is stopped over SSH. The relay is restored automatically
unless `-NoRestore` is supplied.

Example:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acceptance-public-node-failover.ps1 `
  -FaultSshHost ru-01.example `
  -FaultSshUser root `
  -Target 10.253.0.1 `
  -ReportPath .\bpc-public-node-failover.json
```

The JSON report records the selected Node/endpoint timeline, switch delay,
success/failure counts, the largest gap between successful pings and overlay
address/routes before and after the handoff. The default acceptance bound is
1500 ms. A routed LAN address can be used as `-Target` to measure application
reachability beyond the overlay responder itself.

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
gateway failure. Production multi-VPS and Windows Wintun measurements are still
operational acceptance rather than CI guarantees; this is not a zero-loss claim.

## Restart, update and reboot regression

A Public Node reboot recreates the BPC WireGuard kernel interface. Dynamic peer
endpoints are therefore kernel state and cannot literally survive a host reboot.
The Node runtime now reconciles replicated Device peers and Access state
immediately after starting its transport roles and before the first remote
heartbeat. This removes Controller availability from the reboot recovery path;
continuous client traffic can then relearn the peer endpoint through the restored
peer.

Routine dataplane reconciliation and update keep an already-live BPC-owned
WireGuard interface in place. They update the interface private key, listen port,
MTU/address when necessary and do not restart `wg-quick` or remove peers on the
live path. Restarting only `bpc-control.service` or
`bpc-agent-relay.service` likewise does not recreate the WireGuard interface.

Use the root-only operational harness on a Public Node:

```bash
sudo ./scripts/acceptance-node-restart-regression.sh control
sudo ./scripts/acceptance-node-restart-regression.sh transport
sudo ./scripts/acceptance-node-restart-regression.sh update
```

Each stage snapshots canonical Node identity, overlay identity, Device
identity/address material, Access, routes, WireGuard peer set, AllowedIPs and
learned endpoint presence before and after the action. A JSON report is written
to `/tmp/bpc-restart-regression.json` by default.

A real reboot is intentionally two-phase:

```bash
sudo ./scripts/acceptance-node-restart-regression.sh prepare-reboot
sudo reboot
# keep continuous client/BPC traffic running while the Node comes back
sudo ./scripts/acceptance-node-restart-regression.sh verify-reboot
```

The reboot verifier waits for the BPC WireGuard/Node/relay services, gives the
startup local reconcile a bounded window to restore peers, and then checks the
same identity/policy invariants. Endpoint presence after reboot assumes client
traffic is active so WireGuard has a packet from which to relearn the remote
endpoint.
