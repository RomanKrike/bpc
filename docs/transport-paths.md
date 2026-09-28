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
pool keeps both running.

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

Both relays in this test lead to ONE surviving WireGuard destination. Public
Nodes can now materialize the same Device peers/WGShim keys and share the
canonical WireGuard static identity, but WireGuard ephemeral session state and
Linux conntrack/NAT state are not replicated between Nodes. Therefore an
independent gateway failover may still require an inner WireGuard re-handshake
and may not preserve NAT-backed TCP sessions. Production multi-VPS acceptance,
systemd restart, reboot and Windows Wintun measurements are still outstanding;
this is not yet a zero-loss failover claim.
