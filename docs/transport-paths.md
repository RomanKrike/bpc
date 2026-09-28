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

Do not copy independently provisioned public Node endpoints into this list and
assume they share a WireGuard session. Independent gateway keys/sessions require
additional overlay work. Node DNS metadata alone does not prove compatibility.

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

Both relays in this test lead to ONE surviving WireGuard destination. The result
does not prove full gateway/Node failure tolerance, NAT continuity, production
latency, systemd restart, reboot, Windows Wintun behavior or distributed Access
acceptance. It is not a seamless-failover claim. These are still outstanding.
