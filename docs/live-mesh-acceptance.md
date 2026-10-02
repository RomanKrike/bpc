# Combined live mesh acceptance A–H

Status: prepared; no live scenarios executed. Local probe tests validate the
collector only. This document does not mark the mesh release accepted.

## Required test topology and access

Use two Public Nodes, one private site-router with outbound uplinks to both,
a LAN echo host behind that router, and a connected Windows Device. Leader/quorum
scenarios additionally require three reachable Controller voters; they may be
roles on these Nodes or separate test Nodes. Confirm actual membership before
choosing which services to stop. Two voters cannot retain quorum after one loss.

Provide SSH destinations/ports for the Linux Nodes, provisioned key authentication
and verified host keys, and a Windows runner name/labels or remote session with
administrative access. Keep management reachable independently of the BPC paths
being faulted. Use designated test Nodes and preserve the legacy home WireGuard
link. Do not provide private key contents or passwords in chat.

Deploy the candidate mesh commit containing PR #74 to the test Nodes/Device;
the stable `latest` release does not include this development branch. Record the
exact source SHA and binary SHA256 on every host. Perform the documented Raft
migration first if the test cluster uses legacy DBs. Preserve existing identities,
Access, routes, Gateway snapshots and unmanaged networking.

## Traffic collector

Run the echo server on a dedicated LAN host behind the private router:

```sh
python3 scripts/acceptance-echo.py --listen LAN_HOST_IP --port 19090
```

On Windows, with Python 3.11+ and the already-connected BPC Agent:

```powershell
python scripts/acceptance-mesh-traffic.py --target LAN_HOST_IP --scenario D `
  --duration 90 --agent "$env:ProgramData\BPC\bpc-agent.exe" `
  --report .\evidence\D-traffic.json
```

The collector opens two TCP sockets once (64-byte request/reply and 64 KiB
stream chunks), verifies exact echoed bytes and retains partial responses through
timeouts. It never reconnects a broken TCP session. UDP uses a nonce/sequence to
distinguish loss and late replies. ICMP runs concurrently. Every response/failure
has a monotonic offset; maximum success gaps include initial and final outages.
Record Device/overlay/routes and selected transport endpoint throughout the run.
Reports contain an explicit safe projection of Agent status, not credentials.

Start all workloads and establish a healthy baseline before applying the fault.
Keep them running through recovery; provide UTC fault-start/restored timestamps
from the management host. `measurement_complete` means the collector obtained
evidence, **not** scenario acceptance. Every report remains `unreviewed` with
`live_mesh_passed: false` until topology, faults and policy evidence are assessed.

## Scenario matrix

| ID | Controlled event | Required combined evidence |
| --- | --- | --- |
| A | Healthy topology baseline | Windows tunnel and kernel routes, all authorized LAN traffic, healthy multi-uplinks and actual Raft membership |
| B | Stop selected Public Node's BPC dataplane | Alternate Public Node selected; same Device/overlay/routes and both TCP sockets; ICMP/UDP loss and TCP interruption measured |
| C | Restore that dataplane | Uplinks recover; recovery hysteresis holds; persistent traffic and identities remain intact |
| D | Block only one direct routed uplink | Actual bounded multi-hop path via the other Public Node, no loop, private Node remains outbound-only; continuous traffic measurements |
| E | Stop current Raft Leader service | New Leader with quorum; authorized traffic continues; canonical write/heartbeat renewal succeeds via surviving quorum |
| F | Remove Raft quorum | Writes/lease renewal fail; data permitted only until the original absolute 300-second deadline, then denied in ingress/transit/return; no grace reset |
| G | Restore quorum | Revision/state convergence, fresh authorized lease and traffic recovery; revoked/unauthorized route remains denied |
| H | Rolling Node update and restart/reboot | Pinned candidate binaries; unchanged identity/Access/routes and accepted Gateway floor/deadline; session interruption measured under continuous traffic |

For F, measure past the actual lease expiry (normally at least 420 seconds),
not a short ping run. An established TCP socket may stall or close after policy
expires; rejection is expected. Record that separately from B/D session survival.
For H, install a genuinely changed candidate routed binary: same-version repair
alone does not test executable replacement. Include actual systemd restart and
two-phase physical reboot where required; loss caused by updating the destination
echo host is not a mesh failover measurement.

## Evidence and restoration

For each scenario retain traffic JSON, exact fault/restoration timestamps and
command exit statuses, before/during/after `bpc paths list`, `bpc route explain`,
`bpc cluster status`, Node/runtime status, and selected journal messages. Capture
Windows tunnel/routes and Linux kernel routes/firewall state without private
keys or bearer credentials. Verify authorized and forbidden CIDRs with actual
packets. A layer-specific unit/process test cannot mark this matrix passed.

Check and restore faulted BPC services/rules after each scenario, even if a probe
fails. Block only the chosen routed link using its observed address/port and a
dedicated reversible rule; do not drop all traffic to a host or the legacy WG
interface. Decide exact commands from the actual inventory, never guessed ports.
Require all services, canonical revisions/policies and ownership to converge
before advancing. Keep `main` and production release blocked until this report
has real results for A–H.
