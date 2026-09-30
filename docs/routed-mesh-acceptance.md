# Routed mesh acceptance (development)

The mesh draft is not a completed multi-VPS HA release.

## Route authorization and offline policy

Node invitations establish `authorized_routes`. A heartbeat may advertise only
those IPv4 prefixes or their subnets, and cannot provide its own grants. Legacy
Nodes freeze their last canonical advertisements on first heartbeat, including
when they withdraw routes. The Controller administrator can extend the grant:

```bash
bpc node route-authorize NODE_ID --route 192.168.89.0/24
```

The Raft state machine checks route grants alongside owner capability and CIDR
conflicts. Heartbeat updates use a Node-record digest precondition so an older
heartbeat cannot overwrite a concurrent administrator policy change. Default
routes remain rejected; no default-route permission is introduced here.

Routed configs carry a Controller-issued `policy_expires_at`, with 300 seconds
of offline grace. Heartbeats require a strong Controller read, so quorum loss
cannot renew this deadline. The router itself denies ingress, transit and return
data at expiry, independent of the Node daemon. Link probes may continue; they
do not grant forwarding permission. Refresh resumes forwarding with the same
path IDs and mesh sessions. A runtime restart uses the persisted absolute
deadline, never a fresh grace period. Missing or expired leases cannot start the
production routed service: existing development Nodes must complete a heartbeat
before starting the updated runtime. This policy relies on the Node system clock
and its root-owned config received through the authenticated Controller channel.
It covers the new routed mesh; compatibility gateway snapshot policy is separate.

The three-process Controller test now covers replicated route grants, leader
loss, quorum loss (writes and heartbeat renewal denied), quorum restoration and
projection convergence. The router tests cover deadline expiry and renewal.
These are layer-specific tests, not combined live acceptance scenarios E-G.

## Restart and update safeguards

The mesh branch includes `main` 0.20.2's healthy make-before-break migration.
Runtime staging preserves the signed Gateway security snapshot and trust bytes,
including their deadline and revision floor, under a lock shared with snapshot
refresh and verification. Same-version repair and replacement by a new release
therefore do not reset offline grace or permit revision rollback.

Runtime installation now writes a valid newline-terminated `ip_forward` sysctl
file. It compares the running routed service executable with the release binary
through systemd's MainPID and `/proc/PID/exe`. Identical binaries leave the
process running; changed binaries restart the dedicated routed service after
daemon reload. Enrollment and its Controller-issued paths remain unchanged.
A changed-binary restart still requires mesh session reauthentication; combined
traffic interruption and rolling updater scenario H have not been measured on
VPS. The existing peer-restart UDP test is not a TCP rolling-update acceptance.
Healthcheck rejects an expired/missing routed lease even if service, interface
and recent status are present.

After quorum restoration, forwarded mutation acknowledgements now wait for the
receiving follower to apply and reconcile the returned canonical revision.
The process regression checks an immediate read after a follower write and the
subsequent route config, without adding a polling workaround to the caller.

Run the controlled data-path acceptance:

```bash
BPC_ROUTED_MESH_REPORT=/tmp/bpc-routed-mesh.json go test -race ./internal/routed \
  -run TestRoutedDirectToMultiHopPersistentTraffic -count=1 -timeout=60s -v
```

This uses three actual authenticated UDP mesh instances (`ru-01`, `ru-02`,
`home-01`) and userspace IP/TCP stacks. The private Node initiates all links;
Public Nodes have no configured endpoint for it. A UDP fault proxy blocks the
direct `ru-02`/`home-01` link in both directions. The router selects the already
probed `ru-02 -> ru-01 -> home-01` path while the same TCP, small persistent TCP,
UDP and ICMP workloads continue. Recovery must not immediately steal selection.

The Device ingress is injected after WireGuard decapsulation. This test does
not exercise Windows, kernel routes/firewall/NAT, systemd, updater, physical
reboot, enrollment, Device identity or Raft. Overlay source IP is checked using
the still-open TCP socket. Controller-approved routes are fixed test fixtures.

The [initial race-enabled measurement](acceptance/routed-mesh-baseline-localhost.json)
selected multi-hop in 3,862 ms. ICMP lost 32/214 exchanges and UDP lost 193/399
datagrams. Both pre-existing TCP sockets survived, with maximum response gaps
of 6,465 ms for the small exchange and 7,045 ms for the stream. TCP counters are
application messages, not packet-loss or retransmission counters. The four-second
link failure timeout and TCP retransmission timers explain the interruption.
This is not seamless or zero-loss behavior.

The [updated race-enabled measurement](acceptance/routed-mesh-failover-localhost.json)
uses authenticated probes every 250 ms, a 400 ms probe timeout and a one-second
fresh-reply bound, aligning the mesh with the existing fast Device path model.
It selected multi-hop in 857 ms, lost 7/204 ICMP exchanges and 43/261 UDP
datagrams, and kept both TCP sockets open. The maximum UDP gap was 873 ms;
the small TCP exchange gap was 868 ms, while the large TCP stream gap was
4,961 ms. TCP retransmission recovery can outlast path selection substantially.
The regression bound is two seconds for selecting a warm alternative; it is
not a bound on TCP recovery or a production SLA. Recovery hysteresis remains.

Full scenarios A-H are still required on the combined topology: Node outage and
recovery, direct-link failure, Raft leader/quorum loss/restoration and rolling
updates with all traffic probes running. Existing Raft process tests and the
0.20.2 independent-WireGuard tests cover separate layers; they do not substitute
for that combined acceptance. This execution environment denies network
namespace creation and does not expose a kernel TUN or production host access.
