# Routed mesh acceptance (development)

The mesh draft is not a completed multi-VPS HA release.

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
