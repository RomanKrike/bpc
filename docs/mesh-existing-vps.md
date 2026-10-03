# Mesh provisioning on an existing VPS

Live A–H acceptance remains pending. `r1090563` uses `ru-01.blinpi.ru`;
the existing Controller API on `r1259489` remains `sub.blinpi.ru`.
Two Controller voters require both Nodes for quorum. A third voter is needed
before testing Controller availability with a complete VPS outage.

## Candidate update

Take `bpc cluster backup` on the healthy leader. Keep private backups of the
local configuration/identity and the original bundle/checksum. Update one
Controller at a time and check cluster health between updates. Do not downgrade
to a pre-watermark Controller or restore old policy state.

Migration reconciles the existing Raft unit against the new release, preserving
its host, ports, Node identity, certificates, CA and local API authorization.
It never passes `--bootstrap`. An enrolled Controller also receives a freshly
staged public API replica. Primary Agent auto-update publication remains pinned
to the existing stable channel while testing candidates.

The API installers now stage `bpc_topology.py`, perform a strong Raft read before
replica configuration checks, and grant telemetry write access. Mutable
telemetry lives at `/etc/bpc-connect/runtime-topology`, outside versioned Node
runtime symlinks. Fresh heartbeats repopulate it. Only byte-for-byte matches of
the two temporary mesh-test-2 repair drop-ins are removed; other drop-ins stay.

## Controller timing on public VPS Nodes

The Controller executable defaults to a WAN timing profile:
`--raft-heartbeat-timeout=3s`, `--raft-election-timeout=3s`,
`--raft-leader-lease-timeout=2s`. The follower timeout also determines Raft's
heartbeat send interval (randomized between roughly 300 and 600 ms).
The previous upstream defaults were 1s, 1s and 500ms respectively.

These settings tolerate brief delayed TCP acknowledgements but increase failure
detection time to several seconds. They do not change voting, write quorum,
strong-read barriers, persistent storage or fsync. Two voters still require both
Controllers. Actual WAN stability and A–H acceptance remain unverified.

All three duration flags must be positive, election timeout must be at least
heartbeat timeout, and leader lease must not exceed heartbeat timeout. Invalid
settings are rejected before opening the persistent Raft database. Set the same
profile on every Controller. Generated service units use the executable defaults;
custom command-line overrides must be maintained separately when regenerating
a unit. Library callers which omit timing settings retain upstream defaults.

After updating each Controller, verify the executable matches the release and
inspect `journalctl -u bpc-controld.service -n 80 --no-pager -o cat` for
`raft timing heartbeat=3s election=3s leader_lease=2s`. Observe term, leader,
replication and file descriptors under normal load for at least 15 minutes.
A short healthy sample is not proof of stability. Only test Controller loss
with a three-voter quorum; complete loss of either of two voters prevents writes.

## Promote the enrolled second Controller

Run on a healthy Controller with the new candidate installed:

```bash
bpc node configure 1474d3c36d4744cb8f3ee0412e1b04aa \
  --preset public-node --host ru-01.blinpi.ru --dataplane routed
```

The operation retains Node ID, key, name, credential indexes and Controller
membership. It uses an expected-digest Raft mutation; a concurrent Node change
causes a conflict rather than an overwrite. Revoked Nodes, non-Controllers and
existing compatibility Gateways cannot use this promotion path.

`routed` means the existing `bpc-routed-node` mesh service provides Gateway/Relay
functions. It does not bootstrap Xray, create an Agent WireGuard interface, apply
global compatibility WireGuard peers/firewall, or advertise legacy Agent ports.
Gateway signed security snapshots are still required and verified. Snapshot
expiry stops the routed service, never an unrelated Xray service. Routing policy
leases remain enforced by the Go dataplane.

Allow inbound **UDP/24446** for the mesh listener on Public Nodes. Private Nodes
dial Public Nodes outward; they do not require public DNS or inbound forwarding.
The first successful heartbeat installs the routing policy and starts the
service once links exist. Check `bpc status`, `bpc path list`, the routed service
journal and `/run/bpc-connect/routed-status.json`. A Node without links reports
that it is waiting for topology, not that mesh traffic is connected.

For a future clean VPS, an invitation can explicitly select the same mode:

```bash
bpc node create --name NAME --preset public-node --host PUBLIC_DNS \
  --dataplane routed
```

The default remains `compat` for existing workflows.

## Remaining live topology work

Promotion prepares a mesh Node; it does not establish two client ingress paths.
The bootstrap Controller must also have a canonical public Node record/runtime,
and the private site router needs reviewed route ownership/Access. Do not
advertise the home LAN until existing kernel routes have been inspected: the
routed runtime adds routes exclusively and will refuse a conflicting unmanaged
route rather than replace it. A route conflict needs a reviewed coexistence or
migration plan, not removal of the working legacy WireGuard link.

The Windows Device must receive the tested candidate and valid transport paths.
Its old 0.16.2 client and a successful legacy ping do not prove Public Node
failover. Complete the combined [A–H procedure](live-mesh-acceptance.md) before
merging the mesh feature into `main` or publishing a stable release.
