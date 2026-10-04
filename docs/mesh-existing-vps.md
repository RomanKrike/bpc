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
advertise the home LAN until existing kernel routes have been inspected and both
Public Nodes run the isolated routing candidate described below. The private
Site Router still installs its BPC overlay return route exclusively in the main
table and refuses a conflicting route. Preserve the working legacy WireGuard link.

The Windows Device must receive the tested candidate and valid transport paths.
Its old 0.16.2 client and a successful legacy ping do not prove Public Node
failover. Complete the combined [A–H procedure](live-mesh-acceptance.md) before
merging the mesh feature into `main` or publishing a stable release.

### Add the existing bootstrap Controller to mesh alongside Agent

The original Controller created by `bpc init` has a local identity and Raft membership,
but older releases did not create an enrolled Node record for it. Do not run `join`
or `init` again, and do not promote it with `node configure`.

After installing a pinned candidate containing this command, on the bootstrap VPS:

```bash
bpc cluster backup
bpc node mesh-enable --host sub.blinpi.ru --preserve-compat
```

The command requires root, the local canonical state directory, the existing
bootstrap Controller identity and voter record, all three existing public roles,
and `CONTROL_MODE=primary`. The host must include the existing API hostname.
It derives the public key from the existing private key without rewriting either.
It adds the Node and hashed credential/key indexes in one guarded Raft mutation.
It neither adds a voter nor provisions certificates, restarts the API, replaces
Agent interfaces, or authorizes LAN routes. The existing Node name is retained.

A private, fsync-backed registration journal is persisted **before** the Raft
mutation. If a response or local enrollment write is interrupted, rerun the same
command. It reuses the credential and checks the canonical records; revoked or
conflicting registrations are refused. Never paste this journal or enrollment.json:
they contain a credential. The API stays primary on subsequent updates, and its
compatibility Gateway reconciliation remains active alongside routed mesh.
If the primary mode/identity is inconsistent, the update refuses API conversion.

Permit mesh UDP/24446 at the host/provider firewall as needed. Home connections
remain outbound. Confirm fresh, healthy links in `/run/bpc-connect/routed-status.json`
using only node_id, interface, updated_at and the link peer_name/health/rtt_ms/
loss_percent/endpoint fields. Home should then have two public peers, while each
public node also has its inter-public link. Recheck Windows pings to 10.253.0.1 and
192.168.88.180. Healthy probe links do not establish LAN traffic authorization or
Device ingress failover: those remain separate live acceptance steps.

## Isolated Public Node LAN routing

Public Nodes install owned mesh LAN routes in table **12530**, protocol 99.
Only packets explicitly carrying mark **0x425043** use this table, through rule
priority **120**. Ordinary traffic keeps the main table, including existing
`wg0`, `bpgw0` and `bpcag0` routes. The mesh NAT exception additionally requires
output interface `bpcrt0`, so it does not bypass legacy Agent masquerading.

An unreachable default in table 12530 prevents marked packets from falling
through to a legacy route after a mesh LAN route is withdrawn. An occupied
table, reserved rule priority, or overlapping existing mark rule causes startup
to refuse adoption. After an unclean shutdown, retained policy objects require
inspection; the runtime does not delete unknown objects to recover automatically.
Reserve the packet mark exclusively for BPC; do not assign it in other firewall
rules. A clean shutdown removes only the policy objects created by this process.

This stage does not mark Device traffic or grant Device Access. Table 12530
being present and mesh probes being healthy therefore do not demonstrate LAN
access through mesh. Route ownership, Access and an explicit Device ingress
bridge must be configured and tested separately. The Site Router's existing
BPC-owned overlay return route stays in the main table; public LAN isolation
alone does not change it. The privileged CI test verifies marked/unmarked route
selection, withdrawal blocking and preservation of legacy routes/rules in a
network namespace. Live forwarding and failover remain acceptance work.
