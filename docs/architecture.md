# BPC Connect architecture

## Canonical server model

BPC server infrastructure is one **Node**. Controller, gateway, relay and
site-router are capabilities of the same Node, not separate node types.

```text
Node
├── controller
├── gateway
├── relay
└── site_router
```

A machine can expose any combination of capabilities. The current primary RU
deployment is expected to be:

```text
ru-01 = controller + gateway + relay
```

The canonical Node metadata is `/etc/bpc-connect/node.yaml`. Capability checks
are centralized in `bpc_connect.node.Capabilities`; core code must not branch
on historical install profiles or Device record roles.

Schema version 1 includes transport-independent identity plus Node-owned route
advertisement:

```yaml
version: 1

node:
  id: 7e41a8b74a2a4e82a3f7f48353de9a01
  name: ru-01
  public_key: ""
  created_at: 0
  last_seen: 0

roles:
  controller: true
  gateway: true
  relay: true
  site_router: false

advertised_routes: []

endpoints:
  - host: ru-01.blinpi.ru
    public: true
    enabled: true
```

Endpoints are optional Node metadata, carried in canonical `control/nodes/`
records and replicated by the existing Raft state machine. An empty list is
valid for private Nodes. Endpoint metadata does not modify transport listeners,
routes or firewall rules. Enrollment assigns endpoints; heartbeats cannot
replace Controller-assigned endpoints with client-supplied values.

`public_key` is the Node identity key, not an Xray, WireGuard, WGShim or
Device key.

## Canonical state layout

Stage 4.5 makes the state layout explicit:

```text
/etc/bpc-connect/
├── node.yaml
├── identity/
├── cluster/
├── control/
├── runtime/
├── transports/
├── compat/
└── backups/
```

New core code resolves these paths through `bpc_connect.state.StateLayout`.
In particular, Controller state is canonical at
`/etc/bpc-connect/control/`.

Existing transport implementations are not rewritten in Stage 4.5. Historical
transport state under `/etc/bpc-connect/ru-node/` can remain in place while
those transports are bridged through `bpc_connect.compat.runtime`. New domain
state must not be created there.

## Compatibility boundary

Historical vocabulary is isolated under `bpc_connect.compat`.

It currently contains adapters for:

- legacy `BPC_ROLE=ru-node` capability inference;
- historical `ru-node/` transport/runtime locations;
- pre-Stage-3 static Device credentials;
- pre-Stage-4 Device `managed_routes`;
- legacy Device `legacy_tunnel` hints;
- old BP Gateway Device records with `role: gateway` and
  `advertised_routes`.

Core Controller, Node, Access and CLI code call compatibility adapters rather
than reading those fields directly.

Compatibility is intentionally asymmetric:

```text
legacy state -> read/import adapter -> canonical model

canonical model -X-> new legacy writes
```

The old commands that created or mutated BP Gateway Device records are disabled.
`bpc-node gateway list` remains read-only so existing records can be inspected.

## First Controller initialization

A clean installation installs the BPC runtime without assigning a historical
node type. The first cluster Controller is initialized explicitly:

```bash
bpc init \
  --name ru-01 \
  --roles controller,gateway,relay \
  --hostname sub.example.com
```

`bpc init`:

1. verifies that trusted Controller TLS can be provisioned or reused;
2. runs the Stage 4.5 canonical migration;
3. creates/reconciles `node.yaml`;
4. creates the Node Ed25519 identity if needed;
5. creates `cluster/cluster.json`;
6. reconciles the requested transport capabilities through the compatibility
   runtime adapter;
7. starts/reconciles the canonical Controller state and service.

The operation is idempotent for an already initialized state directory.

## Node Join

Additional Nodes join an existing Controller through the Stage 2 one-time join
flow:

```bash
bpc node token create --roles gateway,relay --name ge-02 --expires 15m
bpc join BPC-<controller-envelope>.<one-time-secret>
```

Node Join is separate from BP Connect User/Device enrollment. A joined Node
creates its private Ed25519 identity locally and sends only the public key. The
Controller assigns the Node ID, credential and capabilities, and the Node
reports periodic authenticated heartbeats.

Controller-owned Node enrollment records live below the canonical
`/etc/bpc-connect/control/` tree.

## User, Device and Access model

Stage 3 introduced User and Device identity. Stage 4 introduced Access.

```text
User
 └── Device
      └── Access allow/deny CIDR
```

New Devices do not receive historical `managed_routes`, `legacy_tunnel` or
static `device_token` fields. Old records remain readable only through the
compatibility layer.

Client AllowedIPs are an interface/UX mechanism. The server-side
`BPC-ACCESS` firewall chain is the security boundary.

## Site routing

A routed site is represented by a Node with the `site_router` capability.
Route advertisement belongs to Node state through `advertised_routes`.

Stage 4.5 deliberately does **not** implement the new site-router data plane or
MikroTik integration. Existing BP Gateway runtime scripts remain only as
compatibility assets for installations created before the canonical model.

Future site-router work should build on:

```text
Node(site_router)
        |
        +-- advertised_routes
        |
        v
Controller routing policy
```

and must not reintroduce a separate Gateway entity.

## Network ownership and mutation safety

Stage 4.5 introduces an explicit ownership rule for network mutation:

```text
OWNED_BY_BPC -> may reconcile
LEGACY_BPC   -> may adopt/reconcile after evidence
EXTERNAL     -> never mutate
UNKNOWN      -> fail closed
```

BPC Agent WireGuard provisioning writes ownership metadata next to the BPC
Agent runtime. Controller peer mutation and Access firewall reconciliation
require that evidence before changing the interface.

An existing interface or `/etc/wireguard/*.conf` with the expected name is
**not** sufficient proof of BPC ownership.

The migration itself never changes interfaces, routes, policy rules, WireGuard
peers or firewall state. Before copying BPC state it snapshots:

- `ip -details link`;
- all route tables;
- policy rules;
- redacted `wg show all dump`;
- `iptables-save`;
- `nft list ruleset`;
- systemd units.

The report explicitly lists detected external WireGuard interfaces and records
`External objects modified: NONE`.

## Stage 4.5 migration

`bpc state migrate` copies BPC-owned Controller state from the historical
location to the canonical location without deleting the source.

Before activation it creates:

```text
/etc/bpc-connect/backups/pre-4.5-<timestamp>/
├── inventory/
└── legacy-control/
```

The legacy source, backup copy and staged canonical copy are hashed and compared.
If state changes during the copy, or a different canonical Controller tree
already exists, migration stops rather than choosing one side.

A successful migration writes:

```text
/etc/bpc-connect/control/.bpc-state.json
/etc/bpc-connect/compat/stage-4.5.json
```

The marker makes subsequent runs idempotent.

## Data plane

Stage 4.5 is an architecture cleanup, not a transport rewrite. Existing
transports remain independent:

```text
BP Connect / VPN client
        |
        +-- VLESS + REALITY
        +-- AmneziaWG
        +-- native WireGuard
        +-- WGShim
        +-- Mihomo transports
        +-- OpenVPN / IKEv2 / SSH fallback
        |
        v
BPC Node gateway / relay
```

Transport credentials remain outside `node.yaml` and are not regenerated by
canonical migration.

## Invariants

- One server-side entity: Node.
- Capabilities are composable; they are not node types.
- User, Device, Node and Access identities remain distinct.
- New core state uses canonical paths.
- Legacy schema knowledge stays inside compatibility adapters.
- Unknown or external network objects are not mutated.
- Migration is backup-first and idempotent.
- Existing transport cryptography and packet formats are unchanged.
- The work underlay remains fail closed.
