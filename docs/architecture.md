# BPC Connect architecture

## Stage 1: unified BPC Node

BPC server infrastructure is modeled as one **Node**. Controller, gateway, relay
and site-router are capabilities of that Node, not mutually exclusive node
types.

```text
Node
├── controller
├── gateway
├── relay
└── site-router
```

A single machine can therefore expose any combination of capabilities. The
current RU deployment is expected to converge on:

```text
ru-01 = controller + gateway + relay
```

Stage 1 intentionally does **not** redesign transports, introduce users,
distributed storage, PostgreSQL/etcd/Kubernetes, or implement MikroTik/site
routing. Existing transport services and client APIs remain the data plane.

## Node identity and versioned configuration

The canonical local metadata file is:

```text
/etc/bpc-connect/node.yaml
```

Schema version 1:

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
```

The Node model contains the stable Node id/name, identity public-key slot,
creation/last-seen timestamps and a capability map.

Capability checks are centralized in `bpc_connect.node.Capabilities`.
Callers use `has(...)` / `Node.has_capability(...)` rather than introducing
new scattered node-type comparisons. The map accepts valid future capability
names in addition to the four core capabilities so the schema can grow without
turning every capability into another node type.

The `public_key` field is deliberately independent from Xray, WireGuard,
WGShim and Agent keys. Stage 1 does not rotate transport credentials or invent
a second identity by reusing a transport key. Existing installations therefore
migrate with an empty identity public-key slot until transport-independent Node
identity provisioning is implemented in a later stage.

## Capability semantics in the current implementation

| Capability | Stage 1 meaning |
| --- | --- |
| `controller` | The local BPC Agent control-plane service is enabled. |
| `gateway` | The node provides the existing RU egress/gateway function. |
| `relay` | The node runs a BPC relay path such as the Agent multi-client relay or WGShim relay. |
| `site_router` | Reserved/modelled for a future site-router implementation; no MikroTik/site-routing work is part of Stage 1. |

A capability is metadata describing what a Node is allowed/configured to do.
The existing service-specific state remains authoritative for transport
credentials and runtime parameters in Stage 1.

## Migration and backward compatibility

Older releases use `/etc/bpc-connect/install.env` with
`BPC_ROLE=ru-node` and service state below `/etc/bpc-connect/ru-node/`.
That value is now treated as a **legacy install profile**, not as the Node's
type.

The migration helper creates `node.yaml` idempotently and infers only
capabilities that are already evidenced by legacy state:

| Existing state | Capability inferred |
| --- | --- |
| RU-node config/client state or `BPC_ROLE=ru-node` | `gateway` |
| `ru-node/control/enabled` | `controller` |
| `ru-node/agent/enabled` | `relay` |
| `ru-node/wgshim/enabled` | `relay` |

Migration is additive. It never removes an explicitly configured capability,
including future extension capabilities. It does not regenerate credentials,
move transport state or alter client configuration.

Existing standalone commands remain valid. The unified command namespace adds:

```bash
sudo bpc node status
sudo bpc node info
```

The legacy `bpc-node gateway ...` commands also remain available. Their
`role: "gateway"` field currently belongs to BP Gateway **device records** in
the Agent control-plane store; it is not the server Node classification. This
legacy device-record vocabulary is retained in Stage 1 to avoid breaking
existing clients and route provisioning.

## Control plane and data plane

The unified Node model is an orchestration/metadata layer above the existing
runtime. Stage 1 keeps transport implementations unchanged.

### Existing RU data plane

```text
Work laptop / BP Connect client
    |
    v
BPC transport selection
    |
    +-- VLESS + REALITY
    +-- AmneziaWG 2.0
    +-- WireGuard
    +-- WGShim / Agent relay
    +-- other existing fallbacks
    |
    v
RU Node gateway
    |
    v
Russian Internet / selected private routes
```

The corporate VPN remains installed only on the work laptop. BPC changes the
underlay, not the corporate overlay.

### RU transport isolation

```text
TCP/443    Xray VLESS/REALITY
UDP/443    AmneziaWG 2.0, awg0, 10.251.0.0/24
UDP/51820  native WireGuard, bpcwg0, 10.252.0.0/24
```

Optional transports continue to use independent protocol stacks, interfaces,
credentials and state directories. A failure in one transport must not require
deleting or rotating another transport.

## Safety invariant

The work gateway remains **fail closed**. There is no automatic `DIRECT`
member in the BPC failover group and no direct fallback rule for protected
traffic. Stage 1 does not weaken or replace those routing and transport safety
properties.

## Stage 1 boundaries

Implemented in this stage:

1. a single versioned Node model;
2. extensible centralized capability logic;
3. additive migration from legacy RU-node state;
4. multi-capability Nodes;
5. `bpc node status` and `bpc node info`;
6. compatibility wiring into install, update, status, control and relay enablement;
7. unit tests and architecture documentation.

Explicitly deferred:

- user/account/access models;
- distributed database or multi-controller consensus;
- join-token/node-certificate provisioning;
- transport-independent Node key provisioning;
- site-router/MikroTik implementation;
- removal/renaming of legacy `ru-node` directories and BP Gateway device
  record fields.
