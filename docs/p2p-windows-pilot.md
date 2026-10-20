# Windows P2P pilot (explicit, experimental)

This is an operator pilot, not a finished Moonlight/Sunshine product. It uses
one active session per Agent, default Sunshine ports, same-owner Devices and
an unrenewed grant of at most 60 seconds. Read [ADR 0004](adr/0004-p2p-windows-pilot-runtime.md)
and [STATUS](STATUS.md) before treating any test as real Windows acceptance.

## Prerequisites

Use two separately authorized, isolated Windows test computers with installed
BPC Agents and functioning gateway tunnels. The service must have the current
pilot binary and its existing Wintun dependency. Keep existing Device identity,
WireGuard keys and addresses. Controller must advertise p2p-session-v1 and have
global P2P enabled through the existing Raft-backed canonical config mutation;
never edit canonical files directly on replicas. Configure initiating Access
for the host /32 before setting consent; deny still overrides allow.

Provision an explicitly authorized test Node's TLS relay using its existing
publicly trusted certificate (or a test CA already trusted by both computers):

```text
bpc-p2p-relay --listen BIND_ADDRESS:24446 --cluster CLUSTER_ID --issuer-public-key CONTROLLER_PUBLIC_KEY --tls-cert CERT_FILE --tls-key KEY_FILE
```

The issuer is the Controller public Ed25519 pin. Relay has no Controller signing
key or Device WG private key. Default listener is loopback; no installer enables
a public listener/service. Firewall, TLS files, Node service provisioning and
routing remain separately authorized operator work. There is no insecure TLS
switch. Do not change public Node discovery or gateway peers to point at a Device.

## Explicit bootstrap and consent

On each test computer, use an Administrator terminal:

```text
bpc-agent.exe p2p init
```

This authenticates to the configured Controller using the enrolled Device
credential, creates public trust and policy state in ProgramData/BPC/p2p and
locks that directory to SYSTEM/Administrators. It never overwrites existing
trust or recreates a missing initialized database. Restart the Agent through the
existing supported stop/start procedure to activate the shared-adapter pilot.
No P2P initialization means the original gateway TUN path remains unchanged.

Then on both computers:

```text
bpc-agent.exe p2p consent --enabled=true
```

The proof uses the enrolled Device key and exact Access hash. A conflict requires
refresh/retry; another Device or relay cannot grant consent. Commands use the
access credential maintained by the running Agent; they do not independently
rotate credentials. An expired credential requires the normal Agent refresh.

## Bounded session

On the initiating computer:

```text
bpc-agent.exe p2p request --host HOST_DEVICE_ID --out NEW_PUBLIC_TICKET_FILE
```

Transfer only this public ticket file to the host through the authorized test
channel. Never copy state.json, private keys, credentials or policy.db. Promptly
submit the same ticket on both computers, before its maximum 60-second expiry:

```text
bpc-agent.exe p2p start --ticket PUBLIC_TICKET_FILE --relay TLS_RELAY_HOST:24446
```

The running Agent verifies its own Device/WG keys and address, obtains fresh
Controller policy, attaches a separately filtered WG peer and adds only the
owned BPC /32 route after checking adapter GUID/index and route conflicts. The
TLS name is TLS_RELAY_HOST and must match its certificate. A command saying
requested is not a data-plane/enforcement acknowledgement. Inspect the pilot
logs and verify TCP/UDP with the actual test application independently.

On either computer:

```text
bpc-agent.exe p2p stop
bpc-agent.exe p2p consent --enabled=false
```

The local request is polled once per second. Active policy polls every five
seconds with a three-second request deadline; signed denial or HTTP error
terminates the session. Packet filtering also checks wall/monotonic expiry and
idle transport expiry is watched independently. A stopped ticket cannot be
reused; obtain a new grant. No automatic ticket delivery or long-stream renewal
is implemented. First-peer arrival can precede the other participant; ordinary
WG retry timing is not a WAN latency guarantee.

## Failure and rollback

Established TCP/UDP must stop after denial, expiry or local stop. A reserved
peer address remains blocked instead of returning to gateway, including across
restart; at most 16 distinct peer reservations are retained in this pilot.
Other gateway destinations stay on their existing path. Conflicting/external
routes are refused, never removed. Route/adapter/ACL effects and native cleanup
still require isolated Windows acceptance; userspace tests do not certify them.

If initialized trust/database is missing or corrupt at boot, the overlay fails
closed because previous deny reservations cannot safely be reconstructed. Do
not delete/reset either file to bypass a revision floor or pin. A partial init
also needs deliberate repair. No authorization is restored from disk alone.

For rollback, stop sessions, withdraw consent, disable Controller P2P, wait for
outstanding grants to expire, then stop the overlay and restore the previous
binary. Keep canonical identities and protected policy state; do not wipe trust.
Use the existing owned-adapter reconciliation and never delete external routes.
