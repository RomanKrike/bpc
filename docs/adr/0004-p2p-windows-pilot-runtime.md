# ADR 0004: explicit Windows P2P pilot on the existing BPC adapter

Date: 2026-10-20. Status: proposed pilot implementation.
Baseline: main aecf34e7ddec15135b3fd4c352b72d367f78dade after authorized
merges of #93 and #94. Their tested trees were preserved; #94 was retargeted
to main and its resulting merge tree matched its checked head exactly.

## Task, acceptance and bounds

Enable an explicit Windows Agent pilot using the Controller grants and durable
policy from ADR 0003. A matching Device identity/WG private key and address,
fresh signed policy, a verified TLS relay and endpoint filter are all required.
Controller failure, signed denial, local stop, expiry and Agent shutdown must
stop established TCP/UDP and prevent gateway fallback for reserved peer /32s.
Restart must restore deny reservations before starting gateway WG, without
restoring authorization or silently bootstrapping missing trust/state.

Touched paths: Agent command/runtime, internal/p2p, a separate pilot relay
command, deployment bundle/CI and tests. Relevant invariants: SEC-02/03/04/05/06,
MESH-01 and P2P-01 through P2P-05; add P2P-06 for shared-adapter isolation.
No changes to canonical Controller state, gateway keys/addresses/peer profile,
legacy wire formats, dependencies or production infrastructure.

This permits one active pilot session per Agent, with a bounded 60-second lease, not completion of the whole Windows product
stage. Automatic ticket delivery, coordinated grant renewal for long streams,
relay service provisioning/discovery, UDP/NAT traversal and UI remain pending.
Native Wintun/routes/ACL/service and actual Sunshine acceptance need a separately
authorized isolated pair of Windows machines. Cross-build/userspace tests cannot
establish them. No install, service restart or OS networking script is executed
on this workstation as part of development.

## Decision and lifecycle

Reuse the existing BPC adapter to avoid duplicate overlay addresses and preserve
the gateway's canonical WireGuard identity. Default mode passes the original TUN
directly to the gateway, unchanged. Explicit P2P initialization and Agent restart
select a MuxTUN. It routes only signed, locally bound peer /32s to separate
filtered virtual TUN/WireGuard devices. No peer replaces the gateway WG peer.
Gateway ingress from reserved peer addresses is rejected; malformed/fragmented
IPv4 for a reserved destination also goes to the peer filter, never gateway.
Queues, peers and flows have bounds; closing a peer never closes the OS adapter.

Track persists the remote /32 as a deny reservation before any allow or route.
Reservations are restored at boot before gateway WG starts and last for the
owned overlay lifetime, including after a peer fails or expires. They persist
across restart (at most 16 distinct peers for this pilot). The local bbolt
record adds an optional reserved field; older binaries cannot decode it and
must fail closed rather than downgrade that store. A missing/corrupt initialized
store prevents overlay startup, because its reserved addresses cannot safely be
reconstructed. An already running mux retains its reservations on sync errors.
Do not delete trust or DB files to clear a failed pin/floor.

RunManagedEndpoint binds the enrolled keys/address, obtains a new signed
checkpoint and only then attaches the filtered peer, reconciles its owned route
and authenticates to the relay. Policy polls every 5 seconds with a 3-second
request deadline; independent 100ms wall/monotonic checks close idle expired
sessions. Terminal exit durably stops that ticket and closes both local sockets
and relay connection; relay disconnect revokes the other participant too.
No grant renewal, offline extension or same-ticket reconnect is attempted.
Local command acknowledgement means requested, not proven enforcement or
successful data-plane handshake. A packet already handed to the OS is not recalled.

## Ownership and trust

Only an Administrator explicitly bootstraps the public Controller pin over
existing authenticated HTTPS. Initialization creates, never replaces, trust and
policy state. The p2p directory has an exact protected SYSTEM/Administrators
DACL. Request files carry public tickets/relay metadata only, are bounded and
strictly parsed, and are atomically replaced; no private key is accepted there.
The service uses existing enrolled keys and reloads the access credential saved
by the normal Agent loop; it does not race credential refresh or mutate state.

Routes use the live native adapter LUID -> index/GUID, verified again by the
route script. Add only the peer /32 in ActiveStore. Refuse conflicting routes;
reuse an exact existing route only when the current gateway configuration or
this overlay lifetime created it. No deletion/adoption of external objects, DNS
or default-route change. Reserved routes remain deny guards until overlay
teardown/reconciliation. Native teardown behavior still needs Windows acceptance.
TLS relay hostname comes from the explicit host:port and uses system CA trust;
there is no insecure flag or relay-supplied issuer bootstrap.

The separate bpc-p2p-relay pilot binary requires cluster/issuer pin and existing
TLS files, defaults to loopback, handles shutdown and uses the bounded encrypted
relay from ADR 0002. Bundle it for Linux amd64/arm64. This creates no new Node
entity, installs no service and enables no public listener by default.

## Verification and rollback

Tests exercise real HTTPS policy requests, TLS relay and userspace WG TCP/UDP,
then signed denial, Controller error and idle expiry. Negative tests cover local
key/address binding before network/route mutation, mux gateway isolation,
malformed packets, bounds, shutdown, durable local stop/reservations and bootstrap
refusal. Windows route-plan tests inspect ownership/conflict guards; they do not
execute or certify NetTCPIP/Wintun/ACL effects. Retain all existing CI gates and
record observed revision, commands, failures/skips in STATUS.

Rollback: stop the pilot, withdraw Device consent and disable Controller P2P,
wait out outstanding grants, stop the Agent overlay, then restore the previous
binary. Keep identity, trust and policy DB; do not reinitialize it. Existing
owned-adapter reconciliation handles its routes; never remove external routes.
