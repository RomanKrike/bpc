# ADR 0002: Device-to-Device P2P session boundary

Date: 2026-10-20. Status: accepted isolated foundation, merged in #93.
Baseline: main `ef947e751315885d1196e97391d9139eed973480`.

## Outcome and scope

The requested outcome is ordinary Moonlight/Sunshine over BPC between two
Windows computers, preferring direct delivery and retaining a relay fallback.
This first change implements a testable, encrypted relay vertical slice under
`internal/p2p`. It does **not** enable P2P in installed Agents or issue grants
from the Controller. There are no OS network mutations or new dependencies.

The provisional initial scope is two Devices of the same User, Sunshine's
default ports and IPv4. Cross-owner invitations, custom ports, automatic pairing,
site routing, NAT traversal and production/Windows GUI integration are separate
steps. Same-owner scope narrows the initial authority; it is not inferred from
an existing product requirement. It can be extended in a later version.

## Decision

1. Keep User, Device, Node and Access distinct. A relay remains a capability of
   one Node. Current gateway `TransportPath` entries still lead to the canonical
   gateway WireGuard peer; do not substitute another Device's public key there.
2. A session has two distinct Device identity keys, WireGuard public keys and
   private IPv4 /32 addresses. Each endpoint retains its own WG private key;
   the relay has neither private key. Both endpoints bind the other peer key to
   exactly its /32. Preserve the current gateway identity and routes.
3. A Controller-signed, versioned public grant binds cluster, session, committed
   policy revision, both participants, service and expiry. Maximum validity is
   60 seconds; local monotonic deadlines prevent receipt-time clock rollback
   extending a lease. No Controller signing private key is sent to a Device or
   relay. `SignGrant` is a primitive, not a new authorization API.
4. Initial relay transport is TLS 1.3/TCP with bounded datagram framing. Each
   Device proves possession of its Ed25519 identity using a fresh nonce, ticket
   digest, side and TLS exporter binding. Grants alone are not bearer access.
   The relay sees WireGuard ciphertext and public metadata; TLS termination
   must not expose application plaintext. TCP head-of-line blocking is an
   accepted prototype limitation, not the intended preferred gaming transport.
5. A per-session TUN wrapper filters outgoing plaintext before WG encryption
   and incoming plaintext after WG decryption. The receiving host is the
   security boundary even when the initiating Device bypasses its own filter.
   Bind source/destination /32, direction, TCP/UDP and the Sunshine service.
   Replies require an observed permitted initiator flow; unsolicited reverse
   TCP SYNs are denied. This bounded flow tracker is not a full TCP conntrack
   implementation and is not a general host firewall.
6. Revoke clears local flow authorization; expiry never renews offline. Relay
   revoke closes both sides, rejects reattachment, and remembers revocation
   arriving before admission for the maximum outstanding lease lifetime.
   Grant issuance/revocation delivery, persistent revision floors, restart
   replay protection and Windows suspend/resume policy reconciliation MUST be
   integrated before enabling this on installed Agents. A local revoke return
   is not a distributed enforcement acknowledgement or packet recall.
7. No IP fragmentation, IPv6, ICMP, multicast discovery, all-host grants or
   default routes in this prototype. Permit TCP 47984/47989/48010 and UDP
   47998/47999/48000/48002/48010. Deny administration port 47990. Validate this
   profile against pinned real Moonlight/Sunshine versions before product use.

## Resource and compatibility bounds

At most 128 relay connections (including pending TLS/auth), 64 admitted sessions,
4 KiB data frames, 8 KiB signed tickets and 4096 endpoint flows. Five-second
authentication deadlines, bounded writes and lease deadlines stop idle work.
Revocation tombstones have a fixed bound; exhaustion temporarily rejects new
admissions instead of forgetting revocation. The endpoint bridge binds only
loopback and accepts only its fixed local WG sender; it never learns a target
from an unauthenticated datagram.

No legacy packet format, canonical state schema, gateway Access evaluator,
Controller consensus mutation, installed listener or global configuration is
changed. The new package has no production caller; reverting this change removes
the prototype without network cleanup. Future enabling must be opt-in and must
not introduce a DIRECT escape for the work underlay.

## Acceptance and invariant mapping

- P2P-01 / SEC-02 / SEC-06: reject unknown issuer/cluster, stale revision,
  expired/tampered/unsupported grants, other owners and mismatched Device proof.
- P2P-02 / SEC-02 / SEC-03: receiving endpoint rejects other ports, fragments,
  spoofed addresses and unsolicited reverse initiation; revoke stops both
  directions of established managed flows.
- P2P-03 / MESH-01: relay transfers WG ciphertext between distinct Device peers;
  it does not grant authorization or replace gateway identity. Direct migration
  and MESH-02 data confirmation remain later-stage obligations.
- SEC-01 / SEC-04 / SEC-05 / SEC-07: current underlay, external networking,
  consensus and rollback implementations are unchanged. Existing gates remain
  required; absence of a new host mutation is not evidence of WAN acceptance.

Evidence: `internal/p2p/policy_test.go` and `relay_test.go`. The real userspace
WG/TLS test deliberately leaves the initiator unfiltered and verifies that the
host blocks a forbidden port and established TCP/UDP after host revoke. It uses
synthetic addresses and ephemeral test keys, not production credentials.

## Following stages

1. Integrate issuer and permission evaluation with committed Controller state,
   pinned signing trust, revision floors and revocation delivery; do not treat
   requester-provided ownership as authority. Add runtime capability negotiation.
2. Integrate both Windows endpoint filters and peer reconciliation without
   `replace_peers=true` erasing P2P peers or changing gateway behavior. Own all
   routes/peers explicitly; filter policy expiry must tear down unauthorized
   sessions. Provide a deployable opt-in relay role before claiming a feature.
3. Add an authenticated UDP relay/direct transport and STUN/ICE on the actual
   data socket. Verify data before switching, keep rollback/hysteresis, and
   preserve the remote Device peer through direct/relay handoff. Do not upgrade
   Go or dependencies as incidental work.
4. Add Windows UI and actual Moonlight/Sunshine acceptance across NATs, MTU,
   Wi-Fi changes, offline expiry and restart. Record timing as observations.

See [quality gates](../DEVELOPMENT.md), [status](../STATUS.md),
[roadmap](../ROADMAP.md) and [invariants](../specs/INVARIANTS.md).
