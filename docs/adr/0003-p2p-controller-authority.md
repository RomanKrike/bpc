# ADR 0003: P2P Controller authority and durable endpoint policy

Date: 2026-10-20. Status: accepted opt-in authority, merged in #94.
Parent: [ADR 0002](0002-device-p2p-session-boundary.md), merged PR #93.

## Task and acceptance

Add Controller authorization to the session foundation without enabling installed
Agents. A registered Device can request a same-owner Sunshine grant only when
both Devices explicitly consent and initiating User/Device Access permits the
host /32. Deny overrides allow. Concurrent identity, credential, configuration
or Access changes must prevent stale signing. A managed endpoint must reject
replayed policy and stop established traffic after signed denial or expiry,
including across process restart. Preserve SEC-02/03/05/06 and P2P-01/02/03.

Affected paths: deploy Controller/API and runtime staging, internal/agentctl,
internal/p2p, tests and CI. No OS routes, production listeners, NAT traversal,
Windows UI, automatic pairing, cross-owner sharing or deployed services.

## Decision

Use existing canonical Device/User/credential and Access records, strong reads
and conditional Raft mutations. Before signing, commit unchanged puts guarded
by exact raw SHA256; guard missing optional records with delete + if_absent.
This fences all security inputs without new FSM operations, replicated prefixes
or runtime session state. The transaction advances the committed revision.
This deliberately adds writes/log volume per request; bound callers and measure
before operational enabling. This stage adds no production polling loop, rate limiter or capacity claim;
per-Device admission and load limits remain operational enabling gates.

P2P defaults off unless control/config.json has p2p_enabled=true. Per-Device
Access p2p_enabled=true is additional consent, never an Access allow. Consent
requires the enrolled Device key, token digest, desired value and exact Access
hash; a fresh p2p_change value prevents replay after toggling. The flag is
additive to the existing record, with no schema/version bump or legacy fallback.
Old Controllers do not advertise the capability; clients must fail closed.

All POSTs require capabilities=["p2p-session-v1"] and reject extra fields:

| Endpoint | Input / result |
| --- | --- |
| GET /v1/p2p/info | Device credential; cluster/Device, signing public key/certificate digest, consent and Access hash |
| POST /v1/p2p/consent | enabled, expected_sha256, signature; committed consent revision |
| POST /v1/p2p/issue | host_device_id; base64 signed grant envelope |
| POST /v1/p2p/sync | tickets (at most 16); base64 signed complete policy checkpoint |

Authority derives owner, participants, keys, private IPv4 and revisions from
committed state. Grant TTL is at most 60 seconds; checkpoint TTL at most 30,
both capped by credential expiry. Signing after a slow/expired commit fails.
The existing cluster Ed25519 CA signs domain-separated public envelopes. Deliver
its public pin through authenticated Controller HTTPS, never via the relay.
The current service and private IPv4 restrictions remain those of ADR 0002.

The Go PolicyStore explicitly creates or opens a BPC-owned bbolt file using the
existing dependency. It persists the cluster/Device/issuer pin, revision/time
floors and denied session IDs through fsync before activation/acknowledgement.
Opening missing, corrupt or differently pinned state fails. A restart restores
no authorization: a strictly newer signed checkpoint is required. Signed omission
means denial; the same ticket cannot be authorized again for its remaining life.
Local administrative restoration of an old database is outside this guarantee.

Managed sessions require both valid grant and current checkpoint, checked with
wall and monotonic deadlines. Apply errors fail closed. A future Agent caller
must invoke FailClosed on HTTP/sync errors, poll before expiry, close returned
revoked relay IDs, and preserve the gateway transport. The standalone foundation
primitives remain available for tests; no installed Agent calls this API yet.
Long-running renewal, Windows Wintun integration and relay lifecycle come next.

## Verification and rollback

Tests cover committed-state races, consent proof/replay, deny/disabled/ownership,
quorum/expiry, Python-to-Go wire compatibility, durable floors/restart, malformed
checkpoints and receiving-host TCP/UDP revoke with a malicious unfiltered peer.
The control-runtime CI adds real three-process Raft/mTLS issue/consent/deny and
quorum-loss rejection. Existing CI gates remain intact; see STATUS for observed
results, including platform skips. No WAN or actual Sunshine acceptance claimed.

Rollback: leave P2P disabled, revert this branch and keep canonical identities
and Access records. No migration, new replicated namespace or OS cleanup is
required. Do not delete/recreate endpoint trust stores to bypass a failed pin.
