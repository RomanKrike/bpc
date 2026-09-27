# Distributed Control Plane (Stage 5)

BPC Stage 5 removes the permanent single-Controller dependency while keeping the existing Node capability model. controller, gateway, relay, and site_router remain capabilities of one BPC Node.

## Cluster topology

The supported HA topology is three controller-capable Nodes. HashiCorp Raft replicates canonical control state. Three voters require quorum 2/3. A single Controller loss keeps mutations available; loss of quorum rejects new canonical mutations.

New Controllers enter as pending, join Raft as nonvoters, catch up through the current commit index, and are promoted to voters only after catch-up. Raft leadership is temporary; there is no permanent master.

Raft transport and Controller-to-Controller API traffic use cluster mTLS. Controller certificates are bound to cluster identity and replicated membership. Revoked or fingerprint-mismatched Controller certificates are rejected.

The APIs are separated into public HTTPS control API, cluster mTLS API, Raft mTLS transport, and a loopback root-only operator API protected by a random bearer token.

## Canonical state and consistency

The replicated allowlist includes Users, username indexes, Devices, Nodes, Node credentials, one-use Node Join tokens, Access, canonical route ownership, revocations, Controller membership, cluster metadata, and security-sensitive access/refresh credential records. Historical transport/runtime paths are not accepted as replicated core state.

Every mutation is a deterministic ordered command with optional if-absent, presence, or SHA-256 preconditions. Security-sensitive reads use a Raft barrier. Followers forward mutations to the current Leader rather than maintaining another source of truth.

Refresh-token rotation is one consensus transaction with a checksum precondition on the old token record, so concurrent rotation on different Controllers cannot both commit. Access edits use the same compare-and-set principle.

## Controller enrollment

Controller enrollment is two phase. The joining Node creates its Ed25519 Controller private key locally and sends only a CSR. The existing cluster signs the CSR and commits a pending membership record with the Node enrollment transaction. The Node starts bpc-controld, joins Raft as a nonvoter, catches up, and is promoted to voter only after its applied index reaches the promotion target.

The Node private identity never leaves the Node. Cluster CA signing material is cluster-wide material available to Controllers so a new Raft Leader can continue enrollment without a permanent master. Protocol and state-schema versions are checked before certificate issuance and again before membership activation.

## Client and Node failover

Canonical Controller records contain internal Raft/API endpoints and the public HTTPS endpoint. New Node Join tokens can carry a Controller URL pool while old single-URL tokens remain parseable. BPC Node and BP Connect/Agent clients fail over on network errors and temporary 502/503/504 responses. Authorization 4xx responses are terminal and are not hidden by failover.

A public Controller endpoint still requires trusted public Web PKI; cluster mTLS certificates are not a substitute for public client TLS.

## Gateway security snapshots

Gateway-only Nodes do not join Raft. An authenticated Gateway heartbeat receives a signed security snapshot after a strong consensus read. It contains only Device public/BPC transport identity, Access, canonical routes, revocations, Node trust, Controller public endpoints, revision, created_at, and expires_at.

The snapshot does not contain User password hashes, refresh-token records, 2FA secrets, Controller private keys, Node private identity keys, join secrets, or the Raft log.

Snapshots are Ed25519-signed with cluster signing trust. A Gateway rejects signature failure, cluster-ID mismatch, revision rollback, incompatible schema, future timestamps, and expiry. Unknown, disabled, or revoked Devices are denied. If Controllers are unavailable, only the last verified snapshot is usable until expires_at; the deadline is never extended locally. After expiry the BPC-owned Gateway transport fails closed.

## Route ownership

A site_router heartbeat can advertise non-default IPv4 CIDRs. Each route is stored with owner node_id. Updating the advertised set and the Node heartbeat is one consensus mutation, so withdrawals cannot remain authoritative on another Controller. Stage 5 does not replace the underlying site-router transport.

## Observability and network ownership

bpc cluster status reports cluster identity, Leader/Raft role, voter/quorum health, term, commit and applied indexes, canonical revision, schema/protocol versions, snapshot index and replication lag. Membership changes, state mutations and snapshot/restore operations emit cluster events.

Stage 5 does not broaden BPC ownership of the host network. Existing Stage 4.5 ownership checks remain authoritative: unmanaged WireGuard interfaces, routes, firewall state and unrelated networking systemd units stay outside distributed reconciliation.
