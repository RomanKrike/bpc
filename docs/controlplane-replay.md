# Durable Raft FSM replay

Status: proposed fix; do not release until migration of legacy databases is
implemented and verified. This work does not complete mesh live acceptance.

## Reproduced defect

The canonical Bolt database persists across process exit. Raft replays its
committed log on restart. Applying that log again to the already materialized
canonical state can increase its mutation-count revision, re-evaluate CAS and
creation preconditions against the wrong state, and temporarily roll back a
policy change.

A deterministic regression applies `grant` at index 1, then `revoke` at index 2,
closes and reopens the database, and replays index 1. Before the fix, the value
changes back to `grant` and revision advances from 2 to 3. Previously the real
three-controller process test checked the final projected node record, but did
not require revisions to remain unchanged across restart.

## Proposed change

Persist `canonical_meta/applied_index` in the same Bolt transaction as the
canonical mutation and revision. Conflicting commands also advance this
watermark. Entries at or below the durable watermark must not execute or
project historical operations again. Current projection repair remains the
responsibility of the existing strong-read and follower acknowledgement paths.

The mutation protocol, revision meaning, and version 1 snapshot envelope and
checksum remain unchanged. Snapshot restore replaces canonical state and clears
the previous database watermark atomically, allowing the snapshot's log suffix
to apply. This also supports old snapshots with no applied-index field. Applying
synthetic index-zero logs remains available to existing unit fixtures only.

## Validation

Regression coverage includes policy preservation at every replayed prefix,
unchanged revision after database reopen, three actual Raft restarts with and
without a persisted snapshot, applying a new mutation afterward, and resetting
a newer database watermark when restoring an older snapshot.

The real loopback mTLS three-controller test now requires an unchanged revision
when restarting a persisted voter and equal revisions after leader/quorum
recovery and follower mutations. These are local process tests, not production
VPS or kernel mesh acceptance.

## Legacy startup preflight and revision floor

Before starting a transport listener or Raft, inspect canonical metadata. A
materialized legacy DB without an applied index and without any Raft snapshot
is refused with `ErrLegacyReplayUnsafe`. Canonical entries, revision and
projected files remain intact; do not delete the DB or synthesize an index.
Snapshot presence allows Raft to attempt restoration; it does not bypass Raft
or canonical checksum validation of that snapshot.

Persist the maximum of the current canonical revision and any previously saved
`canonical_meta/revision_floor` before snapshot restoration. The floor is local
metadata and survives restores and failed migration restarts. It is never
replaced by a lower reconstructed revision. Strong reads, normal mutations,
follower acknowledgements, membership changes, snapshot creation and export
fail while reconstruction is below that floor. Health exposes `revision_floor`
and reports `ok: false`; such a Controller is not counted as healthy. An
explicit authorized snapshot restore remains available for recovery, but does
not reset the floor.

A legacy DB with a valid snapshot and an uninflated counter can replay its
suffix normally. The durable Raft regression covers this path through three
restarts, alongside indexed DBs with and without snapshots. Tests also prove
that missing-checkpoint refusal preserves policy and releases the Bolt lock,
malformed metadata is rejected, an inflated floor survives repeated recovery
attempts, and blocked operations do not write policy or change membership.

## Unresolved legacy migration

An existing database created by an older binary has no trustworthy applied
index. Its revision is a count of successful mutations, not a Raft log index;
CAS conflicts and membership entries prevent converting one into the other.
Using the last stored log index would also skip possibly uncommitted entries.
Do not guess either value.

If Raft restores a valid snapshot, the snapshot base and subsequent suffix are
well defined and the cleared watermark is safe. A legacy database without a
snapshot now stops before replay. It needs a verified checkpoint import or a
controlled rejoin procedure; neither is implemented here. A database with an
inflated historical revision stops successful control-plane operations if
snapshot reconstruction falls below its preserved floor. Previously divergent
counters and consumers' signed-snapshot revision floors still need a
cluster-wide reconciliation procedure. These safeguards deliberately do not
claim to complete migration or guarantee availability during a mixed-version
rollout.

The draft therefore does not claim a safe rolling upgrade from arbitrary older
databases. Before merging, implement and test migration without policy rollback
or resetting accepted security revision floors, including mixed binaries,
missing snapshots, CAS/conflict history, and quorum loss. Do not deploy this
branch as a mesh release.
