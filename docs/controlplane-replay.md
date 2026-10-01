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

## Unresolved legacy migration

An existing database created by an older binary has no trustworthy applied
index. Its revision is a count of successful mutations, not a Raft log index;
CAS conflicts and membership entries prevent converting one into the other.
Using the last stored log index would also skip possibly uncommitted entries.
Do not guess either value.

If Raft restores a valid snapshot, the snapshot base and subsequent suffix are
well defined and the cleared watermark is safe. A legacy database that restarts
without a restored snapshot still has the original first-replay problem: the
new watermark prevents later repetitions but cannot retroactively identify its
already materialized prefix. Previously inflated revisions and consumers'
signed-snapshot revision floors also need a cluster-wide migration policy.

The draft therefore does not claim a safe rolling upgrade from arbitrary older
databases. Before merging, implement and test migration without policy rollback
or resetting accepted security revision floors, including mixed binaries,
missing snapshots, CAS/conflict history, and quorum loss. Do not deploy this
branch as a mesh release.
