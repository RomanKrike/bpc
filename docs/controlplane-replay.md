# Durable Raft FSM replay

Status: implemented replay fix and administrative rolling migration, validated
locally with current and pre-watermark binaries. This work does not complete
mesh live acceptance or authorize a production rollout.

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

## Verified offline checkpoint import

An upgraded ready Leader exposes `POST /v1/replay-checkpoint`. It first passes
an ordinary strong-read barrier and requests a Raft snapshot, then opens that
snapshot from the snapshot store. The payload includes the exact state bytes,
index, term, configuration and configuration index from the same stored
snapshot. A whole-payload checksum binds the state and metadata. It does not
construct an index from a logical export or separately sampled status.

The stopped recipient can run the proposed admin command:

```sh
systemctl stop bpc-controld.service
bpc cluster replay-checkpoint --source https://LEADER:9447
systemctl start bpc-controld.service
bpc cluster status
```

These commands describe this unreleased draft. Migrate one recipient at a time;
the selected upgraded Leader and a quorum must remain available. The helper
does not automatically stop or restart services or restore the entire cluster.
Use the HTTPS **cluster API**, not the public Device/Gateway API. The binary
also offers `--replay-checkpoint-source` alongside its normal identity/TLS and
state-directory arguments.

The importer takes the exclusive Bolt lock before contacting the source. It
opens the existing buckets without a write transaction and refuses an incomplete
DB instead of initializing it. Ordinary opens also avoid writing when all
buckets already exist. This preserves DB bytes on rejected source requests.
It requires an existing recipient DB, verifies cluster CA, membership URI and
certificate fingerprint through mTLS, forbids redirects, and binds the source
ID to the authenticated peer. Both authenticated certificates must match the
canonical checkpoint membership records; the source must remain a voter. The
recipient ID and Raft address must match the snapshot configuration, and the
checkpoint cluster must match the recipient's canonical DB. Canonical paths,
snapshot schema/checksum, whole-payload checksum, sizes, index, term and
configuration index are validated before installation.

Before writing the checkpoint, create and fsync a private Bolt backup under
`cluster/raft/replay-backups/`. Preserve all existing snapshot files and refuse
to replace an equal or newer checkpoint. Install through the library's snapshot
sink so normal Raft startup can consume the real metadata. The current canonical
policy, projected files and Node identity are untouched during import. Retain
the original revision floor; importing an older base never lowers it.

The backup contains Raft and canonical state, including control credentials,
and has mode 0600 under an owner-only directory. Node private identity files
are neither transferred nor changed. Verify successful quorum catch-up after
starting the recipient. A successful import does not by itself mark recovery
healthy; finish revision reconciliation below if reconstruction is blocked.

Tests cover installing a checkpoint into a watermark-free legacy DB and
consuming it with actual Raft; preservation of original policy, backup and a
higher revision floor; and rejection of corrupt/mismatched metadata. The real
three-process mTLS scenario also refuses import while the recipient is running,
rejects a follower source and an untrusted fingerprint, then imports and
restarts the recipient while preserving its private key and policy.

The process scenario also stops two voters, then attempts an offline import
from the remaining Controller. A follower rejects it, or a Controller still
reporting Leader fails its strong-read quorum barrier. Every recipient file
(DB, snapshots, previous backups, policy and identity) must stay byte-identical.
After a persisted voter returns and quorum is restored, retry against the
current Leader succeeds; the recipient catches up and all three revisions
converge. This covers checkpoint import around a quorum outage, not arbitrary
mixed-version recovery or an in-flight source crash.

## Administrative revision reconciliation

Gateway heartbeat signs a security snapshot using the revision returned by a
Controller strong read (`deploy/bpc-control-server.py`). Gateway installation
retains its previous signed snapshot as the minimum accepted revision
(`deploy/bpc_gateway_snapshot.py`). An old Controller can have issued a higher
revision before it was removed or became unavailable. Therefore the maximum
floor reported by the remaining Controllers alone cannot prove that a proposed
reconciled revision covers every consumer's accepted floor.

Run on the **current Leader** through the root-only local API:

```sh
bpc cluster reconcile-revision \
  --gateway-receipt GATEWAY_NODE_ID=/root/gateway-security-snapshot.json
bpc cluster status
```

Repeat `--gateway-receipt` for every active canonical Gateway. Copy each
Gateway's latest **accepted** `runtime/security-snapshot.json`, including expired
snapshots; do not replace it with a newly generated lower-revision snapshot.
Collect from the actual Gateway runtime during the migration maintenance window,
with old Controller issuance stopped. The CA signature proves issuance, not
which snapshot a Gateway most recently accepted: supplying an older signed copy
cannot prove its current floor. If a Gateway is inaccessible or its accepted
snapshot is missing, finish collecting evidence before proceeding. No Gateway
snapshot/trust/minimum revision is reset by this command. With no active Gateways,
the command needs no receipt arguments.

The API derives the target itself; it accepts no arbitrary numeric minimum.
For each required receipt, verify Ed25519 against the configured cluster CA,
the exact signed bytes/domain, cluster ID, schema and validity shape. Expiration
is permitted solely for historical evidence; the old policy is never installed.
Missing/extra Gateway IDs, wrong signatures/cluster and exhausted counters fail
before the reconciliation entry is written.

An actual quorum barrier establishes the observed leader state. Every configured
Raft member, including nonvoters, must support recovery version 1 and catch up to
that index over pinned mTLS. Compare canonical policy digests (excluding revision)
and configuration indexes. Take the maximum of current revisions, preserved local
floors and verified Gateway receipts. Recheck state/revision/configuration under
the mutation lock before committing a `ReconcileRevision` entry; a concurrent
policy or membership change requires retry. Ordinary mutation endpoints reject
this reserved command and field. It changes revision metadata only, preserves
canonical entries and CAS inputs, and advances the replay watermark atomically.
Normal mutations retain increment-by-one semantics, with overflow refusal.

Recovery metadata/barriers remain available below the local revision floor; this
does not bypass the guard for ordinary reads, writes, membership or snapshots.
After commit, require a fresh strong read and member confirmations. If leadership
or connectivity disappears, report failure even if the entry committed; retry
on the new Leader recomputes the target and is safe without increment inflation.
The v1 canonical snapshot/checksum format remains unchanged and retains the
reconciled revision. Normal restart persists it as the local floor.

## Supported rolling procedure

1. While the old cluster has quorum, run `bpc cluster backup` on its Leader.
   This creates a real persisted Raft snapshot before upgrade. Keep the backup
   and original state directories; a logical export alone is not a replay base.
2. Upgrade the Leader and the other Controllers one at a time, maintaining quorum.
   A marker-free recipient without a snapshot must stay stopped and import the
   verified paired checkpoint from the upgraded ready Leader before starting.
   An inflated recipient may remain `ok: false` until final reconciliation.
3. Collect the latest accepted signed snapshot from every active Gateway and stop
   issuance by old Controller binaries. Return every configured Raft member to
   service with the new binary and matching canonical policy. Reconciliation
   deliberately refuses a mixed-version or partially inaccessible configuration.
4. Run `bpc cluster reconcile-revision` on the current Leader, verify every member
   is healthy, then resume normal traffic/configuration updates. Signed Gateway
   refresh uses the raised revision and preserves the accepted minimum.
5. Keep upgraded binaries on all Controllers; do not downgrade to the defective
   pre-watermark implementation or add it after migration. Its replay behavior
   remains unsafe even though transport and snapshot v1 stay compatible.

Tests exercise the actual pre-watermark binary from mesh base `2d2a3513`: mixed
membership refuses reconciliation without changing policy/revision, its legacy
no-snapshot restart reproduces counter inflation, verified import preserves the
floor, and the upgraded cluster reconciles while retaining policy. A real
Gateway accepts its high historical signed floor and the refreshed snapshot
without a reset. Missing/forged evidence fails. Additional real Raft tests lose
the Leader after quorum commit but before its FSM/response completes, verify no
successful acknowledgement, elect a successor and retry without inflation. CAS
updates invalidate stale proposals; normal APIs cannot bypass recovery checks.

## Recovery limits

An existing database created by an older binary has no trustworthy applied
index. Its revision is a count of successful mutations, not a Raft log index;
CAS conflicts and membership entries prevent converting one into the other.
Using the last stored log index would also skip possibly uncommitted entries.
Do not guess either value.

If Raft restores a valid snapshot, the snapshot base and subsequent suffix are
well defined and the cleared watermark is safe. A legacy database without a
snapshot now stops before replay and requires a verified checkpoint. If no
ready upgraded Leader can export one, offline import cannot manufacture it.
Floor-blocked members with valid reconstructed state can use administrative
reconciliation when quorum and every configured member return.

This procedure does not reconstruct permanently lost quorum, guess missing
Gateway floors or automatically repair differing canonical policies. Those
conditions refuse successful migration and require preserved backups/evidence.
Availability during rolling maintenance depends on existing quorum/membership;
migration does not grant an isolated Controller authority. The mesh release
still requires production VPS/kernel/Windows acceptance.
