# Distributed Control Plane disaster recovery

This runbook applies to the Stage 5 Raft control plane. Normal failover should not use restore.

## One Controller or Leader is down

With three voters, the remaining two retain quorum. Run bpc cluster status on a surviving Controller, confirm a Leader and quorum 2/3, repair or replace the failed Node, then wait for it to catch up. A failed Leader is expected to be replaced automatically by election.

## Quorum is lost

With only one of three voters reachable, canonical mutations are intentionally unavailable. Do not edit canonical JSON files by hand. Restore connectivity or a valid quorum first.

## Backup

Run sudo bpc cluster backup, optionally with --output PATH. The backup contains a checksummed logical canonical snapshot, metadata and the public cluster CA certificate. It excludes Node private identity keys, Controller private keys and the cluster CA private key.

## Restore

Restore is a disaster-recovery operation, not a normal rollback mechanism. Inspect backup metadata, obtain its cluster_id, and run sudo bpc cluster restore BACKUP --confirm CLUSTER_ID on the current Leader. Multi-Controller restore additionally requires --force after explicit operator acceptance.

The restore path validates backup SHA-256, snapshot checksum/schema, snapshot cluster identity, current cluster identity and Leader role. Raft manual restore keeps the current Raft configuration and distributes restored state to followers.

## Permanently lost Controller

Prefer replacement over shrinking a three-Controller cluster. bpc cluster remove NODE removes a member. BPC refuses unsafe shrinkage to one voter unless --force is explicitly supplied for disaster recovery. Remove the current Leader through another Controller.

Controller removal changes Raft membership first and commits the canonical revocation only after successful membership removal, avoiding premature mTLS revocation.

## Verification after recovery

Verify one Leader, expected quorum, converged commit/applied indexes, zero replication lag, strong-read authorization, persistent Device revocation, correct Access/route ownership, advancing Gateway snapshot revision, and unchanged unmanaged host networking.

Never reconstruct canonical state by copying individual JSON files between Controllers. Raft state is authoritative.
