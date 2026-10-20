# ADR 0006: one compatible mesh and P2P release line

Status: accepted for implementation by the maintainer's request to unify.

The active mesh candidate contains topology and watermarked Raft recovery absent
from stable 0.21.0. Removing its updater guard would allow loss of those contracts.
The P2P transplant and mesh CI have already passed together on PR #98; stable
transport/UI fixes must also be retained in the unified tree.

Starting with 0.22.0, stable packages include both runtimes. A hashed RELEASE.json
declares the mesh-raft-v1-p2p-v1 compatibility profile. The updater validates the
profile, complete archive and nondecreasing stable version before activation.
The channel remains trusted through existing GitHub HTTPS/checksums; the manifest
is not an independently signed release authorization.

Old installed updaters cannot accept that manifest. Ship a separate candidate
transition artifact from the same source, accepted by the original verifier,
to install the new updater once. It retains candidate identity and cannot publish
a stable Windows update. Following transition, ordinary bpc-update installs the
stable artifact. Future incompatible profiles require an explicit migration.

All update failures preserve current live state and the active new runtime.
Automatic DB restore or older-FSM rollback could undo committed security state.
Operators stop the rollout and recover with a compatible forward fix. Backups
remain private; filesystem copies do not substitute for a consistent Leader backup.

No protocol/schema reset, key regeneration, production rollout or native/WAN
acceptance is implied by unification. The P2P pilot stays default-off and bounded.
See [operator procedure](../unified-release-update.md), STATUS and the existing
CI tests for replay/recovery, mesh ingress and candidate/stable updater behavior.
