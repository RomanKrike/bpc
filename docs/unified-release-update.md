# Unified mesh and P2P releases

From 0.22.0, the normal release includes routed mesh/topology, the watermarked
Raft replay/recovery implementation and the default-off P2P/account pilot.
Stable 0.21.0 remains an incompatible downgrade for installed mesh candidates.

## One transition from older candidates

The updater already installed in older mesh candidates requires a `mesh-test`
manifest and refuses bare updates before downloading anything. A remote release
cannot change that installed code. Keep its guard and use the transition artifact
from the successful 0.22.0 release once. It contains the same unified source,
but retains a full `0.22.0-mesh.<source-sha>` version and candidate manifest so
the original verifier accepts it. Its Agent reports that full version too.

1. Plan a maintenance window with independent management access. On the healthy
   Leader run `bpc cluster backup`; retain the private backup, state directories,
   old bundle and trusted checksum. Do not upload state, private keys or backups.
2. Download `bpc-connect-mesh-transition.tar.gz` and `SHA256SUMS` from the same
   pinned release tag, rather than a moving latest URL. Verify their source and
   obtain the transition archive's SHA256 from that release. Stage it on all Nodes.
3. On the observed Follower first:

   ```sh
   bpc-update --bundle /root/bpc-connect-mesh-transition.tar.gz --sha256 TRUSTED_TRANSITION_SHA256
   bpc-status
   bpc cluster status
   bpc path list
   ```

4. Wait for health, all voters online, quorum and zero replication lag; check
   routes and each Node's revision/floor against its own earlier values. If any
   check fails, stop. Update the remaining Node only after convergence.
5. Once all Nodes run the transition, use ordinary `bpc-update`, one Follower
   at a time with the same checks, to install stable 0.22.0. Subsequent compatible
   stable updates use just `bpc-update`. Do not delete `CANDIDATE.json` manually.

In a two-voter cluster both votes are required; each restart temporarily prevents
writes. This procedure does not change membership or promise session continuity.
Keep P2P disabled until every Controller supports its delivery prefix. Provision
the explicit TLS relay and account settings separately; see the pilot guide.

## Verification and recovery

Network updates first check HTTPS-delivered SHA256SUMS, then validate all archive
paths, file hashes, full runtime inventory and `RELEASE.json`. The manifest must
declare `mesh-raft-v1-p2p-v1`; stable versions before 0.22.0 and downgrades are
rejected before extraction/activation. This is a compatibility/integrity check
within the existing GitHub/HTTPS trust boundary, not an independent signature.
Same-version different-content archives are refused. A stable installation also
refuses a pinned candidate through the normal local-bundle updater.

Updates keep a private filesystem backup and switch the release pointer atomically.
That copy is not a consistent Raft recovery point: a live Controller may commit
while files are being copied. Use the explicit Leader backup procedure as well.
If migration/health fails, the new release and current state remain in place;
the updater reports the previous path and exits with failure. Do not continue
the rollout, automatically restore the filesystem copy, downgrade the FSM or
reset revision floors. Diagnose and use a compatible forward fix with the
existing [recovery procedure](controlplane-replay.md).

An older stable installation with a materialized pre-watermark database may fail
the existing legacy replay preflight. This release does not bypass that guard or
claim automatic migration of every historical state. Use the documented rolling
migration/checkpoint procedure on that diagnosed topology. Installed mesh 8c1abba
already has watermarks/floors; it must retain them during the transition.

## Windows and acceptance

The transition preserves the existing signed Windows update channel. Stable
publication uses the existing signing/actual-binary-version checks. Do not publish
a candidate under a stable version override. Generate new prepared personal
HTTPS download links from the stable server to update/install by opening the EXE;
valid existing Device identity and keys are reused. Old links retain their old EXE.
Do not copy identity/key files between PCs. See [the Windows pilot](p2p-windows-pilot.md).

CI covers isolated kernel/Access/recovery, real mTLS/Raft and packaged Windows
version checks for both archives. Native Windows UI/UAC/Wintun and actual two-PC
Moonlight/Sunshine/WAN acceptance remain pending. The P2P pilot still permits only
one unrenewed session of at most 60 seconds over TLS/TCP relay.
