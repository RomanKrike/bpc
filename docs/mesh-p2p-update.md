# P2P on the installed mesh candidate

Historical candidate procedure. For the unified 0.22.0 release and the one-time
transition to ordinary updates, use [the current procedure](unified-release-update.md).

This candidate starts at `8c1abbaf454261fc500f788370ffb54bb70f265e`, not the
stable release branch. It transplants the explicitly enabled P2P pilot/account
window from v0.21.0 while preserving the routed runtime, topology, Access,
watermarked Raft replay/reconciliation and candidate update restrictions.
Stable v0.21.0 is not its upgrade or rollback target. Keep `CANDIDATE.json`.

Obtain the pinned `bpc-connect-dist` artifact from this candidate PR's successful
CI. Verify source SHA, bundle SHA256 and the manifest using
[the existing candidate procedure](mesh-candidate.md). PR CI packages its checked
out merge commit: match `CANDIDATE.json.source_sha` against that checkout, rather
than assuming the feature-branch head is the artifact source. The complete version
is `0.21.0-mesh.<source-sha>`. Both routed and P2P relay binaries are required;
the packaged Windows Agent reports that exact version.

## Update the existing two-Controller cluster

The reported cluster has two voters and needs both for quorum. No procedure can
preserve write availability while one is stopped without first changing the
membership/topology; this task does not change membership. Schedule a maintenance
window and retain independent management access. Existing `healthy` paths do not
prove that application sessions survive maintenance.

1. On the healthy Leader, run `sudo bpc cluster backup`. Retain the private backup,
   existing state directories, installed candidate bundle and its trusted SHA.
   Do not upload databases, access credentials, private keys or this backup.
2. Stage the same verified candidate bundle on both Controllers before updating.
3. Update only the Follower using the existing updater:

   ```bash
   sudo bpc-update --bundle /absolute/path/bpc-connect-deploy.tar.gz --sha256 TRUSTED_BUNDLE_SHA256
   bpc-status
   bpc cluster status
   bpc path list
   ```

4. Wait for health, quorum 2/2, zero replication lag and preserved paths. Compare
   revision and each node's own revision floor with its recorded pre-update values;
   the two local floors need not be equal. Never reset a higher floor to match.
   If catch-up/health fails, stop the rollout and preserve state for diagnosis.
5. Only then update the other Controller and repeat the same checks. The Leader
   may change; use observed roles, not an assumed permanent host assignment.
6. Keep P2P disabled until every Controller understands the new delivery prefix.
   Then provision the explicit TLS relay and configure account mode using the
   existing consensus-backed config mutation, preserving Access allow/deny.

Both installed Controllers already report revision floors/applied-index support;
this candidate retains those implementations. Do not run legacy checkpoint import,
restore, revision reconciliation or edit the Raft DB merely because an update is
available. Use the existing recovery procedure only for an actual diagnosed issue.

## Windows delivery

Candidate auto-update publication remains intentionally disabled, including a
stable `--version` override. After upgrading the server, generate fresh personal
Agent download links through its existing `bpc-agent create` mechanism. Download
and open the new prepared executable on an existing Windows PC to update it in
place: valid existing state is reused, preserving Device identity and keys.
The P2P window's enable button prepares an existing installation explicitly.
New installations sign into the same account; no host invitation acceptance or
ticket transfer is required. See [the pilot guide](p2p-windows-pilot.md).

The generic Agent executable in the CI artifact is not a prepared first-install
package. Do not copy state/key files between computers to make it install.

## Limits and recovery

The pilot remains one unrenewed <=60s TLS/TCP-relay session; native Windows/UI/UAC,
Wintun/routes/ACL/service and actual Moonlight/Sunshine acceptance remain pending.
This is a verified test artifact, not evidence of completed live acceptance.

The new canonical delivery prefix is additive. While it has not been used,
retain the previous pinned mesh bundle for recovery. After P2P delivery records
have been committed, an older mesh Controller does not understand that prefix;
do not downgrade the Controller or delete records/floors to force a rollback.
Use a compatible forward fix and the existing recovery documentation. Endpoint
Agent rollback preserves protected P2P trust/policy and Device/WireGuard identity.
No automatic rewind of live Raft/canonical state is introduced.
