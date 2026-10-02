# Pinned mesh test candidate

This is an unreleased test build. Live A–H acceptance is pending. It does not
change `main`, the stable release or `latest`. Use existing enrolled test Nodes
and an existing Windows Device, with management access outside the tested paths.

## Obtain or reproduce the candidate

Download `bpc-connect-dist` from the successful CI run of the candidate PR. Record
the CI run URL and commit SHA. The artifact's `release-dist` directory contains
the bundle, Windows/Linux binaries and `SHA256SUMS`. Match the source SHA in
`CANDIDATE.json` with the CI checkout SHA (PR CI checks out a merge commit).
The checksum file protects transfer integrity; obtain it from that trusted run,
not an unrelated download location.

To build locally on Linux with Git, Python 3.11+, Go 1.23.12, curl, GNU tar/gzip:

```bash
git clone https://github.com/RomanKrike/bpc.git bpc-candidate-source
cd bpc-candidate-source
git checkout --detach CANDIDATE_COMMIT_SHA
bash scripts/build-mesh-candidate.sh ../mesh-candidate
cd ../mesh-candidate
sha256sum --check SHA256SUMS
```

Replace `CANDIDATE_COMMIT_SHA` with the exact reviewed candidate commit, not
`main` or a mutable branch. The builder refuses tracked modifications, archives
only committed files, requires the completed Raft recovery baseline, and uses
an empty output directory. Version is `0.20.2-mesh.<full-source-sha>` (the base
version follows `pyproject.toml`). The manifest records Go toolchain and hashes
of every bundled file. Timestamps, ordering and ownership are normalized;
rebuilding the same commit with the same Go/tool dependencies produces the same
bundle. Go dependencies and Wintun are pinned. To use a cached original Wintun
ZIP, set `BPC_WINTUN_ARCHIVE` to its absolute path; its pinned hash is still checked.

## Verify and update one Linux Node

Use the updater from the candidate source tree for the first update: an older
installed updater does not understand `--bundle`. Python 3, PyYAML, cryptography
and existing BPC runtime dependencies must already be installed.

Before upgrading a legacy Controller, run `sudo bpc cluster backup` on the
healthy Leader, keep that private backup, and follow
[the Raft migration procedure](controlplane-replay.md). Upgrade one voter at a
time and verify quorum between Nodes. Do not roll back to a pre-watermark
Controller. Keep the latest accepted Gateway security receipts and identities.

From the trusted candidate source directory, with the downloaded archive nearby:

```bash
BUNDLE="$(realpath ../mesh-candidate/bpc-connect-deploy.tar.gz)"
EXPECTED_SHA="$(awk '$2 == "bpc-connect-deploy.tar.gz" {print $1}' ../mesh-candidate/SHA256SUMS)"
python3 scripts/verify-mesh-candidate.py "$BUNDLE" "$EXPECTED_SHA"
sudo bash deploy/bpc-update.sh --bundle "$BUNDLE" --sha256 "$EXPECTED_SHA"
cat /opt/bpc/current/VERSION
python3 -c 'import json; d=json.load(open("/opt/bpc/current/CANDIDATE.json")); print(d["source_sha"], d["go_toolchain"])'
sudo sha256sum /opt/bpc/current/bin/bpc-{controld,routed-node}-linux-$(dpkg --print-architecture)
sudo bpc status
sudo bpc cluster status
sudo bpc path list
sudo bpc route explain LAN_HOST_IP
```

Replace `LAN_HOST_IP` with the echo host. The local updater validates SHA256,
manifest, required runtimes and archive paths before activation. It rejects
links/special files, traversal and conflicting files for an existing version.
Updates are serialized; the release pointer is switched atomically. Migration
and health checks use the new release. The local path makes no release download.
Once a candidate is installed, bare `bpc-update` refuses the stable channel.

If candidate validation fails, exit code is 5 and the updater prints the previous
release path. The candidate and current state remain available for diagnosis;
there is no automatic database rewind. Same-version retry rechecks migration
and health instead of hiding the failure. This wrapper does not make a live
Bolt database backup; use the Controller's documented consistent backup.

To return to a **previous compatible mesh candidate**, retain its original bundle
and trusted checksum, then run:

```bash
sudo bpc-update --bundle /absolute/path/previous/bpc-connect-deploy.tar.gz \
  --sha256 PREVIOUS_TRUSTED_SHA256
sudo bpc status
sudo bpc cluster status
```

This switches application code and reconciles BPC-owned runtime while retaining
current identities, committed Raft policy, revision floors and Gateway deadlines.
Confirm both candidates use compatible state formats. Do not restore a stale
state archive or delete Gateway snapshots to force a downgrade.

## Existing Windows Device

Run PowerShell as Administrator, in the downloaded artifact directory, with
Python 3.11+. These commands preserve the existing `state.json` and enrollment.
The raw candidate binary has no enrollment bootstrap; use it for an existing
Device, not a fresh installation. Do not publish a candidate Agent auto-update
to other users. Keep the test Controller's auto-update manifest fixed during
acceptance so it cannot replace the tested binary.

```powershell
$bundle = (Resolve-Path .\bpc-connect-deploy.tar.gz).Path
$line = Get-Content .\SHA256SUMS | Where-Object { $_ -match '  bpc-connect-deploy\.tar\.gz$' }
if (@($line).Count -ne 1) { throw "Missing or duplicate bundle checksum" }
$sha = ($line -split '\s+')[0]
python .\candidate-source\scripts\verify-mesh-candidate.py $bundle $sha --extract .\verified
if ($LASTEXITCODE -ne 0) { throw "Candidate verification failed" }
$dir = "$env:ProgramData\BPC"
if (!(Test-Path "$dir\state.json")) { throw "Existing enrolled Device required" }
$backup = Join-Path $dir ("candidate-previous-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory $backup -ErrorAction Stop | Out-Null
Stop-Service BPCAgent -ErrorAction Stop
try {
  Copy-Item "$dir\bpc-agent.exe" "$backup\bpc-agent.exe" -ErrorAction Stop
  Copy-Item "$dir\wintun.dll" "$backup\wintun.dll" -ErrorAction Stop
  Copy-Item .\verified\bin\bpc-agent-windows-amd64.exe "$dir\bpc-agent.exe" -ErrorAction Stop
  Copy-Item .\verified\bin\wintun-windows-amd64.dll "$dir\wintun.dll" -ErrorAction Stop
} catch {
  if (Test-Path "$backup\bpc-agent.exe") { Copy-Item "$backup\bpc-agent.exe" "$dir\bpc-agent.exe" -ErrorAction Stop }
  if (Test-Path "$backup\wintun.dll") { Copy-Item "$backup\wintun.dll" "$dir\wintun.dll" -ErrorAction Stop }
  throw
} finally {
  Start-Service BPCAgent -ErrorAction Stop
}
& "$dir\bpc-agent.exe" version
Get-FileHash "$dir\bpc-agent.exe" -Algorithm SHA256
Get-Service BPCAgent
```

`candidate-source` is the checkout of the same reviewed candidate code. Preserve
the printed `$backup` path. To undo the Windows binary replacement, stop
`BPCAgent`, copy these two saved files back, and start `BPCAgent`; keep current
`state.json`. Do not use `uninstall` or enroll again. Windows execution and live
service behavior must be verified on your machine.

## Start the later live tests

On the LAN echo host, from the candidate source:

```bash
python3 scripts/acceptance-echo.py --listen LAN_HOST_IP --port 19090
```

On the connected Windows Device, start a healthy baseline:

```powershell
python .\candidate-source\scripts\acceptance-mesh-traffic.py --target LAN_HOST_IP `
  --scenario A --duration 90 --agent "$env:ProgramData\BPC\bpc-agent.exe" `
  --report .\evidence\A-traffic.json
```

Run B–H separately according to [the live scenario matrix](live-mesh-acceptance.md),
starting traffic before each controlled event and retaining timestamps and
before/during/after Node evidence. For quorum loss F use `--duration 420` or
longer to pass the actual original lease expiry. B/D traffic must keep both TCP
sockets; F deliberately denies traffic after expiry. Exact service/link fault
commands depend on observed Node addresses, ports and current Leader; never
guess them or stop the legacy home WireGuard link. Reports stay unreviewed until
the actual combined results are assessed.
