# Status and evidence

## Windows existing-session recovery (2026-10-20)

Baseline 27458d54fee59c75e5cafbc04cb6a78ad03dc8a8 / 0.22.1. Operator reported
installer timeout, then foreground failure opening an old Agent log. After a
targeted operator log permission repair, new starts were recorded and foreground
execution proved HTTP 401 invalid refresh credential. The installed binary was
still the unified mesh transition and reused a historic account Device profile.
No private state or keys were requested or received; no live PC access by Codex.

Task/plan: explicit installer sign-in for an expired/expiring saved account
session; use stored Controller trust and existing Device/Ed25519/WireGuard identity.
Add a distinct existing-only endpoint, never fall back to fresh registration.
Require active same-owner ID/key/WG binding; recovery must not rewrite Device
metadata and resurrect a concurrent revoke. Preserve Access, P2P consent/policy
and private keys. Validate response ID/address/config before stopping the old
service and replacing credentials. Failed/cancelled/old-server/mismatched recovery
must retain the old local file. Keep state replacement atomic without pre-unlink
and preserve existing Windows DACL before writing the temporary credential file.
Native install error dialog and runtime termination logging expose future failures.

Invariants SEC-02/04/05, MESH-01 and P2P-05/06/07. No Raft/schema/floor reset,
transport or Access rewrite, log ACL reset, background password prompts or removal
of old identities. Version 0.22.2 requires Controllers first, then a fresh prepared
EXE on the PC. Recovery is interactive and cannot revive a revoked/deleted Device.
Checks: Go real HTTPS proof/recovery and failure preservation, native Windows
protected-DACL/sharing-lock replacement, real public HTTP negative identity cases,
full existing CI/process/kernel/Windows gates. Native interactive acceptance is
still operator-owned; exact final verification is recorded at the PR.

Local Windows/Go 1.23.12 checks: Agent/client tests passed, including real HTTPS
recovery proof, old-server/revoked/mismatched/cancelled/stop-failure cases, saved
identity preservation and protected-DACL/sharing-lock tests on temporary files.
Ruff passed; 50 Python Agent checks passed; public HTTP recovery module explicitly
skipped locally because Controller imports require Linux. Full Linux process,
HTTP/security, race, kernel and packaged-Windows CI remains required. No real
Windows installation, service/network change or server deployment by Codex.

## Controller replica / owned gateway sandbox fix (2026-10-20)

Baseline: unified main aa3b5fd5500227bffce8d758fdae61265b72573d (0.22.0).
After an operator update, a public API replica on a Node also owning a local
WireGuard gateway repeatedly exited in sync_wireguard_peers with EAFNOSUPPORT.
Raft retained healthy quorum and zero lag; the API never opened its HTTPS port.
The replica unit allowed AF_INET/AF_INET6 while the owned-gateway startup path
requires AF_NETLINK. Operator applied a named systemd drop-in adding only that
family and restarted only the API. Reported health/API and local WG recovered;
older failures remained in the historical journal. No production access by Codex.

Task/plan: add AF_NETLINK to the replica installer, preserve all other sandbox
and ownership/Access behavior (SEC-02/03/04/05), reproduce the old filter and
exercise the new installer value with real systemd/WireGuard in an isolated
namespace. Keep root integration in CI; never target an existing host interface.
Version 0.22.1 packages the correction for ordinary updates. No schema, Raft,
floor, key, migration, transport selection or Access-policy rewrite. The earlier
RU-only migration tail is not changed: Controller runtime reconciliation already
refreshes enrolled replicas before that tail. Full final CI remains required.

The operator subsequently reported healthy API, both mesh paths healthy with
zero observed loss, quorum 2/2 and zero replication lag after the drop-in. This
is operator-reported recovery, not a broader WAN/session acceptance claim.
Local Windows verification: 65 focused Python checks and Ruff passed; two real
systemd/netns cases explicitly skipped on Windows. Bash syntax and diff checks
passed. Runtime change is confined to the generated replica address-family list.

## Unified mesh/P2P release 0.22.0 (2026-10-20)

Maintainer requested unification after the incompatible stable/mesh update was
identified. Baselines: stable 2882dfcaafb977af6a8f842bc3da87e3af1c288f and
mesh/P2P 4b08a16c6fa0f556b266135cfd6472d45d98c587. Previous candidate #98
passed all 12 jobs in run 39384503627; its archive passed both current and
original 8c1abba verifiers. That evidence does not cover the changes below.

Task/plan: preserve both mesh recovery/topology and stable jitter/UI fixes;
unify packaging and version 0.22.0; verify complete stable manifests, reject
incompatible/downgrade downloads, preserve live state on failure; build a separate
old-verifier-compatible transition artifact. Cover bridge -> bare stable update,
repeated update, missing runtimes/profile, downgrade and failed-health state
preservation in temporary root-owned fixtures. Retain every CI gate, test both
packaged Windows versions and validate the real transition using the old verifier.

Scope/invariants: updater, packaging/CI, version and docs; SEC-04/05/06,
MESH-01/02 and P2P-01..07 remain mandatory. No Raft/store/checkpoint/schema
rewrite, state rewind, Node/Device/key change or network ownership adoption.
See ADR 0006 and [update/recovery procedure](unified-release-update.md).
No live install, fault, restart or Windows service/network mutation is authorized
or performed by this implementation. Merge/release is requested separately from
production rollout. Final revision verification is pending below/at the PR.

Local verification (Windows, Go 1.23.12/Python 3.12): 88 targeted Python tests
passed; 13 POSIX-root updater/publication cases skipped with an explicit reason.
Ruff passed; Agent, agentctl and wgshim tests passed, including the retained
jitter/healthy-migration regressions. Linux-target go vet ./... passed. Bash
syntax and git diff --check passed. Initial Agent source assertion expected the
old idle-handshake cutoff; restored the already tested stable assertions alongside
the stable UI fix. Git comparison confirms no change from #98 to routed,
controlplane/controld, topology, Node enrollment or Access implementation.
Full Linux/race/privileged/process and packaged-Windows checks remain CI gates;
local socket tests required sandbox elevation but mutated no host network.

## Mesh-compatible P2P candidate: task and plan (2026-10-20)

Installed baseline: 8c1abbaf454261fc500f788370ffb54bb70f265e, reported by
both live Controller diagnostics. The two-voter cluster is healthy, caught up,
and serves real direct and indirect mesh paths. Stable 0.21.0 is not a compatible
replacement: it lacks routed topology and the candidate Raft replay safeguards.
Do not remove CANDIDATE.json or bypass the pinned-bundle updater.

Task: transplant P2P/account UI from released 0.21.0 onto this exact mesh base,
then build a pinned test candidate without modifying main/latest or live hosts.
Preserve routed runtime, topology prefixes, revision/applied-index/floor handling,
route ownership, existing Access enforcement, update guards and signed-update
validation. Add only the P2P delivery prefix, endpoint runtime, APIs and UI.
Existing mesh and all P2P/Windows/race/Access/process CI gates must pass together.
Candidate Windows binaries must report the complete injected bundle version;
existing candidate auto-update publication remains disabled.

Plan: retain governance from stable; three-way apply only the P2P delta against
its original stable baseline; resolve overlap in favor of preserving mesh
contracts; add both routed and P2P packaging/verification; run focused checks,
then full combined CI and artifact verification. Restore no live state and
perform no remote installs/restarts. The two voters both count toward quorum;
any one restart temporarily prevents writes. Operators need a consistent leader
backup and the existing candidate upgrade/rollback procedure. Existing rollback
must never rewind the Raft DB or security floors. Native Windows/real streaming
and operational candidate acceptance remain pending, independently of CI.

The stable-release history below is evidence for the source being transplanted,
not a statement that these servers are on stable or that mesh was removed.

Implementation: three-way P2P-only transplant from the original stable baseline,
retaining both topology and P2P modules in primary/replica staging. Raft's Go/Python
canonical prefix lists each gain only `control/p2p-delivery/`. Source comparison
against 8c1abba confirms unchanged routed runtime, topology, Access, Controller
replay/store/checkpoint/reconciliation, Node enrollment, gateway snapshots and
candidate updater/Agent publication guard. Agent retains injected full bundle
version and signed-update executable-version validation. Packaging includes both
routed and P2P runtimes and conditionally requires P2P relay binaries while still
accepting older complete mesh bundles for verification. CI retains both meshes'
kernel/recovery and the stable P2P/race/Windows gates, plus packaged-Windows version.
See [operator procedure](mesh-p2p-update.md).

Local Windows / Go 1.23.12: Agent, agentctl and p2p tests passed. Python Agent
checks: 50 passed; Ruff passed. Linux-target `go vet ./...` and Linux amd64
controld/routed/P2P relay builds passed. Windows Agent builds with the candidate
version injected and reports `0.21.0-mesh.local-check`; formatting/diff passed.
The mesh controlplane tests fail on Windows directory fsync and filesystem
projection behavior; implementation of those paths is byte-identical to the mesh
baseline. Python authority/policy tests cannot collect locally because the mesh
gateway snapshot imports Linux fcntl; mesh installer tests also use os.geteuid.
These are recorded limits, not passes. Full combined Linux/Windows CI and pinned
artifact verification remain required before supplying an update command.


## Release 0.21.0 preparation (2026-10-20)

The maintainer explicitly requested a release. #95 merged as
`aba8c4711ba99c978c72c87a7e1e3ab00e7cb4a8`; #96 merged as
`a2582c907e72c3eb0f064490306d4014eebdac39` (release-branch baseline).
The retargeted #96 merge tree matched its tested head exactly. #95 passed
[nine jobs](https://github.com/RomanKrike/bpc/actions/runs/39376264479); #96
passed [all ten jobs](https://github.com/RomanKrike/bpc/actions/runs/39380269517),
including Windows Agent/client/script parsing, Linux race and real Raft/mTLS.

Release scope: bump package and Windows Agent together to 0.21.0, guard version
agreement, and publish the matching CHANGELOG section in automatic release notes.
The Agent previously still advertised 0.16.2 while the package was 0.20.2.
The version change goes through a tested PR; successful main CI triggers the
existing Release workflow. No manual workflow dispatch, server/Agent deployment,
signed update publication or P2P enabling is performed by this release task.
Real Windows/two-PC acceptance remains pending and is stated in release notes;
P2P stays experimental and explicitly enabled only. See the pilot guide and
ADR 0005 for all-Controller upgrade order and downgrade constraints.

Release preparation local checks: Ruff and 51 Agent Python checks passed;
Windows Agent builds and `version` reports 0.21.0. Executing the release-note
extraction from the workflow produced only the matching changelog section with
the experimental limits/upgrade instructions. Formatting and diff checks passed.
The full required CI runs on the version PR and again after merge on main.

## Account P2P delivery and Windows window (2026-10-20)

Candidate based on #95 head da3c7edc4d4b0769409afb144b4941d2c10c18fd;
no merge, release dispatch or deployment. [ADR 0005](adr/0005-account-p2p-delivery.md)
records the user-requested no-invitation flow and explicit canonical-prefix change.
Reuses the existing prepared HTTPS executable/download and tray UI. Fresh account
enrollment in explicitly configured account mode initializes trust and signs
consent; repeated install/restart does not restore withdrawn consent. Existing
Agents can explicitly prepare/restart from the window with service image/argument
ownership checks. Controller provides authorized peer list, CAS-protected public
delivery slots for both Devices and authenticated own-slot polling across replicas.
Receiving Agents verify signed grant and local Device/WG/address bindings before
creating an ordinary policy-enforced request. No file transfer or host invitation
acceptance is needed. The UI reports requested, not established.

Local Windows Go 1.23.12: `go test ./cmd/bpc-agent ./internal/agentctl -count=1
-timeout=120s` passed, including PowerShell AST parsing (no UI execution),
preparation without service mutation, missing-store refusal and foreign-service
command-line rejection. `internal/controlplane` and `internal/p2p` passed in the
focused suite; existing wgshim `TestAdaptiveTransportSelectsFasterTCP` failed its
3s timing assertion on Windows, including one isolated retry. No transport code
changed and the failure is recorded, not counted as a pass. Linux CI is required.
Ruff passed. `pytest tests/test_p2p_delivery.py tests/test_p2p_authority.py
tests/test_agent.py --basetemp=../p2p-account-final -ra`: 78 passed / 1 skipped
(Go wire binary supplied by Linux CI). Linux-target `go vet ./...`, Windows
Agent build and `gofmt -l cmd internal` passed. The initial restricted run failed
on sandbox temp-file rename/loopback restrictions; local tests then ran with
workspace temporary files and isolated loopback outside that sandbox.

The existing full CI remains mandatory; an additional Windows Agent/client and
embedded-window parser job is included. Real public HTTP and three-Controller
Raft/mTLS tests now exercise account delivery and quorum loss. CI evidence will
be linked from the PR. Native window interaction/UAC, Wintun/routes/ACL/service
restart and Moonlight/Sunshine streaming remain PENDING. No test host was changed.
The pilot still expires in <=60s, retains at most 16 peer deny reservations and
rejects a new delivery while its slot is unexpired. Controller/relay provisioning
and enabling account mode are operator steps; an existing old download link is
not silently upgraded by this source change. Long-stream renewal is pending.

## Windows P2P pilot runtime (2026-10-20)

Authorized merges: #93 -> d939bffb6aa4c4a04b36df22fe1eb40490dd1081;
#94 -> aecf34e7ddec15135b3fd4c352b72d367f78dade (this task baseline).
The retargeted #94 merge tree matched its tested head. Main CI subsequently
passed: [39329400368](https://github.com/RomanKrike/bpc/actions/runs/39329400368).
Existing Release automation ran after main CI; no workflow was manually
triggered and no host/install/service/network mutation was performed here.

[ADR 0004](adr/0004-p2p-windows-pilot-runtime.md) specifies the bounded task,
invariants, compatibility and rollback; [operator guide](p2p-windows-pilot.md).
Implemented explicit Agent trust/consent/request/start/stop commands, a policy
polling lifecycle, shared-adapter endpoint filters and durable peer deny
reservations restored before gateway startup. Default (uninitialized) gateway
path uses its original TUN unchanged. Only current-adapter GUID/index /32 routes
may be added; conflicting routes are refused. An explicit standalone TLS relay
pilot command is included in the Linux amd64/arm64 bundle and cross-build gates.

This is one active, unrenewed <=60s pilot session, with up to 16 retained peer
reservations. Native Wintun/NetTCPIP, ACL, service and actual Moonlight/Sunshine
acceptance remain PENDING; no actual Windows route/adapter tests ran. Automatic
ticket delivery, coordinated long-stream renewal, relay service provisioning,
UI and UDP/NAT traversal remain pending. An initialized missing/corrupt store
prevents overlay startup; do not reset it to bypass trust/revision floors.

Published runtime/CI source: `87e51313064020cd7b84738cf87241634804b862`.
Local Windows amd64, Go 1.23.12 / Python 3.12; local tested commit a9c4b05
followed only by docs/package comments in d3fee33. `go test ./... -count=1 -timeout=120s`
passed Agent, pilot relay, agentctl, controlplane, p2p and wgshim; the overall
native Windows run still FAILS at pre-existing Linux-only syscall.Kill in
controld. `go test -race ./internal/p2p` is unavailable locally (CGO absent);
Linux CI remains required. `pytest tests/test_agent.py --basetemp=../p2p-stage3-agent-temp
-q` passed 50 tests; `ruff check .` passed. `gofmt -l cmd internal`, `git diff --check` and
`GOOS=linux GOARCH=amd64 go vet ./...` passed. Existing cross-build matrix
passed with CGO_ENABLED=0, plus new pilot relay Linux amd64/arm64.
`go test -c -o ../cross-build/p2p-stage3-windows.test.exe ./internal/p2p` and
`BPC_P2P_TEST_BINARY=<that binary> pytest tests/test_p2p_authority.py
--basetemp=../p2p-stage3-contract-temp -q` passed 18 tests including Python-issued
wire compatibility with the new durable reservation state.

Published head e602f6d66d67bed0faa0dfb52111825258add1f0 passed all nine Linux
CI jobs: [39375921357](https://github.com/RomanKrike/bpc/actions/runs/39375921357).
This includes Go tests/vet/cross-builds, race, Python 3.11/3.12/3.13,
control-runtime, privileged Access/systemd rollback, ShellCheck and packaging
with both new relay binaries. Python 3.11: 336 passed / 6 skipped; dedicated
control-runtime executes the process/wire cases: 20 passed. This evidence-only
record follows that successful runtime; native Windows acceptance remains pending.

Actual userspace HTTPS policy/TLS relay/WireGuard TCP+UDP acceptance passes
signed denial, Controller failure, idle expiry and expiry during blocked sync.
The blocked-sync fixture initially waited for HTTP cancellation before reading
the request body, causing httptest.Close to hang; it now consumes the body and
has an explicit test-only cleanup release. The runtime expiry watcher was not
weakened. An initial handshake test assumed simultaneous peer arrival; removed
unnecessary keepalive on the loopback UDP bridge and synchronized the test peers.
Tests also cover local key/address mismatch before route/network changes,
queued/malformed peer isolation from gateway, bounds, durable local stop and
reservations, and bootstrap refusal on missing initialized state.

## P2P Controller authority (2026-10-20)

Runtime/CI revision `a402f9315a8a9ab1035bb81d57641d940410beea`.
Stacked on draft #93 at `042b81504a323b53544722dcfa593cc19f1f9e64`; main
remains unchanged. [ADR 0003](adr/0003-p2p-controller-authority.md) records the
task, API, invariants, compatibility, costs and rollback.

Implemented default-off Controller info/consent/issue/sync APIs, exact-state
Raft authorization fences, same-owner Access and both-Device consent, client
methods and a durable endpoint policy verifier. Signed denials and revision/time
floors survive restart; cached allows do not. Managed receiving-host filtering
stops established TCP/UDP after a signed denial, even with an unfiltered peer.
Runtime staging includes the new Python module on primary and replica. No new
FSM operations, state prefixes, dependency, gateway path or installed Agent
enabling. Polling/renewal, Windows ownership/Wintun, NAT and product acceptance
remain pending. A committed consent change is not an endpoint enforcement ack.

Local Windows amd64 / Go 1.23.12, Python 3.12: `ruff check .`,
`gofmt -l cmd internal`, `git diff --check` passed.
`go test ./internal/p2p ./internal/agentctl ./internal/controlplane ./internal/wgshim
-count=1 -timeout=120s` passed. The final full Go run also passed these packages
and Agent; overall native Windows failure remains the pre-existing Linux-only
`syscall.Kill` in controld. Local race requires CGO, unavailable here.

`go test -c -o ../cross-build/p2p-authority-windows.test.exe ./internal/p2p`
and `BPC_P2P_TEST_BINARY=<that binary> pytest tests/test_p2p_authority.py
tests/test_p2p_http.py tests/test_agent.py --basetemp=../p2p-stage2-final-temp -q`
passed 68 tests, including the Python-issued grant/checkpoint accepted by Go;
HTTP module skipped on Windows (Linux fcntl dependency). Socket/DB tests ran
with loopback and workspace temporary files outside sandbox restrictions.
`GOOS=linux GOARCH=amd64 go vet ./...` and the existing CI cross-build
matrix passed locally (CGO_ENABLED=0; WGShim Linux amd64/arm64 and Windows
amd64; relay/controld Linux amd64/arm64; Agent Windows amd64).
`pytest tests/test_identity.py tests/test_gateway_snapshot.py tests/test_config.py
--basetemp=../p2p-existing-policy-temp -q` passed 15 tests. Adding the existing
Access suite stopped collection on Windows because it imports Linux fcntl;
this is not an Access pass.

Real Linux public HTTP and three-process Raft/mTLS acceptance, including
quorum-loss rejection, are added to control-runtime CI; until observed they
are pending, as are the full existing Linux gates. No infrastructure changed.

Initial Linux CI on `0601de2` exposed one stale deployment-test fixture:
its isolated runtime copy omitted the new bpc_p2p module, although both actual
installers already staged it. Updated that fixture; no test gate was weakened.
The initial Python run had 335 passes / 6 skips and this failure. Final CI
results below supersede that failed run once observed.

Linux CI on `66043605b25396b787833a8706441fceee525d03` subsequently passed
all nine jobs: Go tests/vet/cross-builds, race, Python 3.11/3.12/3.13,
control-runtime, privileged Access/systemd rollback, ShellCheck and packaging.
[Run 39326476714](https://github.com/RomanKrike/bpc/actions/runs/39326476714).
Python 3.11 reported 336 passed / 6 skipped; the dedicated control-runtime job
executes the otherwise skipped process and cross-language cases (20 passed,
including public HTTP). No runtime changes follow that successful revision;
this evidence-only update is also subject to the unchanged CI workflow.
This remains isolated/userspace evidence, not installed Windows streaming.

## Device P2P foundation (2026-10-20)

Baseline: main `ef947e751315885d1196e97391d9139eed973480`. Contract commit
`f0f9ef0`; implementation/tests `512f7ff` (same source tree as locally tested
`0b81714`). See
[ADR 0002](adr/0002-device-p2p-session-boundary.md) and
[remaining stages](ROADMAP.md#moonlight--sunshine-device-p2p-2026-10-20).

Implemented an isolated `internal/p2p` package: same-owner signed grants with
60-second maximum lease, TLS 1.3 relay with Device key proof bound to its TLS
channel, bounded opaque WireGuard forwarding, and plaintext endpoint filtering.
There is no production caller, installed listener, Controller grant API, Windows
UI, direct/NAT traversal, or schema/dependency change. This is a foundation
prototype, not an enabled Moonlight/Sunshine feature.

Local environment: Windows amd64, Go 1.23.12. Test keys/addresses are synthetic.
Socket tests ran outside the restricted sandbox with workspace temporary files;
the sandbox's initial loopback/temporary-file errors are environment failures.
No OS routes, firewall rules, installed clients or real infrastructure changed.

| Check | Observed result |
| --- | --- |
| `go test ./internal/p2p -count=1 -timeout=60s` | Passed, including real userspace WG/TLS/TCP/UDP, malicious unfiltered initiator, forbidden host port, established-flow host revoke, idle lease expiry, proof replay and bounded/concurrent policy tests |
| `go test ./... -count=1 -timeout=120s` | Agent, agentctl, controlplane, p2p and wgshim passed; overall FAILED because existing controld uses Linux-only `syscall.Kill` on Windows |
| `GOOS=linux GOARCH=amd64 go vet ./...` | Passed; cross-platform static check, not Linux runtime evidence |
| `go test -race ./...` | Unavailable locally: `-race requires cgo`; Linux CI must pass it |
| `go test ./internal/p2p -run='^$' -fuzz=FuzzUntrustedGrant -fuzztime=10s -parallel=2` | Passed, 39,751 executions; bounded run, not exhaustive parser proof |
| `gofmt -l cmd internal`; `git diff --check` | Passed after CRLF-only checkout normalization; no changes to existing Go sources |
| Existing CI cross-build matrix | Passed locally: WGShim Linux amd64/arm64 and Windows amd64; relay/controld Linux amd64/arm64; Agent Windows amd64 |
| P2P test cross-compilation | Passed for Linux amd64/arm64 and Windows amd64; cross-compilation is not execution |

The first relay framing test exposed a test-only telemetry timing assumption:
the receiver can finish reading before the relay increments its byte counter.
The test now waits for that asynchronous counter, without changing forwarding.

Follow-up review requires canonical Base64 encodings for identity and WireGuard
keys. This prevents alternate whitespace/newline spellings of the same key from
bypassing the distinct-participant key comparison. Added regression cases and
re-ran P2P tests plus `go vet ./internal/p2p`: passed. The full-suite/fuzz and
cross-build observations above describe the initial foundation; final Linux CI
must also cover this validation-only follow-up on the PR head.

Full Linux Python/Go/race, process, privileged Access/systemd and cross-build jobs
remain required on the PR head. CI evidence is recorded separately after it is
observed. This localhost acceptance does not establish real Sunshine streaming,
Windows Wintun integration, WAN latency, NAT reachability or stream continuity.
Persistent revocation/revision reconciliation and Controller authorization are
mandatory before installed Agent enabling. No merge, deployment or release was
performed by this change.

The host initially blocked publishing pending explicit user authorization to
send the implementation to GitHub. The user subsequently authorized this branch
push and a draft PR for CI, without merge, deployment or release. CI results on
the published PR head must still be observed before claiming those gates pass.

Linux CI was subsequently observed successful on runtime revision
`cc82d5b3e549855b71b329b665491b020185d880`:
[run 39321630146](https://github.com/RomanKrike/bpc/actions/runs/39321630146).
All nine jobs passed: Go tests/vet/cross-builds, race, control-runtime,
access-kernel-rollback, Python 3.11/3.12/3.13, ShellCheck and packaging. This
status-only evidence record follows that tested runtime; no runtime source
changes follow the successful run. It remains userspace/isolated Linux evidence,
not installed Windows or real Sunshine/NAT acceptance.

## Inspected baseline

2026-10-18: main `c00f265e4a0e464e15fa3804ef4adca3b5be1803`, package
version 0.20.2. No tracked AGENTS.md existed. Reviewed README, canonical
architecture, distributed control plane, Access/revoke rollback, transport paths,
test plan, Go module, Python project, CI/release workflows and related code/tests.

Existing CI: Python lint/tests/config rendering (3 versions), Go formatting,
tests/vet/cross-builds, ShellCheck, control daemon process integration,
privileged Access/systemd rollback and package/deployment-bundle builds.

## This change

Adds scoped agent guidance, task/role/gate process, roadmap, architecture links,
invariant-to-test map and an ADR. Adds race coverage alongside existing CI.
No runtime/config/schema/dependency/release behavior is intentionally changed.
Runtime/configuration sources and dependency files are unchanged from baseline.

## Local verification (Windows, Go 1.23.12 / Python 3.12)

Tested process/docs/CI changes through `6918d0c`; this status-only record follows.

| Check | Result |
| --- | --- |
| `ruff check .` | Passed |
| Selected existing Python tests below | 65 passed with workspace `--basetemp` |
| `bpc-connect validate config/gateway.example.yaml` | Passed, fail-closed |
| `bpc-connect render config/gateway.example.yaml -o build/mihomo/config.yaml` | Passed |
| Go formatting | Passed after normalizing Windows checkout CRLF to LF in memory; no Go source edits |
| `GOOS=linux GOARCH=amd64 go vet ./...` | Passed (cross-platform static check) |
| `go test ./...` | Internal agentctl/controlplane/wgshim and cmd/bpc-agent passed, including userspace network acceptance; overall failed because Windows cannot compile controld's existing `syscall.Kill` |
| Native `go vet ./...` | Same existing Windows controld compile limitation |
| `go test -race ./...` | Could not run: Windows environment has no CGO C compiler |
| Full `pytest --cov=bpc_connect --cov-report=term-missing` | Collection stopped: 9 Linux-dependent modules import unavailable `fcntl` |
| New Markdown relative links; `git diff --check` | Passed |

Selected command: `pytest tests/test_config.py tests/test_validation.py tests/test_xray.py tests/test_identity.py tests/test_node.py tests/test_stage45_architecture.py tests/test_stage45_migration.py tests/test_gateway_snapshot.py tests/test_clash_failover.py --basetemp=../pytest-bpc-portable --tb=short -q`.
The first selected run hit a sandbox temporary-directory permission error;
using an explicit workspace temporary directory resolved it. Raw Windows
`gofmt -l` lists CRLF checkout files; LF-normalized content passes unchanged.

Full Linux tests, race, ShellCheck, process, privileged namespace/systemd and
cross-build/bundle checks require the PR CI result. No operational fault,
production deployment or release was run. Check the PR's exact head revision;
local subset success must not be reported as a full green CI run.

## Remaining limits

Site-router mesh implementation is separate from main; no merge or deployment
is included. Loopback acceptance is not production-network evidence. Namespace,
systemd and real Windows/Wintun/VPS acceptance need their supported environments.
See [roadmap](ROADMAP.md) and [quality gates](DEVELOPMENT.md).

## Follow-up: Windows Connect transient Wi-Fi jitter (2026-10-18)

Source baseline: main `745ffb357c594a65de9f48b7796a2bcb8e8091b4`.
Reported Windows reproduction: typing `\\` in Explorer raised router RTT from
approximately 3 ms to 343 ms **with both BPC and an unrelated WireGuard tunnel
disconnected**. The underlying Wi-Fi latency spike is independent of an active
BPC tunnel; no BPC service logs from the reproduction are available.

Code inspection found two application-level contributors:

- `internal/wgshim/path.go` previously bypassed its consecutive-failure
  threshold when selecting a warm standby; one fully missed 400 ms probe
  round could force a cross-node handoff. The fix applies the same threshold
  to reachability, selection and migration fallback.
- `cmd/bpc-agent/ui_windows.go` previously changed `Connected` to
  `Connecting` solely when the last WireGuard handshake aged past 180 s,
  even with a live local adapter. The fix treats a prior handshake plus
  current adapter telemetry as established, then reports `Degraded` after
  15 s of missing authenticated relay reachability.

Regression coverage: `internal/wgshim/path_test.go` tests isolated probe
loss, sustained failure and recovery without path flapping. The existing
userspace failover and make-before-break acceptance tests remain required.

**Verification status:** CI and Go tests on this branch have not yet been
observed; Windows UI behavior, real packet continuity and Wi-Fi-triggered
reproduction remain unverified. No production deployment, release or main
merge has been performed. Human reviewer should check new status semantics
and the path convergence/latency tradeoff (MESH-01/MESH-02).
