# Status and evidence

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
