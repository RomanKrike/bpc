# Status and evidence

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
