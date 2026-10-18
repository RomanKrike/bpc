# Development and quality gates

The workflow is task -> plan -> implement -> verify -> record -> PR; role and
scope rules live in [AGENTS.md](../AGENTS.md). This adapts the requested ArtCraft
style of explicit context, bounded tasks and recorded verification. The original
discussion's substantive answer was unavailable; no specific ArtCraft model or
implementation is asserted. ECC is optional guidance, not a project dependency.

## Gate matrix

`.github/workflows/ci.yml` is executable authority. Run from the repository root
with Go 1.23.x (module minimum 1.23.1) and Python 3.11+; CI covers 3.11/3.12/3.13.

| Change | Required checks before merge |
| --- | --- |
| Every PR | Existing CI, diff review, accurate docs and no credentials |
| Go/runtime | `gofmt -l cmd internal` must print nothing; `go test ./...`; `go test -race ./...`; `go vet ./...`; existing cross-build matrix |
| Python/config | `pip install -e '.[dev]'`; `ruff check .`; `pytest --cov=bpc_connect --cov-report=term-missing`; example validate/render in CI |
| Shell/install | Existing ShellCheck job; relevant Python deployment/contract tests |
| Control state/auth | Go controlplane suite plus `control-runtime` process/mTLS job |
| Access/firewall/probe | Python policy tests plus `access-kernel-rollback` namespace and systemd job |
| Path/mesh routing | Invariant mapping below, loopback WGShim acceptance and affected control/Access checks |

CI includes all existing jobs even for documentation PRs. Race runs separately
with a bounded timeout; CI's Linux toolchain supplies CGO support. Do not weaken
an existing gate to make an unrelated change pass. Record baseline failures and
environment limits distinctly. Branch protection is configured by maintainers;
documented gates alone do not make GitHub checks required.

## Network verification levels

1. Unprivileged loopback: `go test ./internal/controlplane ./internal/agentctl ./internal/wgshim`
   covers real Raft/mTLS and userspace WireGuard responders.
   For path work run `go test -race ./internal/wgshim -count=1 -v` and inspect
   independent-node and make-before-break tests. These also run in the full suite.
2. Process integration (Linux CI): build `go build -o /tmp/bpc-controld ./cmd/bpc-controld`,
   then `BPC_CONTROLD_BINARY=/tmp/bpc-controld pytest tests/test_control_processes.py -s`.
3. Privileged isolated Linux: use the exact `BPC_TEST_NETNS=1` and
   `BPC_TEST_SYSTEMD=1` commands from `access-kernel-rollback`. Without these
   switches the corresponding tests skip. Windows cannot substitute for them.
4. Operational acceptance: [transport paths](transport-paths.md),
   [public node acceptance](public-node-acceptance.md) and
   [test plan](test-plan.md). These require a separately authorized test topology,
   management access and rollback. They are not default CI or permission to stop
   a production relay, update a host or reboot it.

Record localhost timing as observations, never WAN guarantees. Existing NAT or
conntrack state on a failed gateway is not replicated. Passing loopback tests
does not establish production TCP continuity or full mesh availability.

## PR evidence

Include outcome/non-goals, baseline and tested commit, affected invariant IDs,
commands and results, skips with reasons, remaining risks and rollback. Use small
commits for rules/process, architecture/contracts, and CI respectively. Record a
new failure once, diagnose it, and avoid repeated broad runs without a reason.
Do not trigger release.yml manually. Main CI success can trigger the existing
release workflow, so keep this work on the PR branch until maintainer review.
