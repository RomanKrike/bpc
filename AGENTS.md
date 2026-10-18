# Working on BPC with Codex and ECC

Read this file, the nearest scoped AGENTS.md, [status](docs/STATUS.md), and only
the architecture/spec sections relevant to the task. Existing code and CI are
the baseline; verify claims against them before changing behavior.

- Keep one Node entity with composable capabilities. Keep User, Device, Node,
  Access, overlay identity and transport selection distinct.
- Preserve working transports, packet formats, canonical state and compatibility
  adapters. No opportunistic rewrites, dependency upgrades or global tool config.
- Unknown/external network objects must not be mutated. Preserve fail-closed
  routing and the Access enforcement boundary; see [invariants](docs/specs/INVARIANTS.md).
- Never commit credentials, private keys, live state or unredacted diagnostics.
- Use a short-lived branch and small coherent commits. No production deployment,
  live fault injection, release dispatch or merge without explicit authorization.

## Task -> plan -> implement -> verify -> record -> PR

1. Task: state the user-visible outcome, affected paths, acceptance criteria and
   non-goals. Read existing tests and CI before proposing new tooling.
2. Plan: list small changes, relevant invariant IDs, checks and rollback. Use a
   short PR/task note; create an ADR only for a durable architectural decision.
3. Implement: make the smallest compatible change. Codex is the implementer;
   use relevant installed ECC skills selectively, never require ECC to run BPC.
4. Verify: run [quality gates](docs/DEVELOPMENT.md). Record exact commands,
   revision, environment, failures and skips. A skipped test is not a pass.
5. Record: update STATUS for current evidence, ROADMAP for remaining work, specs
   for changed contracts and ADRs for decisions. Link existing docs, avoid copies.
6. PR: describe problem/result, scope, invariant coverage, checks and limitations.
   Keep release/deployment separate. Human maintainer owns acceptance and merge.

Planner, implementer and reviewer are roles, not mandatory separate agents.
The reviewer checks the diff and evidence independently of implementation claims.
Do not delegate or start parallel agents unless requested. Do not mandate a
particular model: select a Codex model available to the user for task complexity.
Prefer targeted searches/reads and focused checks during iteration, then the
required gates once on the final revision. Stop repeating passed checks unless
the change or new evidence warrants it.
