# Go runtime

Follow root AGENTS.md. Read the relevant package and tests before editing.

- `controlplane`: deterministic canonical mutations, preconditions, quorum and
  mTLS trust are contracts; never add runtime paths to replicated state casually.
- `agentctl`: transport changes must preserve Device/overlay identity and Access.
- `wgshim`: authenticated probes select paths; return WireGuard data confirms
  migration. Preserve bounded rollback and cryptographic protocol behavior.
- Run focused package tests while iterating, then Go tests, race, vet and
  formatting gates from docs/DEVELOPMENT.md. Keep real traffic acceptance tests.
