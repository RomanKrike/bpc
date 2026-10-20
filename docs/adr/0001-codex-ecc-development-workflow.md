# ADR 0001: Repository-owned Codex/ECC workflow

Date: 2026-10-18. Status: proposed for maintainer acceptance in this PR.

## Context

BPC already has working transports, canonical state, safety boundaries and CI,
but no tracked agent instructions or compact current-work/evidence entry point.
The requested ArtCraft-style process needs durable context and small verifiable
tasks without importing a framework or guessing an unavailable original model.

## Decision

Keep instructions and contracts in the repository. Use scoped AGENTS.md,
ROADMAP/STATUS, the existing architecture with development links, and test-linked safety
invariants. Use task -> plan -> implement -> verify -> record -> PR with human
acceptance. Codex implements; relevant ECC skills are optional aids. Planner and
reviewer are roles, with no mandatory agent fan-out or fixed model.

Retain existing CI and add Go race checks. Keep operational network fault tests
separate from loopback and isolated privileged CI. No production rollout follows
from this process change.

## Consequences and alternatives

Small context reads and focused iteration reduce token use. Documentation must
change with contracts, and every result must name its revision/environment.
A copied framework, duplicated architecture and mandatory multi-agent pipeline
would add drift and operating cost; an instructions-only change would leave the
race gate unenforced. Branch protection and runtime mesh work remain separate.

Rollback: revert the process/docs and additive race job commits; no state or
network migration is required.
