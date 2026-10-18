# Development roadmap

Baseline: main `c00f265` (2026-10-18 inspection). This is a process roadmap;
existing feature branches are not claims of shipped main behavior.

| Order | Bounded task | Acceptance / owner role |
| --- | --- | --- |
| 1 | Establish Codex/ECC workflow and context | AGENTS, status, architecture index, ADR and invariant map reviewed; maintainer |
| 2 | Add race gate without replacing CI | Existing jobs retained; final PR CI including race passes; implementer/reviewer |
| 3 | Close verification gaps | Record Linux kernel/systemd, control-process and race results for exact revision; reviewer |
| 4 | Review site-router/mesh candidate separately | Compare candidate to main, specify ownership, source identity, route withdrawal and fail-closed behavior; planner |
| 5 | Validate approved mesh topology | Candidate-specific tests plus isolated Linux route/Access integration and rollback evidence; implementer/reviewer |
| 6 | Operational acceptance | Explicitly authorized test Nodes; WAN failover, DNS/MTU and persistent traffic reports; maintainer/operator |

Main already contains route ownership metadata and transport-path failover. Its
architecture explicitly defers the new site-router dataplane. Do not import a
mesh branch or mark it complete as part of documentation/process adoption.
Feature work starts with its own acceptance criteria and a small plan, not an
automatic rewrite of the current runtime.
