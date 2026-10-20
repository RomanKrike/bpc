# Development roadmap

Current work: unify mesh and P2P into stable 0.22.0 with a verified one-time
candidate transition and guarded ordinary updates. See [procedure](unified-release-update.md)
and ADR 0006. Operational mesh and Windows streaming acceptance remain pending.

Previous candidate context: P2P was transplanted onto the installed mesh
commit 8c1abbaf454261fc500f788370ffb54bb70f265e, preserving routed topology and
watermarked Raft recovery. See [candidate update](mesh-p2p-update.md) and STATUS.
The stable-branch history below does not authorize replacing an active mesh
server with a stable bundle or claim native operational acceptance.

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

## Moonlight / Sunshine Device P2P (2026-10-20)

Windows-to-Windows is the requested first platform. Scope and acceptance live in
[ADR 0002](adr/0002-device-p2p-session-boundary.md), rather than changing the
existing gateway path contract.

| Stage | State / remaining work |
| --- | --- |
| Session foundation | Merged #93; isolated signed-grant, TLS relay and endpoint filtering, userspace WG TCP/UDP acceptance |
| Controller integration | Merged #94; default-off APIs/client, committed Access/consent fences, signed checkpoints and durable revision/revoke state |
| Windows runtime | Explicit bounded pilot: pinned trust, policy polling, shared-adapter filtered peers, durable deny reservations and owned /32 route plans; native Windows acceptance, coordinated long-session renewal/delivery and relay service lifecycle remain pending |
| Direct transport | Pending: UDP relay, same-socket STUN/ICE, data-confirmed switching and rollback |
| Account delivery / UI | Implemented candidate: existing HTTPS prepared Agent, first-login setup in explicit account mode, owned-device list, same grant delivered to both Agents, no invitation acceptance; CI/native acceptance tracked in STATUS |
| Product acceptance | Pending: real Windows UI/UAC and Moonlight/Sunshine, NAT/MTU/suspend/restart/offline tests |

The foundation is not a shipped P2P feature. Existing mesh candidates, production
deployments and release actions remain separate work.
