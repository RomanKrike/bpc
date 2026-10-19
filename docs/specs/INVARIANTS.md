# Safety and mesh-routing contracts

Scope: inspected main `c00f265`. MUST statements are review obligations. Test
references identify existing evidence locations, not a claim that every negative
case is exercised or that a new revision passed. Add a regression when behavior
changes; label missing coverage in the PR and STATUS.

| ID | Contract | Implementation / existing verification |
| --- | --- | --- |
| SEC-01 | Work underlay MUST fail closed with no automatic DIRECT escape when transports fail. | `src/bpc_connect/config.py`, `mihomo.py`; `tests/test_config.py`, `test_validation.py`, `test_clash_failover.py`; real outage/DNS proof remains operational |
| SEC-02 | Access MUST default deny; any matching deny overrides allow; revoked/disabled Devices have no effective routes. Client AllowedIPs MUST NOT substitute for server enforcement. | `deploy/bpc_access.py`; `tests/test_access.py`, `test_access_kernel.py` |
| SEC-03 | Successful local Access reconciliation MUST revoke managed established traffic in both directions, including revoked responders/retired addresses, while preserving authorized replies. A consensus commit alone MUST NOT be reported as enforcement acknowledgement. | `tests/test_access_kernel.py`, `test_access.py`; [revoke limits](../access-revoke-rollback.md) |
| SEC-04 | Unknown/external interfaces, routes and firewall objects MUST NOT be mutated; expected names are insufficient ownership. Migration MUST preserve backups, refuse conflicting state and remain idempotent. | `src/bpc_connect/ownership.py`, `compat/migration.py`; `tests/test_stage45_migration.py`, `test_bootstrap_ownership.py` |
| SEC-05 | Canonical security mutations MUST use consensus/preconditions; quorum loss MUST reject writes. Controller trust MUST bind cluster, membership and certificate. | `internal/controlplane`; FSM, TLS, Raft and stage5 integration tests; `tests/test_control_processes.py` |
| SEC-06 | Gateway snapshots MUST verify signature, cluster/schema/revision/time/expiry and deny unknown/revoked identities. Offline use MUST NOT extend expiry. Controller authentication databases/private identity keys MUST NOT leak to gateways/Device configs. Gateway-required WGShim PSKs are intentionally scoped secrets. | `deploy/bpc_gateway_snapshot.py`; `tests/test_gateway_snapshot.py`, `test_gateway_dataplane.py`; distributed-control-plane.md |
| SEC-07 | Probe rollback MUST be armed before mutation and clean only uniquely tagged rules, including after command failure/SIGKILL. | `scripts/firewall_probe.py`; `tests/test_firewall_probe.py`, `test_firewall_probe_systemd.py` |
| MESH-01 | Path switching MUST preserve Device identity, overlay address/key, Access and AllowedIPs; transport reachability MUST NOT grant authorization. | `internal/agentctl/path_test.go`, `internal/wgshim/cross_node_acceptance_test.go`; `tests/test_public_node_provisioning.py` |
| MESH-02 | Healthy migration MUST preserve the old peer/session during verification. Only returned WireGuard data confirms migration; probes/handshake alone do not. Unconfirmed traffic MUST have bounded rollback; idle tunnels are distinct. | `internal/wgshim/path_test.go`, `path_acceptance_test.go`; transport-paths.md |
| MESH-03 | Discovery MUST use authenticated relay health plus matching canonical overlay public key; Controller-issued endpoints MUST NOT be replaced by arbitrary heartbeat hostnames. | `deploy/bpc_node_enrollment.py`; `tests/test_node_enrollment.py`, `test_public_node_provisioning.py` |
| MESH-04 | Advertised non-default IPv4 CIDRs MUST belong to a site_router Node; heartbeat and route withdrawal MUST commit together. Route advertisement MUST NOT itself confer Device Access. | `tests/test_node_enrollment.py` (`test_site_router_heartbeat_owns_canonical_routes`), controlplane tests; distributed-control-plane.md |

## Device P2P prototype contracts

These apply to the foundation and opt-in Controller authority; installed Agent
enabling remains pending. See [ADR 0002](../adr/0002-device-p2p-session-boundary.md)
and [ADR 0003](../adr/0003-p2p-controller-authority.md).

| ID | Contract | Verification |
| --- | --- | --- |
| P2P-01 | A session MUST bind trusted cluster/issuer, revision, distinct same-owner Device identity/WG keys, service and bounded expiry. Device proof MUST bind a fresh relay challenge and TLS channel. A ticket alone MUST NOT authenticate a Device. | `internal/p2p/policy_test.go`, `relay_test.go` |
| P2P-02 | The receiving endpoint MUST enforce plaintext source/destination, service, initiation/reply direction and expiry independently of the initiator. Local revoke MUST invalidate established flows in both directions; expiry MUST NOT renew offline. | Real userspace WG/TLS/TCP/UDP test with an unfiltered initiator, plus policy tests; durable managed-policy revoke tests; installed Windows remains pending |
| P2P-03 | A session relay MUST forward only between authenticated participants, retain WG payload encryption, bound connection/session/frame/flow resources, close revoked sessions and reject ticket reattachment for the outstanding lease lifetime. | `internal/p2p/relay_test.go`; no claim of restart persistence or production deployment |

| P2P-04 | Grant/policy signing MUST follow a committed fence of exact identity, credential, configuration and Access inputs. Both Devices MUST consent; initiating Access MUST allow the host and deny MUST win. | `tests/test_p2p_authority.py`, real Raft/mTLS `test_control_processes.py`, public `test_p2p_http.py` |
| P2P-05 | Managed endpoints MUST persist trusted issuer and revision/time floors, restore no cached allow after restart, reject replay and invalidate established traffic on signed denial or expiry. Sync failure MUST fail closed before renewal. | `internal/p2p/authority_test.go`, managed real-WG relay test; installed Agent loop remains pending |

## Candidate mesh obligations (not implemented by this change)

Before merging a site-router dataplane candidate, specify and test: authenticated
source identity across hops, deny/revoke in both directions across every ingress,
route ownership conflicts/withdrawals, stale or expired policy, loop/default-route
rejection, external-network preservation, restart/failure and rollback. Compare
to main explicitly; do not infer coverage from transport-only failover tests.

Userspace tests use a surviving routed destination and explicit return-path
assumptions. They do not promise survival of gateway-local NAT/conntrack flows,
WAN convergence or arbitrary TCP sessions. Linux privileged checks are required
for actual firewall enforcement; WAN/Windows evidence is separately recorded.
