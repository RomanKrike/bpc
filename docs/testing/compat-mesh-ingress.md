# Compatibility Device ingress into routed mesh

On a Public Node with an existing BPC-owned WireGuard interface, local gateway
reconciliation uses the canonical Node enrollment to mark client traffic to
Controller-authorized site routes. The packet enters the existing routed policy
table (12530, mark 0x425043); the main routing table and unrelated WireGuard
interfaces are not changed. Nodes without local compatibility ingress remain
unchanged. Enrollment changes now trigger the existing reconcile path unit.

BPC-MESH-IN marks known Device source IPs to managed site CIDRs. BPC-ACCESS checks
current authorization before its conntrack return allowance, including disabled
and revoked Devices. BPC-MESH-GUARD denies these flows if the selected output is
not bpcrt0, including when the routed process stops and removes its policy rule.
The routed process already supplies the scoped no-NAT exemption for bpcrt0.

Previously managed sources/CIDRs remain guarded after route withdrawal or Device
removal: a withdrawn mesh route must not silently return to legacy WireGuard.
The local ownership journal is mesh-ingress-firewall.json. Do not delete this
journal to disable the guard; explicit downgrade/removal needs a coordinated
migration. Unrelated root/legacy traffic still uses the main routing table.

Reconciliation serializes firewall changes and replaces each owned chain with an
iptables-restore transaction. It inserts the new tagged Access jump before
removing old jumps; existing untagged Access jumps migrate without an enforcement
gap. It refuses adoption of mesh chains without matching ownership evidence.

## Validation

`tests/test_mesh_ingress_kernel.py` runs in three disposable Linux namespaces in
CI. It verifies source IP preservation over real forwarding, established TCP
revocation, idempotent reconciliation, and denial before legacy forwarding after
removal of the mesh policy rule. The veth interface represents the mesh TUN
boundary; this test does not exercise the encrypted Node transport or Raft.

Live validation must capture a new Windows TCP/SSH connection entering bpcag0 and
leaving bpcrt0, verify Access revocation while it remains connected, and exercise
site-uplink failure while preserving the TCP session. Windows Public Node ingress
migration remains a separate acceptance scenario.
