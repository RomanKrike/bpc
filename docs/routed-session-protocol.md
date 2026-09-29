# Routed Node session lifecycle (development)

This applies only to the unreleased Node-to-Node routed mesh in PR #68.
Existing Device WireGuard/WGShim v1 payloads and profiles are unchanged.

Each configured Node link reuses the WGShim authenticated codec and directional
keys. Each process incarnation generates a fresh random 128-bit local epoch.
A probe carries the local epoch and a fresh 128-bit challenge. Its authenticated
reply echoes both and adds the responder's epoch. The reply must match an
outstanding challenge, configured peer, and destination endpoint. Only this
response may install a remote epoch and reset that peer's replay window.

Data carries sender epoch, receiver epoch, a 64-bit sequence number and the
routed frame. Both epochs must match the confirmed session before the sequence
window is updated. This allows a restarted sender to restart its sequence while
rejecting captured data from either process's previous incarnation. Ordinary
probe replies with an unchanged epoch never reset the replay window.

An unsolicited probe request is not evidence of freshness. It can elicit a
reply and a bounded return challenge, but cannot change the learned endpoint or
reset replay state. Replayed data is rejected before endpoint learning. Private
Nodes initiate probes to public endpoints; public Nodes learn private endpoints
only after completing the return challenge. No inbound private DNS/IP or port
forwarding is required by this exchange.

Runtime reload preserves confirmed sessions for unchanged peer identity/key
material. Peer metadata reads and updates share a lock. Keys changing deliberately
create a new session. The probe timeout and existing path health policy bound
recovery; no production timing guarantee is asserted.

Tests exercise actual localhost UDP challenge/response, private endpoint learning,
public runtime restart, replayed-packet endpoint hijack rejection, both incarnation
changes, duplicate/out-of-order sequence handling and race detection. These are
protocol integration tests, not full kernel routing, Windows or multi-VPS HA
acceptance.
