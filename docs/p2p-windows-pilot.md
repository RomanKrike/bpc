# Windows P2P pilot (explicit, experimental)

For a server already on a pinned mesh candidate, use the
[mesh-compatible candidate procedure](mesh-p2p-update.md). Stable v0.21.0 is not
an upgrade for that server. Candidate Windows updates use fresh prepared links;
the candidate's existing signed auto-update publication guard remains in force.

This is an operator pilot, not a finished Moonlight/Sunshine product. It uses
one active session per Agent, default Sunshine ports, same-owner Devices and
an unrenewed grant of at most 60 seconds. Read [ADR 0004](adr/0004-p2p-windows-pilot-runtime.md)
and [STATUS](STATUS.md) before treating any test as real Windows acceptance.

## Prerequisites

### Account pilot: download, sign in, select your computer

The new account UI builds on this pilot; see [ADR 0005](adr/0005-account-p2p-delivery.md).
The operator first upgrades all Controllers to the matching version and enables
`p2p_enabled: true`, `p2p_account_mode: true` and `p2p_relay: "HOST:24446"`
through the existing canonical consensus-backed config mutation. Provision the
TLS relay below and retain the initiating Access allow/deny policy. A mixed
Controller quorum is not supported after enabling the new delivery prefix.

Use the existing personal HTTPS download link for a prepared Windows Agent
generated from this version's deployment bundle. Download and open the executable,
approve Windows elevation, and sign into the same account on both computers.
Fresh account enrollment automatically initializes P2P trust and signs consent
when the Controller advertises account mode. If the Controller is unavailable,
the optional setup is deferred; use the window's enable button after recovery.
An old prepared executable does not acquire new code just because its link exists.

Open BP Connect from the tray, choose Settings -> Moonlight / Sunshine (also in
the tray context menu). Existing installations use **Enable on this PC** once;
the dialog explicitly warns about the Agent restart and short BPC interruption.
On the initiating computer, refresh the list, select the owned Sunshine computer,
and press **Connect**. No ticket file, invitation acceptance or terminal is needed
on the host. The list is an authorized-device list, not proof of online status.
Open Moonlight and add the displayed BPC address. Sunshine installation and its
own Moonlight pairing remain separate; do not bypass their authentication.

The UI reports a queued request, not confirmed packet delivery. Both Agents poll
their own authenticated delivery slot every two seconds; grants remain <=60s.
**Disable P2P on this PC** stops locally and withdraws consent. Restart/reinstall
does not automatically restore withdrawn consent. A pending slot cannot be replaced
until expiry, including after local stop. Long-session renewal remains pending.

The command-line procedure below is retained for compatibility and diagnostics.

Use two separately authorized, isolated Windows test computers with installed
BPC Agents and functioning gateway tunnels. The service must have the current
pilot binary and its existing Wintun dependency. Keep existing Device identity,
WireGuard keys and addresses. Controller must advertise p2p-session-v1 and have
global P2P enabled through the existing Raft-backed canonical config mutation;
never edit canonical files directly on replicas. Configure initiating Access
for the host /32 before setting consent; deny still overrides allow.

Provision an explicitly authorized test Node's TLS relay using its existing
publicly trusted certificate (or a test CA already trusted by both computers):

```text
bpc-p2p-relay --listen BIND_ADDRESS:24446 --cluster CLUSTER_ID --issuer-public-key CONTROLLER_PUBLIC_KEY --tls-cert CERT_FILE --tls-key KEY_FILE
```

The issuer is the Controller public Ed25519 pin. Relay has no Controller signing
key or Device WG private key. Default listener is loopback; no installer enables
a public listener/service. Firewall, TLS files, Node service provisioning and
routing remain separately authorized operator work. There is no insecure TLS
switch. Do not change public Node discovery or gateway peers to point at a Device.

## Explicit bootstrap and consent

On each test computer, use an Administrator terminal:

```text
bpc-agent.exe p2p init
```

This authenticates to the configured Controller using the enrolled Device
credential, creates public trust and policy state in ProgramData/BPC/p2p and
locks that directory to SYSTEM/Administrators. It never overwrites existing
trust or recreates a missing initialized database. Restart the Agent through the
existing supported stop/start procedure to activate the shared-adapter pilot.
No P2P initialization means the original gateway TUN path remains unchanged.

Then on both computers:

```text
bpc-agent.exe p2p consent --enabled=true
```

The proof uses the enrolled Device key and exact Access hash. A conflict requires
refresh/retry; another Device or relay cannot grant consent. Commands use the
access credential maintained by the running Agent; they do not independently
rotate credentials. An expired credential requires the normal Agent refresh.

## Bounded session

On the initiating computer:

```text
bpc-agent.exe p2p request --host HOST_DEVICE_ID --out NEW_PUBLIC_TICKET_FILE
```

Transfer only this public ticket file to the host through the authorized test
channel. Never copy state.json, private keys, credentials or policy.db. Promptly
submit the same ticket on both computers, before its maximum 60-second expiry:

```text
bpc-agent.exe p2p start --ticket PUBLIC_TICKET_FILE --relay TLS_RELAY_HOST:24446
```

The running Agent verifies its own Device/WG keys and address, obtains fresh
Controller policy, attaches a separately filtered WG peer and adds only the
owned BPC /32 route after checking adapter GUID/index and route conflicts. The
TLS name is TLS_RELAY_HOST and must match its certificate. A command saying
requested is not a data-plane/enforcement acknowledgement. Inspect the pilot
logs and verify TCP/UDP with the actual test application independently.

On either computer:

```text
bpc-agent.exe p2p stop
bpc-agent.exe p2p consent --enabled=false
```

The local request is polled once per second. Active policy polls every five
seconds with a three-second request deadline; signed denial or HTTP error
terminates the session. Packet filtering also checks wall/monotonic expiry and
idle transport expiry is watched independently. A stopped ticket cannot be
reused; obtain a new grant. No automatic ticket delivery or long-stream renewal
is implemented. First-peer arrival can precede the other participant; ordinary
WG retry timing is not a WAN latency guarantee.

## Failure and rollback

Established TCP/UDP must stop after denial, expiry or local stop. A reserved
peer address remains blocked instead of returning to gateway, including across
restart; at most 16 distinct peer reservations are retained in this pilot.
Other gateway destinations stay on their existing path. Conflicting/external
routes are refused, never removed. Route/adapter/ACL effects and native cleanup
still require isolated Windows acceptance; userspace tests do not certify them.

If initialized trust/database is missing or corrupt at boot, the overlay fails
closed because previous deny reservations cannot safely be reconstructed. Do
not delete/reset either file to bypass a revision floor or pin. A partial init
also needs deliberate repair. No authorization is restored from disk alone.

For rollback, stop sessions, withdraw consent, disable Controller P2P, wait for
outstanding grants to expire, then stop the overlay and restore the previous
binary. Keep canonical identities and protected policy state; do not wipe trust.
Use the existing owned-adapter reconciliation and never delete external routes.
