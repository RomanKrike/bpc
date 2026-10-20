# Account P2P delivery and Windows controls

Task: reuse prepared HTTPS Agent downloads and account login; connect two owned
Windows Devices without exporting/importing a public ticket or accepting an
invitation on the host. Preserve P2P-01..06, SEC-02/04/05 and MESH-01.

Extend the existing tray UI, authenticated Device API and bounded session runtime,
without new UI dependencies. Installation into an explicitly configured account
pilot initializes trust and signs Device consent before starting the service.
Existing installations may explicitly prepare through the P2P window. Consent
revocation remains available and must not be automatically undone at restart.

Controller config must explicitly set `p2p_account_mode: true` and a TLS
`p2p_relay` host:port, in addition to `p2p_enabled`. Account mode uses same-owner
Devices and the existing initiating Access allow/deny checks, not login alone
as network authorization. Existing manual pilot APIs remain compatible.

Add one bounded, expiring public delivery slot per Device under the new canonical
`control/p2p-delivery/` prefix. This deliberately extends ADR 0003's no-session
state rule for reliable delivery across Controller replicas. Slots contain only
the signed public grant, canonical relay and expiry; no private keys, packets,
flow state or renewed authorization. Publishing both slots uses a single CAS
mutation fenced by current pair/config/credential state. A busy slot rejects
replacement. At most one retained slot per Device; expired slots are overwritten.
Both peers poll their own slot with fresh authentication and authorization.
Endpoint grant/policy verification remains the authorization boundary.

Use a preliminary grant fence, then a separate delivery fence: grant signing
occurs only after its committed revision. Delivery revalidates the exact signed
participants and current Access. Quorum loss fails closed. Empty polling needs a
linearizable read; nonempty delivery additionally fences the complete security
snapshot before returning it. Polling never extends the <=60s grant.

The Windows window selects an owned host, requests delivery and stops/revokes
locally. A queued request is never presented as an established data plane.
No host-side invitation prompt is required. UAC elevation is still required for
local administrative preparation. Moonlight/Sunshine installation, their own
pairing and long-session renewal are separate work.

Acceptance: test owner/Access boundaries, busy races, expiry, revocation,
Controller replica delivery, default-off install and repeat preparation preserving
trust. Run existing CI in full. Native Wintun/UI/UAC and real streaming remain
isolated operational acceptance, not claims from compilation or script parsing.

Rollback: withdraw consent/disable account mode and stop sessions, let grants
expire, restore previous Agent binaries while retaining protected trust/policy floors.
Controller downgrade needs explicit snapshot/schema review; it is not automatic.
Old Controllers cannot materialize the new prefix: upgrade the Controller quorum
before enabling account mode; do not use mixed versions for this pilot.
