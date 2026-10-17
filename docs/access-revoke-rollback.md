# BPC-1 Access revocation and temporary probe rollback

## Baseline inspected

Main at 832a969 retains the original established-before-Access bypass. PR #87
merged as 172e09f into feature/site-router-mesh, not main. Its CI #526 passed.
PR #68 is still the main-targeting mesh integration/release gate. This follow-up
targets the mesh branch so it preserves the compatibility ingress guard, atomic
chain replacement, routed policy table, multi-path runtime and join flow.
Do not merge all mesh changes to stable solely to obtain this Access fix.
A stable backport needs the Access-only parts and its own privileged checks.

No tracked bpc-mark-rollback-* or bpc-mesh-icmp-rollback-* scripts/units were
found in main or the mesh branch. Previously installed transient units cannot
be audited without collecting their actual definitions from the relevant VPS.
Inspect `systemctl list-timers --all` and `systemctl cat UNIT` before relying on
any old rollback unit. Never cancel old timers just because a probe failed.

## Enforcement

Reconciliation now keeps retired IPv4 Device addresses in the local ownership
journal even on a pure compatibility gateway. Deleted/renumbered clients cannot
fall through to broad forwarding or conntrack accepts. Revocation also checks
the reverse destination before established return allowances, via a second
owned FORWARD jump. This prevents unsolicited server data continuing after
revocation. Regrant uses current effective routes. Static site-router peers are
still excluded from the client list. Historical addresses intentionally remain
denied until explicitly reassigned to a currently authorized Device.

The guarantee starts after a successful local firewall reconcile; a Controller
commit alone is not a distributed gateway enforcement acknowledgement. Existing
snapshot polling/lease expiry and reconciliation delivery remain relevant.
INPUT to the gateway itself, alternate unmanaged VPN interfaces, IPv6 and
application sessions outside the managed forwarding path are not covered here.

## Safe temporary MARK probes

Save scripts/firewall_probe.py at a stable root-controlled path on a Linux
systemd host. The caller must be in the host network namespace. Select exactly
one test Device source address, one test LAN destination and the owned ingress
interface. Keep management SSH outside this test path and retain provider console
access. Do not persist probe rules with iptables-save/netfilter-persistent.

Example (substitute verified test addresses; the command is a bounded observer):

```sh
sudo python3 /root/bpc/scripts/firewall_probe.py \
  --interface bpcag0 --source 10.253.0.2 --destination 192.168.88.12 \
  --icmp --seconds 60 -- sleep 30
```

This only marks ingress packets; traffic must originate on the selected Device.
Without --icmp the same exact source/destination mark permits TCP observation.
It does not add any Access ACCEPT or change INPUT, OUTPUT, routing or NAT.

The helper creates a unique bpc-mesh-icmp-rollback-* or bpc-mark-rollback-* timer,
verifies it is active BEFORE insertion, and serializes insertion and cleanup
with flock. The watchdog removes the exact uniquely tagged rule at a fixed UTC
OnCalendar deadline with Persistent=true. Relative OnActive
timers must not be used: repeated manager reloads on the actual VPS postponed
their expiry. The root integration test includes SIGKILL plus repeated
daemon-reload to guard this production failure mode.
The watchdog operates independently of SSH and the test process. Normal completion,
nonzero exit and timeout clean
up immediately. Cleanup errors leave the watchdog armed; service failures retry.
SIGKILL cannot run finally, so the real systemd integration test explicitly
checks that case. Keep the script and its Python executable available until
cleanup finishes. Timers do not survive reboot; unpersisted iptables rules also
disappear on reboot. Loss of systemd/kernel/root storage is not a guaranteed
rollback environment. The helper does not roll back Access/Raft policy or
unrelated pre-existing rules.

## Evidence and release gates

Unit tests cover exact rule scoping, invalid inputs, watchdog setup refusal,
failed insertion/test, timeout and cleanup errors. The privileged CI job checks
actual systemd cleanup after a failed command and SIGKILL with an unmatchable
test interface, alongside the existing namespace/kernel suite. The namespace
test checks both directions of an already-established TCP socket after revoke,
source preservation and fail-closed fallback.

Local Windows cannot run the Linux server suite (fcntl, Linux uid and privileged
network namespaces are required). No live VPS, Termius session, provider-console
fallback or installed transient rollback unit has been verified in this task.
CI and live acceptance results must be recorded separately; test code and
previous CI results are not evidence that the new revision passed.

## Peer reply compatibility

Authorization is tied to the original conntrack flow, in both directions.
An active responder Device need not have an initiation grant to send replies
for an initiating Device's permitted connection. Its own new connections still
require its own grants. Revoked/deleted/retired identities are denied before
flow allowances, including when they are the responder. Untracked packets from
or towards known Devices remain denied. The privileged namespace regression
covers peer replies, ungranted peer initiation, revoked responders and the
existing bidirectional TCP revoke/fallback checks. It reproduces a reply-drop
regression in the prior current-packet-source implementation.
