# BPC Access and routes

Stage 4 introduces a deliberately small Access model. It does not add
Organizations, Teams, policy engines, or network-object abstractions.

## Model

Access is attached to either a User or a Device and currently contains IPv4 CIDR
rules:

```text
User / Device
      |
    Access
      |
 allow / deny CIDR
```

Records live in the Controller state directory under `control/access/`. User
and Device records are combined for a Device. Existing `managed_routes` from
the pre-Access gateway workflow are treated as legacy explicit allows so
upgrades do not silently break existing gateway grants.

Rules are default-deny:

- a destination is reachable only when it is covered by an allow;
- any matching deny overrides any allow, including broader or narrower
  overlapping rules;
- a revoked or disabled Device has no effective routes regardless of allows;
- `0.0.0.0/0` is rejected so this stage remains split-tunnel.

For overlapping rules the Controller subtracts denied networks from allowed
networks before publishing routes. For example, allowing `192.168.0.0/16` and
denying `192.168.88.0/24` publishes CIDRs covering the /16 except the denied
/24.

## CLI

```bash
bpc access list
bpc access list --user roman
bpc access list --device pc004

bpc access grant --user roman 192.168.88.0/24
bpc access revoke --user other 192.168.88.0/24

bpc access grant --device pc004 10.253.0.0/24
bpc access revoke --device pc004 10.253.0.50/32
```

`grant` writes an allow rule. `revoke` writes a deny rule. Granting or
revoking the exact same CIDR toggles that exact rule between the two sets;
overlapping broader/narrower rules remain and deny still has priority.

## Client routes vs enforcement

The Controller returns only the Device's effective routes in the WireGuard
profile (plus the Controller WireGuard address as an infrastructure /32). This
keeps the client routing table aligned with what the User can reach.

That is not the security boundary. The BPC Node also owns an iptables chain
named `BPC-ACCESS` on the Agent WireGuard interface. For each active client
source address it accepts effective allowed CIDRs and then drops every other
forwarded destination. Existing/related reply traffic is accepted first.

Therefore:

```text
Client AllowedIPs = UX
BPC-ACCESS firewall = security
```

Access changes reconcile the firewall immediately and do not restart BPC.
Clients receive route changes on their next normal config sync.

## Device revoke precedence

Device revoke removes the WireGuard peer and credentials as before. In addition,
the Access evaluator returns no routes for a disabled/revoked Device, so a stale
Access allow cannot restore connectivity.

## Stage 4 boundary

This stage intentionally implements CIDR resources only. The Access record
format keeps a separate subject type so service- and Node-scoped resources can
be added later without introducing an enterprise RBAC model now.
