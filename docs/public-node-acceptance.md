# Public Node acceptance

## Automated evidence and scope

`tests/test_control_processes.py` starts three real `bpc-controld` subprocesses
with independent directories, Raft databases and loopback mTLS sockets. It checks
nonvoter membership, voter promotion, Node enrollment and endpoint replication,
process restart and a canonical mutation after leader failure. CI runs it in the
`control-runtime` job. This is process integration, not VPS/systemd/reboot acceptance.

Run it locally:

```bash
go build -o /tmp/bpc-controld ./cmd/bpc-controld
BPC_CONTROLD_BINARY=/tmp/bpc-controld pytest tests/test_control_processes.py -s
```

## Live prerequisites

Use two disposable Debian 12/13 hosts to validate provisioning. Use three
Controller Nodes for loss-of-one-voter write availability (two voters require
both to remain available). DNS must already point to each public host. Allow
TCP/80 for HTTP-01 issuance, TCP/8444 for public control and TCP/9445,9447 between
Controllers. BPC cannot configure provider DNS or provider firewalls.

The following commands are an acceptance procedure, not a claim that they have
already been executed on VPS hosts. Run them on the designated test host only.
Do not stop production Controllers as an initial test.

## First Node: ru-01

```bash
curl -fsSL https://github.com/RomanKrike/bpc/releases/latest/download/install.sh | bash
bpc init --name ru-01 --roles controller,gateway,relay --hostname ru-01.blinpi.ru
bpc cluster status
bpc node create --name ru-02 --preset public-node --host ru-02.blinpi.ru --expires 1h
```

If ru-01 already runs BPC 0.18.4 with a working distributed Controller, use
`bpc-update` and `bpc cluster status` instead of reinitializing it.

## Second Node: ru-02

Run the exact generated `curl ... | bash -s -- join BPC-...` command as root.
Then:

```bash
bpc status
bpc node info
bpc cluster status
systemctl is-active bpc-controld bpc-control bpc-node xray bpc-agent-relay
journalctl -u bpc-controld --no-pager -n 100
```

On ru-01 inspect membership events for `state=nonvoter` and `action=promote`.
On both hosts, membership must converge to voter and canonical Node endpoint
records under `/etc/bpc-connect/control/nodes/` must agree. Inspect only selected
non-secret fields, for example:

```bash
python3 - <<'PY'
import json
from pathlib import Path
for path in sorted(Path('/etc/bpc-connect/control/nodes').glob('*.json')):
    node = json.loads(path.read_text())
    print(node['node_id'], node['name'], node.get('endpoints', []))
PY
```

Repeat the same generated installation command on ru-02. Verify its Node ID,
identity key and existing transport credentials have not changed. A consumed
token must fail if replayed from a different, unenrolled host.

## Restart, update and reboot on ru-02

Record `bpc node info` and the relevant learned WireGuard peer endpoints before
and after the following, while a test client sends traffic:

```bash
systemctl restart bpc-control
bpc status
systemctl restart bpc-node
bpc cluster status
bpc-update
bpc status
reboot
```

After reconnecting to ru-02, repeat `bpc status`, `bpc node info` and
`bpc cluster status`. Identity, enrollment and endpoints must persist. Compare
only BPC-owned network objects; unrelated WireGuard/routes/firewall must remain
unchanged.

## Controller failure and private Node

Enroll ge-01 using the same public-node procedure before testing quorum failover.
On a surviving Controller:

```bash
bpc node create --name home-01 --preset site-router --route 192.168.88.0/24 --expires 1h
```

Stop the current leader's test `bpc-control` and `bpc-controld` services, then run
the generated command on the private test host. It must enroll through a
surviving Controller without a public IP, DNS or inbound forwarding. Restore the
stopped services and verify catch-up and endpoint consistency on all three.

A site-router currently advertises Node-owned routes and maintains outbound
control heartbeats. This release does not add a new routed-site transport, grant
Access automatically or implement multipath dataplane.

## Compatibility and limitations

- Old single-URL tokens and endpoint-less Node YAML remain valid.
- Bootstrap supports amd64/arm64 Debian 12/13 and Ubuntu 24.04.
- Release checksum verification relies on trusted HTTPS to GitHub; this is not
  an independent release-signing system.
- Repeated bootstrap resumes the installed version. `bpc-update` remains the
  update mechanism; no timer that might update Raft voters simultaneously is added.
- Invitation download itself uses GitHub; Controller pool failover applies to
  enrollment and subsequent control requests, not GitHub availability.
- A short secret URL is intentionally not implemented; join credentials are not
  placed in HTTP download URLs.
- New firewall rules have explicit BPC comments. Historical untagged rules are
  not automatically removed based only on subnet/interface matches.
