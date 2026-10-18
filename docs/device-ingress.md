# Device gateways alongside routed mesh

Mesh link readiness does not imply that a Public Node accepts Windows clients.
The compatibility Agent ingress must exist, use the canonical overlay identity,
and report a healthy relay and WireGuard interface before discovery advertises it.
The Windows counter groups transport ports by Node, not by UDP port.

The bootstrap Controller retains its existing Agent ingress when mesh is enabled.
Its heartbeat now advertises that preserved ingress. Pure routed Nodes still do
not install or advertise Agent transports during join or heartbeat.

An additional **enrolled Controller/Gateway/Relay** can explicitly enable Device
ingress using its replicated canonical overlay key and Device records:

```bash
python3 /opt/bpc/current/deploy/bpc-enable-device-ingress.py --host PUBLIC_IP_OR_DNS
```

Before running this privileged provisioning command, independently arm and verify
an absolute UTC rollback timer and keep an independent management SSH connection
and provider console available. The command itself does not supply a rollback
watchdog. Do not run the historical full proxy bootstrap or replace canonical
control/config.json. The helper rejects an existing unmarked Agent runtime and
unknown interface ownership; inspect such resources rather than adopting them.

Provisioning reuses only the owned Agent dataplane installer, preserving the
canonical Node model, cluster configuration and mesh service. Peers and Access
are reconciled before a Node-bound local `device-ingress.json` marker is written.
This explicit marker permits subsequent startup/heartbeat reconciliation. It
does not change routed role configuration or grant any additional Access.

The relay startup guard validates the signed security snapshot. Expired snapshot
grace stops ingress as well as mesh; removing gateway/relay capability stops
ingress, and leaving the cluster disables it. A matching canonical WireGuard
identity is required for discovery; an independent gateway identity cannot be
substituted into the existing client's unchanged WireGuard profile.

Authenticated runtime `public_host` associates the existing IP-based compatibility
pool with its real Node and prevents a DNS alias being counted as another gateway.
Stopped Device ingress is excluded even when the mesh relay service is healthy.

Verification covers explicit opt-in, identity binding, preserved cluster state,
startup, capability withdrawal, lease expiry, IP/DNS grouping, unhealthy ingress,
legacy compatibility and ordinary routed join. The kernel namespace regression
checks Access revocation and fail-closed Device-to-mesh forwarding. A live Windows
handoff still requires observing an actual cross-Node switch and application
traffic; a `2/2` counter alone is insufficient evidence.
