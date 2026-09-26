# Stage 2: one-command install and Node Join

Stage 2 enrolls a server-side BPC Node into an existing Controller without
manually editing BPC configuration files. It extends the unified Node model
from Stage 1 and does not replace the existing data-plane transports.

## End-to-end flow

On an existing Controller, create a one-time token:

```bash
bpc node token create \
  --roles gateway,relay \
  --name ge-02 \
  --expires 15m
```

The command prints a token whose public envelope contains the Controller HTTPS
endpoint and whose 256-bit secret is stored by the Controller only as a
SHA-256 index.

On a clean Debian/Ubuntu VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh | sudo sh
bpc join BPC-<controller-envelope>.<one-time-secret>
```

The `bpc` wrapper elevates Node-management operations through `sudo` when
needed, so the user-facing join command does not require a separate `sudo`
prefix.

After a successful join:

```bash
bpc status
bpc node info
```

On the Controller:

```bash
bpc node list
```

To revoke the local Node credential and leave the cluster:

```bash
bpc leave
```

Use `bpc leave --force` only when the Controller is permanently unavailable
and local state must be detached. The private identity key is intentionally
kept locally so leaving a cluster does not silently rotate the machine
identity.

## Enrollment protocol

`bpc join` performs the following sequence:

1. Parse the Controller HTTPS endpoint from the opaque `BPC-` token.
2. Create an Ed25519 identity under
   `/etc/bpc-connect/identity/node.key` if the Node does not already have one.
3. Derive and send only the public key together with the one-time token.
4. The Controller atomically validates token existence, expiration and replay
   state.
5. The Controller rejects an active duplicate public-key fingerprint.
6. The Controller allocates a unique Node ID and a random Node credential.
7. The Controller consumes the token and writes a tombstone so replay is
   distinguishable from an unknown token.
8. The Node stores its enrollment state, applies the Controller-assigned ID,
   name and capabilities to `node.yaml`, reconciles existing role services and
   starts `bpc-node.service`.
9. `bpc-node.service` sends periodic authenticated heartbeats and receives the
   current capability/config payload.

The Node private key is never part of the HTTP request and is never written to
Controller state.

## Controller state

Node enrollment is intentionally separate from the existing BP Connect
User/Device Agent enrollment. Stage 2 adds these Controller directories below
the existing control-plane state:

```text
node-join/          unused token metadata, indexed by SHA-256(secret)
node-join-used/     consumed/expired token tombstones
nodes/              cluster Node records
node-public-keys/   active public-key fingerprint -> Node ID index
node-credentials/   SHA-256(credential) -> Node ID index
```

State files are written atomically with mode `0600`; secret-bearing
directories are created with mode `0700`.

## Capability reconciliation

Capabilities remain metadata on one Node rather than separate Node types.

- `gateway`: reuses the existing Xray/REALITY gateway bootstrap and state.
- `relay`: reuses the existing Agent/WGShim relay data-plane provisioner.
- `controller`: an already provisioned Controller service is reconciled and
  started. Automatic promotion of a completely fresh remote Node into a second
  Controller would require certificate distribution and replicated Controller
  state, which belongs to a later distributed-control-plane stage.
- `site_router`: remains modeled but is not implemented in Stage 2; MikroTik
  and site routing are explicitly deferred.

A typical Stage 2 fresh-server token therefore assigns `gateway,relay`.

## Idempotency and compatibility

The no-argument installer is safe to run again. It preserves the current
release/state pointer, existing transport credentials, Node identity and
enrollment files.

The old explicit bootstrap remains supported:

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh \
  | sudo bash -s -- --role ru-node --reality-server-name www.bing.com
```

Running `bpc join` again on an already enrolled Node returns the existing Node
identity and does not overwrite enrollment or transport configuration.

## Security properties

- Join tokens are single-use and expire.
- Token replay is rejected after successful use and after expiration.
- Active duplicate Node public-key identities are rejected.
- Node credentials are random 256-bit bearer credentials and the Controller
  stores only their SHA-256 lookup index.
- Controller communication requires HTTPS with normal CA verification.
- Node private identity key mode is `0600`; identity/enrollment state is
  root-owned.
- Existing Xray, WireGuard, WGShim and Agent transport keys are not reused as
  the Node identity.

## Tests

The Stage 2 suite includes an HTTP integration path:

```text
Create join token
  -> POST /v1/nodes/join
  -> POST /v1/nodes/heartbeat
  -> replay token (409)
  -> POST /v1/nodes/leave
  -> old credential rejected (401)
```

Additional tests cover expiration, duplicate active identity, root-only
permissions and Controller-assigned Node IDs.
