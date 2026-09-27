# Install and update lifecycle

BPC Nodes are installed from versioned GitHub Release bundles rather than from a
mutable checkout.

## Filesystem layout

Application code is immutable:

```text
/opt/bpc/
├── releases/
│   └── <version>/
└── current -> /opt/bpc/releases/<active-version>
```

Canonical state is outside the release tree:

```text
/etc/bpc-connect/
├── node.yaml
├── identity/
├── cluster/
├── control/
├── runtime/
├── transports/
├── compat/
└── backups/
```

Existing transport installations may still have state under
`/etc/bpc-connect/ru-node/`. Stage 4.5 treats that tree as compatibility
runtime/input; new Controller and domain state is not written there.

Release updates therefore do not regenerate transport credentials.

## Install the runtime

On a clean Debian/Ubuntu server:

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh | sudo bash
```

This installs the current release and command wrappers without assigning a
historical server type.

### Initialize the first Controller

For the first Node in a cluster:

```bash
bpc init \
  --name ru-01 \
  --roles controller,gateway,relay \
  --hostname sub.example.com
```

The hostname is used for trusted Controller HTTPS when an existing certificate
is not already available.

### Join another Node

Create a one-time token on the Controller, then join the new host:

```bash
bpc node token create --roles gateway,relay --name ge-02 --expires 15m
bpc join BPC-<controller-envelope>.<one-time-secret>
```

## Legacy explicit bootstrap

The historical installer profile remains available only for compatibility with
existing deployments and recovery procedures:

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh \
  | sudo bash -s -- --role ru-node --reality-server-name www.bing.com
```

`BPC_ROLE=ru-node` is not a canonical Node type. Clean installations should
use `bpc init` or `bpc join`.

## Stage 4.5 canonical migration

Updates run the canonical migration before BPC-owned runtime reconciliation.

You can run it explicitly:

```bash
bpc state migrate
```

Before changing BPC state it snapshots current network/runtime inventory under:

```text
/etc/bpc-connect/backups/pre-4.5-<timestamp>/
```

The inventory includes links, all routes, policy rules, redacted WireGuard
state, iptables, nftables and systemd units.

The migration may copy historical BPC Controller state from:

```text
/etc/bpc-connect/ru-node/control/
```

to:

```text
/etc/bpc-connect/control/
```

It does not delete the source. The source, backup and staged destination are
verified before the canonical copy is activated.

If a non-empty canonical Controller tree already differs from the historical
tree, migration fails instead of overwriting either side.

A successful migration writes ownership/idempotency markers:

```text
/etc/bpc-connect/control/.bpc-state.json
/etc/bpc-connect/compat/stage-4.5.json
```

Subsequent migration runs return the recorded report without making a second
copy.

## Network ownership safety

Migration does not mutate network objects.

Runtime reconciliation follows the ownership policy:

- `OWNED_BY_BPC`: BPC may reconcile it;
- `LEGACY_BPC`: BPC may adopt it when historical BPC evidence exists;
- `EXTERNAL`: BPC must not mutate it;
- `UNKNOWN`: BPC fails closed.

For the BPC Agent WireGuard interface, a matching interface name alone is not
ownership evidence. Stage 4.5 writes explicit ownership metadata and requires
it before Controller peer or Access firewall mutation.

This protects unrelated interfaces such as a pre-existing `wg0`, their routes
and firewall rules.

## Status

Use canonical Node status:

```bash
bpc status
bpc node status
bpc node info
```

The legacy detailed `bpc-status` command remains available for transport
diagnostics.

Status commands do not print private keys, PSKs, passwords or secret
subscription tokens.

## Update

```bash
sudo bpc-update
```

The updater:

1. repairs command links for the currently active release;
2. downloads and verifies the latest release bundle;
3. exits without changing state when already current;
4. backs up `/etc/bpc-connect` before switching versions;
5. installs the new immutable release;
6. switches `/opt/bpc/current`;
7. runs Stage 4.5 canonical migration before BPC runtime reconciliation;
8. reconciles only BPC-owned/legacy-BPC runtime;
9. validates enabled transports and health checks.

If release validation fails, the existing updater restores the previous release
pointer and BPC state backup and attempts to restore the prior BPC runtime.

Stage 4.5 does not intentionally remove external interfaces, routes, rules,
WireGuard peers or firewall state during update.

## Legacy BP Gateway workflow

The pre-canonical commands that created a BP Gateway as a Device record are no
longer write-capable:

```text
bpc-node gateway create
bpc-node gateway grant
bpc-node gateway ungrant
bpc-node gateway remove
```

They fail with a migration message. Existing records can be inspected with:

```bash
bpc-node gateway list
```

Future routed-site provisioning uses `Node(site_router)` and Node-owned
`advertised_routes`; its new data plane is outside Stage 4.5.

## Release pipeline

CI on pull requests and `main` validates:

- Python 3.11, 3.12 and 3.13;
- Ruff;
- pytest;
- Go tests, vet and cross-builds;
- ShellCheck;
- config rendering;
- Python package build;
- deployment bundle generation.

The Release workflow runs after successful CI on `main`. The version from
`pyproject.toml` becomes `v<version>`.

Release assets include:

```text
bpc-connect-<version>-deploy.tar.gz
bpc-connect-deploy.tar.gz
SHA256SUMS
Python wheel / source distribution
```

## Versioning

BPC uses semantic versions. A release version change belongs in a tested pull
request. After merge, successful main-branch CI publishes the matching release.
