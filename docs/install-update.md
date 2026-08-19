# Install and update lifecycle

BPC nodes are installed from versioned GitHub Release bundles rather than directly from a mutable checkout.

## Filesystem layout

```text
/opt/bpc/
  releases/
    <version>/
  current -> /opt/bpc/releases/<active-version>

/etc/bpc-connect/
  install.env
  ru-node/
    config.json
    client.env
    gateway-transport.yaml
    awg/
      client.conf
      clash-verge.yaml
    wg/
      client.conf
      clash-verge.yaml

/var/backups/bpc/
  state-<timestamp>-<version>.tar.gz
```

Application releases are immutable directories under `/opt/bpc/releases`. Runtime credentials and generated configuration live outside the release tree under `/etc/bpc-connect`, so an application update does not regenerate transport credentials.

## Fresh RU-node installation

Use `www.bing.com` as the tested REALITY target for the pinned Xray runtime:

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh \
  | sudo bash -s -- --role ru-node --reality-server-name www.bing.com
```

You may provision AWG and native WireGuard in the same install:

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh \
  | sudo bash -s -- \
      --role ru-node \
      --reality-server-name www.bing.com \
      --public-host 203.0.113.10 \
      --port 443 \
      --with-awg \
      --awg-port 443 \
      --with-wg \
      --wg-port 51820
```

Before generating Xray credentials, `bootstrap-ru-node.sh` runs `bpc-check-reality-target.sh`. The preflight verifies DNS resolution and a TLS 1.3 handshake, then rejects Certificate handshake messages above the pinned REALITY parser limit. The known-bad `www.microsoft.com` target is explicitly rejected for Xray 26.3.27 because its Certificate record can exceed 8192 bytes; see [XTLS/Xray-core#6356](https://github.com/XTLS/Xray-core/issues/6356).

The installer performs these steps:

1. installs minimal download/extraction prerequisites;
2. downloads `bpc-connect-deploy.tar.gz` from the latest GitHub Release;
3. downloads `SHA256SUMS` and verifies the deployment bundle;
4. extracts the version into `/opt/bpc/releases/<version>`;
5. atomically points `/opt/bpc/current` at that release;
6. provisions the requested role on first install, including REALITY target preflight;
7. reconciles the available BPC commands under `/usr/local/sbin`;
8. optionally provisions the selected secondary transports.

Installed commands include:

```text
bpc-status
bpc-update
bpc-enable-awg
bpc-enable-wg
```

## Status

```bash
sudo bpc-status
```

The status command intentionally does not print UUIDs, private keys, PSKs, or other client credentials. Optional transports report `disabled`, `active` or a failed health state without exposing secrets.

## Update

```bash
sudo bpc-update
```

The updater:

1. repairs command symlinks for the active release before checking the remote version;
2. downloads and verifies the latest release bundle;
3. exits without changing the release if the active version is already current;
4. creates a backup of `/etc/bpc-connect` when switching versions;
5. installs the new release into a new immutable release directory;
6. switches `/opt/bpc/current` to the new version and reconciles command links;
7. validates all currently enabled managed transports;
8. restarts Xray and runs the health check again.

Optional transports are not enabled implicitly by an update. Existing AWG/WireGuard state remains under `/etc/bpc-connect` and is health-checked only when its `enabled` marker exists.

If either health check fails, the updater restores the previous release pointer and BPC state backup, repairs command links for the restored release, then attempts to restore the prior runtime.

## Release pipeline

`CI` runs on pull requests and `main`. It validates Python 3.11-3.13, Ruff, pytest, ShellCheck, Mihomo config generation, Python package build, and deployment bundle creation.

The `Release` workflow runs only after a successful `CI` run on `main`. The stable version from `pyproject.toml` becomes the GitHub Release tag (`v<version>`). If that release already exists, the workflow does not republish it.

A release contains at least:

```text
bpc-connect-<version>-deploy.tar.gz
bpc-connect-deploy.tar.gz
SHA256SUMS
Python wheel / source distribution
```

The stable asset name `bpc-connect-deploy.tar.gz` allows installed nodes to resolve the latest release without parsing the GitHub API.

## Versioning

BPC uses semantic versions. To publish a new release, change the version in `pyproject.toml` in a tested pull request and merge it to `main`. A successful main-branch CI run then publishes that version automatically.
