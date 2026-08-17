# Install and update lifecycle

BPC nodes are installed from versioned GitHub Release bundles rather than directly from a mutable checkout.

## Filesystem layout

```text
/opt/bpc/
  releases/
    0.1.0/
    0.1.1/
  current -> /opt/bpc/releases/<active-version>

/etc/bpc-connect/
  install.env
  ru-node/
    config.json
    client.env
    gateway-transport.yaml

/var/backups/bpc/
  state-<timestamp>-<version>.tar.gz
```

Application releases are immutable directories under `/opt/bpc/releases`. Runtime credentials and generated configuration live outside the release tree under `/etc/bpc-connect`, so an application update does not regenerate VLESS/REALITY credentials.

## Fresh RU-node installation

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh \
  | sudo bash -s -- --role ru-node --reality-server-name YOUR_REALITY_TARGET
```

You may explicitly specify the public address and Xray port:

```bash
curl -fsSL https://raw.githubusercontent.com/RomanKrike/bpc/main/install.sh \
  | sudo bash -s -- \
      --role ru-node \
      --reality-server-name YOUR_REALITY_TARGET \
      --public-host 203.0.113.10 \
      --port 443
```

The installer performs these steps:

1. installs minimal download/extraction prerequisites;
2. downloads `bpc-connect-deploy.tar.gz` from the latest GitHub Release;
3. downloads `SHA256SUMS` and verifies the deployment bundle;
4. extracts the version into `/opt/bpc/releases/<version>`;
5. atomically points `/opt/bpc/current` at that release;
6. provisions the requested role on first install;
7. installs `bpc-status` and `bpc-update` commands.

## Status

```bash
sudo bpc-status
```

The status command intentionally does not print VLESS UUIDs, REALITY keys, or other client credentials.

## Update

```bash
sudo bpc-update
```

The updater:

1. downloads and verifies the latest release bundle;
2. exits without changes if the active version is already current;
3. creates a backup of `/etc/bpc-connect`;
4. installs the new release into a new immutable release directory;
5. switches `/opt/bpc/current` to the new version;
6. validates the existing managed Xray configuration;
7. restarts Xray and runs the health check again.

If either health check fails, the updater restores the previous release pointer and BPC state backup, then attempts to restart the previous Xray service configuration.

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
