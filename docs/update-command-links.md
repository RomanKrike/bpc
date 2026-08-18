# Command-link reconciliation

BPC installs operator commands as symlinks in `/usr/local/sbin` that point to scripts in the current release under `/opt/bpc/current/deploy`.

`bpc-update` reconciles these symlinks on every invocation before checking whether the downloaded release version matches the installed version. This ensures commands introduced by a newer release become available even when the upgrade itself was executed by an older updater.
