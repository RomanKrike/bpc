# AWG update behavior

`bpc-update` upgrades the BPC release and preserves `/etc/bpc-connect`. An already enabled AWG transport keeps its generated keys and runtime configuration; enabling AWG is explicit and is never silently turned on by an update.
