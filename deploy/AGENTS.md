# Host mutation and compatibility boundary

Follow root AGENTS.md and docs/specs/INVARIANTS.md. Read existing ownership,
Access, migration and rollback helpers before changing installers or scripts.

- Require explicit BPC ownership before reconciling network objects. An expected
  interface name alone is not ownership. Never adopt unrelated host networking.
- Preserve compatibility reads and backup-first canonical migration; avoid new
  legacy writes. Do not regenerate identities during update/reconcile.
- Test authorization in both directions, including established connections and
  revoked responders. AllowedIPs alone never proves server-side enforcement.
- Preserve watchdog-before-mutation and exact tagged cleanup for temporary probes.
- Linux namespace/systemd checks run in CI or an isolated authorized test host.
  Never execute install/update/fault scripts on real infrastructure as a shortcut.
