# Windows Connect: minimal automatic connection client

The existing Windows Agent provides the connection service, embedded WireGuard,
tray UI, automatic startup after Connect, and automatic selection of enrolled
gateway paths. Disconnect stops the service and disables automatic startup.
Closing the window leaves the service running. This iteration keeps that model;
no manual gateway picker, resource browser or server provisioning is added.

## Status contract

- Disconnected: the Agent service is stopped or missing.
- Connecting: service running, waiting for the first usable tunnel.
- Reconnecting: a previous handshake exists, but current tunnel/transport evidence
  is missing, stale, unhealthy or awaiting a handshake after a gateway change.
- Connected: recent tunnel telemetry and handshake, recent transport telemetry,
  and a reachable selected endpoint. A reachable standby alone is insufficient.

Runtime/transport updates must be at most 10 seconds old, handshake at most
180 seconds old; at most five seconds of future clock skew is accepted. Gateway
changes publish node_changed_at. A handshake preceding that change cannot mark
the connection ready. Switching UDP ports on the same gateway does not require
this new-handshake condition. Timestamp resolution is one second.

The automatic gateway summary counts distinct Node identities, not transport
ports. Legacy telemetry without Node identities shows the automatic-selection
label without inventing a gateway count. Green status proves a usable gateway
tunnel, not availability or Access permission for every LAN application.

## Validation

Run on Windows without installing a service or touching network adapters:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/test-windows-ui.ps1
go test ./cmd/bpc-agent ./internal/agentctl ./internal/wgshim
go vet ./cmd/bpc-agent ./internal/agentctl ./internal/wgshim
go build -o dist/bpc-agent.exe ./cmd/bpc-agent
```

The PowerShell checks execute the shipped presentation functions and parse the
production UI script without opening a window. CI runs them under Windows
PowerShell 5.1. Existing transport tests include independent gateway failover,
path recovery cooldown, and preserving the overlay worker during path changes.
These are isolated socket tests; they do not require live VPS firewall changes.

Local validation for this iteration: Windows build/version, go vet, 50 Python
Agent regressions and 15 PowerShell status/summary cases passed. Actual desktop
click-through, UAC cancellation, suspend/resume, installer changes and live
gateway failure on the user's laptop are not covered by these checks. Before
distributing an update, verify these manually with an independent management
path and retained previous executable. Do not silently replace a working Agent.

Automatic gateway selection does not replicate remote TCP/NAT state. Existing
application sessions may reconnect after a gateway change. Live acceptance
through both deployed gateways remains pending the separate ru-01 update.

ECC verification-loop and windows-desktop-e2e guidance informed the checks and
stable accessible names for Connect/Disconnect. These tests are not a claim of
full desktop UI Automation coverage.
