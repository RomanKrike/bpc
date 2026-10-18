# A simple Windows network download

`https://CONTROLLER:8444/bpc/` serves a static download page. It requires no
invitation flow. The prepared EXE contains public network settings, the existing
GUI Agent and Wintun. It contains no password, enrollment token, Device private
key or network authorization. Users sign in through the existing graphical login;
each installation generates fresh Device identity and receives that user's Access.

Use an installer, not portable mode: Windows needs an administrator-approved
network driver and a background service. Users download, run, approve Windows,
sign in and use Connect. The application appears in Start and selects gateways
automatically. Closing the window leaves its existing background-service behavior.

Build from independently verified Agent and driver artifacts:

```text
python scripts/build-windows-network-installer.py
  --agent VERIFIED_AGENT.exe --agent-sha256 VERIFIED_SHA256
  --wintun VERIFIED_WINTUN.dll --wintun-sha256 VERIFIED_SHA256
  --update-public-key UPDATE_PUBLIC.pem
  --controller https://PRIMARY:8444 --controller https://SECONDARY:8444
  --device Windows-PC --output NEW_OUTPUT_DIRECTORY
```

The output directory must be new. Publish its four files atomically as
`control/client-download/` on the chosen download Controller. The control API
serves only index.html, style.css, BPC-Connect-Setup.exe and SHA256SUMS; it does not
expose arbitrary files, directories, symlinks, credentials or configuration files.
The page uses external CSS and a restrictive Content Security Policy. Do not place
the account password on the public page or inside the EXE. Deliver it separately.

This changes no network listener or firewall port. Existing Xray/REALITY use of443
must remain intact; deployments using API8444 retain that explicit port in the URL.
The download page lives on the chosen Controller; installed clients use both
configured controllers. Protect API code rollout with an independent absolute UTC
rollback and retain the exact previous source files. Never restore cluster DB state
for a page rollback.

The executable preserves its GUI subsystem and BP icon. Appending bootstrap and
driver payloads does not provide Authenticode signing: the current preview is
unsigned and Windows may display a warning. Existing Moonlight session continuity
across gateway changes remains unproven; application reconnection may be necessary.

Regression tests cover payload/schema, checksums, invalid controller origins,
non-overwrite behavior, HTTP download, headers, and rejection of secret/traversal
paths. A clean Windows installation and first Device registration still require
interactive acceptance on a separate machine, not replacement of an active Device.
