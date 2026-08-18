# AmneziaWG security notes

- AWG server and client keys are generated on the RU node and stored only under `/etc/bpc-connect/ru-node/awg` with root-only permissions.
- The generated Clash profile contains a client private key and preshared key; never commit or publish it.
- The userspace runtime is pinned by both image tag and digest so a future `latest` image cannot silently change the deployed protocol implementation.
- BPC only adds forwarding rules for the dedicated `10.251.0.0/24` AWG subnet and masquerades that subnet through the RU node default IPv4 interface.
- Xray continues to own TCP/443. AWG owns UDP/443, so enabling AWG does not replace or reconfigure the existing Xray listener.
