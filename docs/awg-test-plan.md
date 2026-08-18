# AWG2 end-to-end test plan

1. Confirm `bpc-status` is healthy before enabling AWG.
2. Permit inbound UDP/443 in the VPS/provider firewall.
3. Run `bpc-enable-awg` and confirm the container and `awg0` interface are healthy.
4. Import `/etc/bpc-connect/ru-node/awg/clash-verge.yaml` into Clash Verge Rev.
5. Keep Clash TUN and System Proxy disabled for the selective-proxy test.
6. Select `BPC-RUSSIA -> BPC-RU-AWG-01`.
7. Run `curl.exe --proxy socks5h://127.0.0.1:7897 https://ifconfig.me` on Windows.
8. Confirm the returned address is the RU VPS public IPv4.
9. Run `docker exec bpc-awg awg show awg0` and confirm a recent handshake and transfer counters.
10. Only after this baseline passes, add CPS/I1-I5 obfuscation profiles and automatic transport fallback.
