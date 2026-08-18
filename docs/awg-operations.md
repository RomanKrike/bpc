# AWG operational commands

```bash
bpc-status
bpc-enable-awg
docker ps --filter name=bpc-awg
docker exec bpc-awg awg show awg0
docker logs --tail 100 bpc-awg
systemctl status bpc-awg-firewall.service --no-pager
```

These commands do not require printing or copying client private keys.
