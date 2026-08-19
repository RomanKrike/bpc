# Automatic Clash failover

BPC can render one Clash Verge Rev profile containing every enabled RU-node transport:

```text
/etc/bpc-connect/ru-node/clash-verge-auto.yaml
```

The profile is root-only because it contains client credentials.

## Default order

```text
AmneziaWG -> WireGuard -> VLESS/REALITY
```

The `BPC-AUTO` Mihomo group uses `fallback` semantics. Each transport is periodically tested through an HTTPS 204 endpoint. If the preferred transport is unavailable, Mihomo selects the next healthy transport in the configured order. There is no `DIRECT` entry.

Rebuild the profile manually after changing transport state:

```bash
sudo bpc-render-clash
```

Override the preference order when rendering:

```bash
BPC_CLASH_TRANSPORT_ORDER="wg awg vless" sudo -E bpc-render-clash
```

Supported order tokens are `awg`, `wg` and `vless`.

Health checks can be tuned through:

```text
BPC_CLASH_HEALTH_URL
BPC_CLASH_HEALTH_INTERVAL
BPC_CLASH_HEALTH_TIMEOUT
BPC_CLASH_MAX_FAILED_TIMES
```

Defaults are a 15-second interval, 5-second timeout and two failed checks before a forced health recheck.

After importing the aggregate profile in Clash Verge Rev, traffic routed to `BPC-AUTO` no longer requires manually switching between the individual transport profiles.
