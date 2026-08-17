# BPC Connect

Fail-closed multi-transport connectivity bridge for the first BPC milestone: **Georgia -> Russia -> corporate VPN / home infrastructure**.

## v0.1 scope

- Mihomo TUN gateway.
- Ordered fallback between VLESS/REALITY, AmneziaWG and Tailscale.
- Config generator with safety validation.
- Fail-closed policy: no automatic DIRECT route from the work gateway.
- nftables kill-switch template.
- GitHub Actions CI, tests and release artifacts.

This repository intentionally separates the BPC underlay from the corporate VPN. The corporate VPN remains on the work laptop; BPC runs on a separate gateway and provides it with a Russian egress path.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check .
```

Validate and render the example:

```bash
bpc-connect validate config/gateway.example.yaml
bpc-connect render config/gateway.example.yaml -o build/mihomo/config.yaml
```

## Deployment status

Milestone 1 is repository/CI/config generation. `deploy/bootstrap-gateway.sh` currently installs only safe base prerequisites. It deliberately does **not** enable routing or firewall rules automatically until interface names and the real RU test node are known and validated.

See `docs/architecture.md` and `docs/test-plan.md`.

## Security

- Never commit production UUIDs, private keys, Tailscale auth keys, Mihomo API secrets or real infrastructure credentials.
- Treat the generated Mihomo configuration as a secret.
- The work gateway must fail closed: transport failure must not expose the work laptop directly through the Georgia ISP.
