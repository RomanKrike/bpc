# Secure Clash subscription

BPC can publish `/etc/bpc-connect/ru-node/clash-verge-auto.yaml` as a tokenized HTTPS subscription for Clash Verge Rev or another compatible Mihomo client.

## Requirements

Before enabling the endpoint:

1. Create a DNS A record for a dedicated hostname that points to the RU-node public IPv4 address.
2. Permit inbound TCP/80 for Let's Encrypt HTTP-01 validation and renewal.
3. Permit inbound TCP/8443, or the custom subscription port selected with `--port`.
4. Ensure the aggregate profile exists (`bpc-render-clash`).

TCP/443 remains available to Xray/REALITY. The subscription service therefore uses TCP/8443 by default.

## Enable

```bash
sudo bpc-enable-subscription --hostname sub.example.com
```

Optional parameters:

```text
--port 8443
--email admin@example.com
--skip-dns-check
```

`--skip-dns-check` is intended only for a deliberate trusted reverse-proxy setup where the public subscription hostname does not resolve directly to the RU node.

The enable command:

- verifies DNS by default;
- installs Python, Certbot and required TLS utilities;
- obtains a trusted Let's Encrypt certificate with standalone HTTP-01;
- generates a 64-hex-character (256-bit) random URL token;
- stores token/runtime state under `/etc/bpc-connect/ru-node/subscription` with root-only permissions;
- creates and enables `bpc-subscription.service`;
- performs a local HTTPS self-test before marking the endpoint enabled;
- enables `certbot.timer` and installs a renewal deploy hook that restarts the service after certificate renewal.

## URL

The enable command prints the URL once. To print it later:

```bash
sudo bpc-subscription-url
```

Example shape:

```text
https://sub.example.com:8443/<64-hex-secret>/clash.yaml
```

The token is an access credential. Anyone who obtains this URL can download the aggregate profile and therefore receive the client credentials embedded in it.

`bpc-status` intentionally reports only a redacted endpoint:

```text
Subscription: active (https://sub.example.com:8443/<hidden>/clash.yaml)
```

## Runtime behavior

The HTTPS service reads the aggregate profile on every valid request. Running `bpc-render-clash` replaces the profile atomically, and the next subscription refresh receives the new file without restarting the subscription service.

Only `GET` and `HEAD` against the exact tokenized path return the profile. Other paths return `404`. Request paths are deliberately omitted from service logs so the token is not leaked to the journal.

## Certificate renewal

BPC uses the distribution Certbot timer. The Let's Encrypt HTTP-01 challenge requires inbound TCP/80 to remain reachable during renewal. The renewal hook restarts `bpc-subscription.service` so the process reloads the renewed certificate.

Check renewal scheduling with:

```bash
systemctl status certbot.timer --no-pager
```

Check the subscription service with:

```bash
systemctl status bpc-subscription.service --no-pager
```

## Security notes

- Do not publish the subscription URL in GitHub, tickets, screenshots or shared logs.
- Do not proxy the endpoint through a service that records full URL paths unless its access logs are configured to suppress the secret path.
- Prefer a dedicated hostname for the subscription endpoint.
- The server intentionally does not provide an insecure HTTP profile endpoint.
