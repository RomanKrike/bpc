#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


class SubscriptionHandler(BaseHTTPRequestHandler):
    server_version = "BPCSubscription/1.0"
    protocol_version = "HTTP/1.1"

    def _serve(self, include_body: bool) -> None:
        token = Path(self.server.token_file).read_text(encoding="utf-8").strip()  # type: ignore[attr-defined]
        expected_path = f"/{token}/clash.yaml"
        if urlsplit(self.path).path != expected_path:
            self.send_error(404)
            return

        profile = Path(self.server.profile_file).read_bytes()  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Content-Length", str(len(profile)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Disposition", 'inline; filename="bpc-clash.yaml"')
        self.end_headers()
        if include_body:
            self.wfile.write(profile)

    def do_GET(self) -> None:  # noqa: N802
        self._serve(include_body=True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(include_body=False)

    def log_message(self, format: str, *args: object) -> None:
        # Do not log request paths: the URL path contains the subscription token.
        return


class SubscriptionServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve the BPC Clash profile over tokenized HTTPS")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--cert-file", required=True)
    parser.add_argument("--key-file", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1024 <= args.port <= 65535:
        raise SystemExit("port must be between 1024 and 65535")

    for path in (args.profile, args.token_file, args.cert_file, args.key_file):
        if not Path(path).is_file():
            raise SystemExit(f"required file is missing: {path}")

    server = SubscriptionServer((args.listen, args.port), SubscriptionHandler)
    server.profile_file = args.profile
    server.token_file = args.token_file

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=args.cert_file, keyfile=args.key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
