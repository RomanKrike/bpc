#!/usr/bin/env python3
from __future__ import annotations

import argparse
import signal
import socketserver
import threading


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        while True:
            try:
                data = self.request.recv(65535)
            except TimeoutError:
                continue
            if not data:
                return
            self.request.sendall(data)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(data, self.client_address)


class ReuseTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ReuseUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser(description="BPC acceptance TCP/UDP echo probe")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=19090)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")

    tcp = ReuseTCPServer((args.listen, args.port), TCPHandler)
    udp = ReuseUDPServer((args.listen, args.port), UDPHandler)
    threads = [
        threading.Thread(target=tcp.serve_forever, daemon=True),
        threading.Thread(target=udp.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()

    stopping = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        stopping.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        stopping.wait()
    finally:
        tcp.shutdown()
        udp.shutdown()
        tcp.server_close()
        udp.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
