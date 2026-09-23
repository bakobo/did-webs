#!/usr/bin/env python3
"""Serve M7 artifacts on localhost HTTPS through a local CONNECT proxy.

The proxy keeps the DID host and implicit port 443 intact for the third-party
resolver without changing DNS or needing a privileged listener. Both sockets
bind only to loopback. The TLS certificate must name the DID host.
"""

from __future__ import annotations

import argparse
import select
import socket
import socketserver
import ssl
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar


class ArtifactHandler(SimpleHTTPRequestHandler):
    extensions_map: ClassVar[dict[str, str]] = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".cesr": "application/cesr",
    }


PROXY_TARGET_INVALID = b"e.input.format.proxy-target.f: The proxy accepts CONNECT only for the configured DID host on port 443.\n"
PROXY_HEADERS_TOO_LARGE = (
    b"e.input.range.proxy-headers.f: The CONNECT headers exceed the 16384-byte limit.\n"
)


def _refuse(
    handler: socketserver.StreamRequestHandler, status: bytes, body: bytes
) -> None:
    handler.wfile.write(
        b"HTTP/1.1 "
        + status
        + b"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n\r\n"
        + body
    )


class Tunnel(socketserver.StreamRequestHandler):
    target_host: str
    target_port: int

    def handle(self) -> None:
        line = self.rfile.readline(4096).decode("ascii", errors="replace").strip()
        allowed = {
            f"CONNECT {self.target_host}:443 HTTP/1.0",
            f"CONNECT {self.target_host}:443 HTTP/1.1",
        }
        if line not in allowed:
            _refuse(self, b"403 Forbidden", PROXY_TARGET_INVALID)
            return
        header_bytes = 0
        while True:
            header = self.rfile.readline(4096)
            header_bytes += len(header)
            if header_bytes > 16384:
                _refuse(
                    self,
                    b"431 Request Header Fields Too Large",
                    PROXY_HEADERS_TOO_LARGE,
                )
                return
            if not header:
                return
            if header in (b"\r\n", b"\n"):
                break
        with socket.create_connection(("127.0.0.1", self.target_port)) as upstream:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
            sockets = (self.connection, upstream)
            while True:
                ready, _, _ = select.select(sockets, [], [])
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (
                        upstream if source is self.connection else self.connection
                    ).sendall(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--host", default="dids.bakobo.com")
    parser.add_argument("--https-port", type=int, default=8443)
    parser.add_argument("--proxy-port", type=int, default=8444)
    args = parser.parse_args()

    handler = partial(ArtifactHandler, directory=str(args.root.resolve()))
    https = ThreadingHTTPServer(("127.0.0.1", args.https_port), handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(args.cert, args.key)
    https.socket = tls.wrap_socket(https.socket, server_side=True)

    class Proxy(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    Proxy.RequestHandlerClass = Tunnel
    Tunnel.target_host = args.host
    Tunnel.target_port = args.https_port
    with Proxy(("127.0.0.1", args.proxy_port), Tunnel) as proxy:
        threading.Thread(target=https.serve_forever, daemon=True).start()
        try:
            proxy.serve_forever()
        finally:
            https.shutdown()
            https.server_close()


if __name__ == "__main__":
    main()
