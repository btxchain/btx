#!/usr/bin/env python3
"""Read-only loopback preview, never a node RPC proxy. Native release does not use HTTP."""
from __future__ import annotations
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

class Handler(SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'none'; worker-src 'self'; font-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'")
        super().end_headers()
    def do_GET(self) -> None:
        host=self.headers.get('Host','')
        if host not in {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}:
            self.send_error(403,'Loopback host required');return
        super().do_GET()
    def list_directory(self, path: str):
        self.send_error(403,'Directory listing disabled');return None

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--web',type=Path,default=Path(__file__).resolve().parents[2]/'gui/atlas/web')
    args=parser.parse_args()
    if not 1024<=args.port<=65535: parser.error('Port must be 1024–65535')
    web=args.web.resolve(strict=True)
    server=ThreadingHTTPServer(('127.0.0.1',args.port),partial(Handler,directory=str(web)))
    print(f'BTX Atlas synthetic preview: http://127.0.0.1:{args.port}/',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
