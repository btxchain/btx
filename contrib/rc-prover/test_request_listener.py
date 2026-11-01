#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Real loopback listener regression; no authentication, node or GPU."""
import socket
import struct
import subprocess
import sys
import time


def main():
    process = subprocess.Popen([sys.argv[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    peers = []
    try:
        port = int(process.stdout.readline())
        def connect():
            return socket.create_connection(("127.0.0.1", port), timeout=3)
        def request(data=b"status\n"):
            with connect() as peer:
                peer.sendall(data)
                assert peer.recv(32) == b"ok\n"
        peers = [connect() for _ in range(4)]
        start = time.monotonic()
        request()
        assert time.monotonic() - start < 1, "idle peers blocked complete request"
        for _ in range(40):
            peer = connect()
            peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0))
            peer.close()
        request()
        with connect() as peer:
            peer.sendall(b"x" * 65537 + b"\n")
            try:
                assert peer.recv(32) == b"", "oversized line was accepted"
            except ConnectionResetError:
                pass
        request()
        with connect() as peer:
            peer.sendall(b"incomplete")
            start = time.monotonic()
            assert peer.recv(32) == b"", "partial line was not expired"
            elapsed = time.monotonic() - start
            assert 1.5 <= elapsed < 3, "wrong framing deadline"
        request()
        with connect() as waiting:
            waiting.sendall(b"pend")
            # A synthetic dispatch longer than the framing timeout must not
            # expire another peer's partial request while the worker is busy.
            time.sleep(0.05)
            request(b"sleep\n")
            waiting.sendall(b"ing\n")
            assert waiting.recv(32) == b"ok\n", "dispatch consumed framing deadline"
        with connect() as peer:
            peer.sendall(b"quit\n")
        assert process.wait(timeout=3) == 0
        print("idle-peer isolation, reset recovery, size/deadline limits and dispatch pause passed")
        return 0
    finally:
        for peer in peers:
            peer.close()
        if process.poll() is None:
            process.kill()
        _, errors = process.communicate(timeout=3)
        if errors:
            print(errors, file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
