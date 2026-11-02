#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Real loopback listener regression; no authentication, node or GPU."""
import concurrent.futures
import socket
import struct
import subprocess
import sys
import time
import threading


def main():
    process = subprocess.Popen([sys.argv[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    peers = []
    try:
        port = int(process.stdout.readline())
        def connect(timeout=3):
            return socket.create_connection(("127.0.0.1", port), timeout=timeout)
        def request(data=b"status\n", timeout=3):
            with connect(timeout) as peer:
                peer.sendall(data)
                assert peer.recv(32) == b"ok\n"
        peers = [connect() for _ in range(4)]
        start = time.monotonic()
        request()
        assert time.monotonic() - start < 1, "idle peers blocked complete request"
        for peer in peers:
            peer.close()
        peers = [connect() for _ in range(32)]
        time.sleep(0.1)  # Let the listener fill all pending slots.
        start = time.monotonic()
        request(timeout=6)  # Wait in backlog instead of being reset at capacity.
        elapsed = time.monotonic() - start
        # No slot is freed until an idle peer's 2-second framing budget expires.
        # A missing pending limit would serve this request immediately.
        assert 1 <= elapsed < 6, f"full-slot backpressure missing or too slow: {elapsed:.3f}s"
        print(f"full-slot backpressure: {elapsed:.3f}s", flush=True)
        for peer in peers:
            peer.close()
        peers = []
        # A refresh/reconnect attack must not preempt an admitted partial frame.
        peers = [connect() for _ in range(31)]
        for peer in peers:
            peer.sendall(b"x")
        time.sleep(0.03)
        with connect() as victim:
            victim.sendall(b"sta")
            time.sleep(0.03)
            for peer in peers:
                peer.sendall(b"x")
            time.sleep(0.03)
            with connect() as extra:
                victim.sendall(b"tus\n")
                assert victim.recv(32) == b"ok\n", "admitted partial frame evicted"
        for peer in peers:
            peer.close()
        peers = []
        stop = threading.Event()
        primed = threading.Event()
        churn_errors = []
        def churn():
            slots = []
            try:
                for _ in range(32):
                    peer = connect()
                    peer.sendall(b"x")  # Alternate attack: incomplete non-empty frames.
                    slots.append(peer)
                primed.set()
                index = 0
                while not stop.wait(0.005):
                    slots[index].close()
                    slots[index] = connect(timeout=6)
                    slots[index].sendall(b"x")
                    index = (index + 1) % len(slots)
            except Exception as exc:
                churn_errors.append(str(exc))
                primed.set()
            finally:
                for peer in slots:
                    peer.close()
        attacker = threading.Thread(target=churn)
        attacker.start()
        try:
            assert primed.wait(3), "churn peer setup timed out"
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as clients:
                futures = [clients.submit(request, b"x" * 65536 + b"\n" if i % 4 == 0 else b"status\n", 6)
                           for i in range(16)]
                for future in futures:
                    future.result(timeout=8)
            with connect(timeout=6) as partial:
                partial.sendall(b"sta")
                time.sleep(0.03)
                partial.sendall(b"tus\n")
                assert partial.recv(32) == b"ok\n", "progressing frame lost under churn"
        finally:
            stop.set()
            attacker.join(timeout=8)
        assert not attacker.is_alive() and not churn_errors, churn_errors
        request()
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
        print("idle/full-slot/churn admission, reset recovery, size/deadline limits and dispatch pause passed")
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
