#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""btx-guardd keeps serving when a local client misbehaves.

Loopback only. No btxd is started.
- A client that resets the connection while replies are written does not end the daemon.
- A line longer than 4096 bytes is BTX035_LIMIT_EXCEEDED, and the connection is closed.
- An idle connection does not hold the guard past the node's 2 s client timeout.
- A full permit table refuses PREPARE with BTX035_LIMIT_EXCEEDED instead of growing.
"""

import socket
import struct
import subprocess
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

MAX_LINE_BYTES = 4096  # kMaxLineBytes in src/btx-guardd.cpp
MAX_PERMITS = 1024  # GuardTable::kMaxPermits
CLIENT_TIMEOUT = 2  # GuardClientExchange uses a 2 s send and receive timeout
FINGERPRINT = "a" * 96


class ModelNetGuarddTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0
        self.setup_clean_chain = True
        self.guardd_proc = None

    def setup_network(self):
        pass

    def setup_nodes(self):
        pass

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        exeext = self.config["environment"].get("EXEEXT", "")
        self.guardd = Path(self.config["environment"]["BUILDDIR"]) / "bin" / f"btx-guardd{exeext}"
        if not self.guardd.is_file():
            raise SkipTest("btx-guardd not found")

    def start_guardd(self):
        self.port = p2p_port(0)
        self.guardd_proc = subprocess.Popen([str(self.guardd), "--port", str(self.port)],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            assert self.guardd_proc.poll() is None, "btx-guardd exited at startup"
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise AssertionError("btx-guardd did not listen")

    def ask(self, line):
        """One request per connection, like the node's guard client."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=CLIENT_TIMEOUT) as s:
            s.sendall(line.encode() + b"\n")
            reply = b""
            while b"\n" not in reply:
                chunk = s.recv(4096)
                if not chunk:
                    break
                reply += chunk
        return reply.decode().strip()

    def assert_alive(self):
        assert self.guardd_proc.poll() is None, f"btx-guardd exited with {self.guardd_proc.returncode}"

    def stop_guardd(self):
        if self.guardd_proc is not None and self.guardd_proc.poll() is None:
            self.guardd_proc.terminate()
            try:
                self.guardd_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.guardd_proc.kill()

    def run_test(self):
        self.start_guardd()
        try:
            self.check_guardd()
        finally:
            self.stop_guardd()

    def check_guardd(self):
        self.log.info("A permit is one use")
        verb, secret, _, _ = self.ask(f"PREPARE research.run {FINGERPRINT} 1").split()
        assert_equal(verb, "PERMIT")
        assert self.ask(f"EXECUTE {secret}").startswith("RECEIPT ")
        assert_equal(self.ask(f"EXECUTE {secret}"), "ERR BTX035_REPLAY")

        self.log.info("A client that resets the connection while replies are written does not end the daemon")
        for _ in range(3):
            s = socket.create_connection(("127.0.0.1", self.port))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            try:
                s.sendall(b"NOOP\n" * 20000)
            except OSError:
                pass  # the daemon may drop a client that does not read its replies
            s.close()
            time.sleep(0.5)
            self.assert_alive()
        assert_equal(self.ask("NOOP"), "ERR BTX035_SCHEMA")

        self.log.info("A line longer than the cap is refused and the connection is closed")
        with socket.create_connection(("127.0.0.1", self.port), timeout=CLIENT_TIMEOUT) as s:
            s.sendall(b"A" * (MAX_LINE_BYTES + 1))
            reply = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                reply += chunk
        assert_equal(reply, b"ERR BTX035_LIMIT_EXCEEDED\n")
        self.assert_alive()

        self.log.info("An idle connection does not hold the guard past the node's client timeout")
        with socket.create_connection(("127.0.0.1", self.port)) as idle:
            time.sleep(0.1)
            start = time.time()
            assert self.ask(f"PREPARE research.run {FINGERPRINT} 1").startswith("PERMIT ")
            assert time.time() - start < CLIENT_TIMEOUT
            idle.settimeout(CLIENT_TIMEOUT)
            assert_equal(idle.recv(16), b"")

        self.log.info("A full permit table refuses PREPARE instead of growing")
        replies = []
        with socket.create_connection(("127.0.0.1", self.port), timeout=CLIENT_TIMEOUT) as s:
            with s.makefile("rb") as f:
                for _ in range(MAX_PERMITS // 64):
                    s.sendall(f"PREPARE research.run {FINGERPRINT} 1\n".encode() * 64)
                    replies += [f.readline().decode().strip() for _ in range(64)]
        permits = sum(r.startswith("PERMIT ") for r in replies)
        refused = [r for r in replies if not r.startswith("PERMIT ")]
        # The two permits issued above are still within their 30 s life.
        assert_equal(permits, MAX_PERMITS - 2)
        assert_equal(refused, ["ERR BTX035_LIMIT_EXCEEDED"] * 2)
        self.assert_alive()


if __name__ == "__main__":
    ModelNetGuarddTest(__file__).main()
