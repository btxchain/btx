#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""btx-hcpd gives each request a total read deadline.

The daemon serves one connection at a time. SO_RCVTIMEO (2 s) bounds a single
recv(), so a client that sends one byte a second never trips it. Without a
total deadline such a client holds the daemon, and every other client waits,
for as long as it keeps sending; SIGTERM waits too.

Isolated loopback btx-hcpd only.
"""

import socket
import subprocess
import threading
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, get_datadir_path

PORT = 18832
HOLD = 15  # how long the slow client keeps sending, in seconds
DEADLINE = 5  # HCP_REQUEST_READ_DEADLINE


class ModelNetHcpdSlowClient(BitcoinTestFramework):
    def set_test_params(self):
        # HCP-only: no btxd/modeld.
        self.num_nodes = 0
        self.setup_clean_chain = True
        self.proc = None
        self.proc_log = None

    def setup_network(self):
        pass

    def setup_nodes(self):
        pass

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        builddir = self.config["environment"].get("BUILDDIR")
        self.hcpd = Path(builddir) / "bin" / "btx-hcpd"
        if not self.hcpd.is_file():
            raise SkipTest("btx-hcpd not found")

    def _start(self):
        d = Path(get_datadir_path(self.options.tmpdir, 0)) / "slow"
        d.mkdir(parents=True, exist_ok=True)
        self.proc_log = open(d / "hcpd.log", "a", encoding="utf-8")
        self.proc = subprocess.Popen([str(self.hcpd), f"-bind=127.0.0.1:{PORT}", f"-datadir={d}"],
                                     stdout=self.proc_log, stderr=subprocess.STDOUT)
        for _ in range(50):
            if self.proc.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
                time.sleep(0.5)  # let the daemon finish with the probe connection
                return
            except OSError:
                time.sleep(0.1)
        raise AssertionError("btx-hcpd did not start")

    def _stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.proc_log is not None:
            self.proc_log.close()

    def _get_profile(self):
        start = time.monotonic()
        with socket.create_connection(("127.0.0.1", PORT), timeout=HOLD + 15) as s:
            s.sendall(b"GET /profile HTTP/1.1\r\nHost: x\r\n\r\n")
            data = b""
            while chunk := s.recv(65536):
                data += chunk
        return time.monotonic() - start, data.split(b"\r\n", 1)[0]

    def _slow_client(self, closed_at):
        """Send a request line, then one header byte a second for HOLD seconds."""
        start = time.monotonic()
        with socket.create_connection(("127.0.0.1", PORT)) as s:
            s.sendall(b"GET /profile HTTP/1.1\r\n")
            s.settimeout(1)
            while time.monotonic() - start < HOLD:
                try:
                    if s.recv(1) == b"":
                        closed_at.append(time.monotonic() - start)
                        return
                except socket.timeout:
                    pass
                try:
                    s.sendall(b"X")
                except OSError:
                    closed_at.append(time.monotonic() - start)
                    return

    def run_test(self):
        self._start()
        try:
            elapsed, status = self._get_profile()
            assert_equal(status, b"HTTP/1.1 200 X")

            self.log.info("A slow client is dropped at the deadline and the next request is served")
            closed_at = []
            slow = threading.Thread(target=self._slow_client, args=(closed_at,))
            slow.start()
            time.sleep(0.3)
            elapsed, status = self._get_profile()
            slow.join()
            assert_equal(status, b"HTTP/1.1 200 X")
            assert elapsed < DEADLINE + 3, f"next request waited {elapsed:.1f} s"
            assert closed_at and closed_at[0] < DEADLINE + 3, f"slow client closed at {closed_at}"

            self.log.info("SIGTERM does not wait for a slow client")
            slow = threading.Thread(target=self._slow_client, args=([],))
            slow.start()
            time.sleep(0.5)
            start = time.monotonic()
            self.proc.terminate()
            self.proc.wait(timeout=HOLD + 15)
            stopped = time.monotonic() - start
            slow.join()
            assert_equal(self.proc.returncode, 0)
            assert stopped < 4, f"btx-hcpd took {stopped:.1f} s to stop"
        finally:
            self._stop()


if __name__ == "__main__":
    ModelNetHcpdSlowClient(__file__).main()
