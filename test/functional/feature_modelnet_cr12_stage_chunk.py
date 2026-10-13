#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""btx-hcpd reads a CR12 import chunk up to the engine's stage cap.

HcpEngine admits POST /institutional/imports/chunks bodies up to
HCP_CR12_MAX_STAGE_BYTES (16 MiB) and holds every other request to
max_body_bytes (1 MiB). The daemon's read cap follows the same rule: a chunk
up to 16 MiB reaches the engine, one byte more gets the engine's 413, and any
other request over the 1 MiB bound is still dropped before it is read.

Isolated loopback btx-hcpd only.
"""

import http.client
import json
import socket
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, get_datadir_path

API_BASE = "https://exchange.example/btx/hcp/v1"
VERIFIER = "pkce-verifier-demo-aaaa"
PORT = 18831
CHUNKS = "/institutional/imports/chunks"
MIB = 1024 * 1024
STAGE_CAP = 16 * MIB  # HCP_CR12_MAX_STAGE_BYTES
DROPPED = "dropped"


class ModelNetCr12StageChunk(BitcoinTestFramework):
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
        d = Path(get_datadir_path(self.options.tmpdir, 0)) / "stage"
        d.mkdir(parents=True, exist_ok=True)
        self.proc_log = open(d / "hcpd.log", "w", encoding="utf-8")
        argv = [str(self.hcpd), f"-bind=127.0.0.1:{PORT}", f"-datadir={d}", "-instance=stage", "-finance=1"]
        self.proc = subprocess.Popen(argv, stdout=self.proc_log, stderr=subprocess.STDOUT)
        for _ in range(50):
            if self.proc.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
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

    def _get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=5) as r:
            return json.loads(r.read().decode())

    def _lab_token(self):
        pkce = self._get(f"/lab/pkce?verifier={VERIFIER}")
        auth = self._get("/lab/authorize?" + urllib.parse.urlencode({
            "account": "account-demo",
            "client_id": "client-demo",
            "redirect": "https://app.example/cb",
            "state": "state-1",
            "challenge": pkce["challenge"],
        }))
        tok = self._get("/lab/token?" + urllib.parse.urlencode({
            "code": auth["code"],
            "verifier": VERIFIER,
            "redirect": "https://app.example/cb",
        }))
        return tok["access_token"]

    def _send(self, token, method, path, size):
        """Send `size` body bytes. Return (status, body), or (DROPPED, b"") if the
        daemon closed the connection without an HTTP response."""
        route = path.split("?", 1)[0].removeprefix("/btx/hcp/v1")
        proof = self._get("/lab/dpop?" + urllib.parse.urlencode({
            "htm": method,
            "htu": API_BASE + route,
            "access_token": token,
        }))
        headers = {
            "Authorization": "Bearer " + token,
            "DPoP": json.dumps(proof, separators=(",", ":")),
            "Content-Type": "application/octet-stream",
        }
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
        try:
            conn.request(method, path, body=b"a" * size, headers=headers)
            r = conn.getresponse()
            result = (r.status, r.read())
        except (ConnectionError, http.client.HTTPException):
            result = (DROPPED, b"")
        finally:
            conn.close()
        self.log.info(f"{method} {path} {size} bytes: {result[0]}")
        return result

    def run_test(self):
        self._start()
        try:
            token = self._lab_token()

            self.log.info("A chunk up to the stage cap reaches the engine")
            for path, size in (
                (CHUNKS, 64 * 1024),
                (CHUNKS, 2 * MIB),
                ("/btx/hcp/v1" + CHUNKS, 2 * MIB),
                (CHUNKS, STAGE_CAP),
            ):
                status, body = self._send(token, "POST", path, size)
                assert_equal(status, 201)
                assert_equal(json.loads(body)["length"], size)

            self.log.info("One byte over the stage cap gets the engine's 413, not a dropped connection")
            status, body = self._send(token, "POST", CHUNKS, STAGE_CAP + 1)
            assert_equal(status, 413)
            assert_equal(json.loads(body)["error"]["code"], "BODY_TOO_LARGE")

            self.log.info("Every other request keeps the max_body_bytes read cap")
            for method, path in (
                ("POST", "/institutional/imports/validate"),
                ("POST", f"/institutional/imports/validate?next={CHUNKS}"),
                ("PUT", CHUNKS),
            ):
                status, _ = self._send(token, method, path, 2 * MIB)
                assert_equal(status, DROPPED)

            self.log.info("The daemon is still serving")
            status, _ = self._send(token, "POST", CHUNKS, 64 * 1024)
            assert_equal(status, 201)
        finally:
            self._stop()


if __name__ == "__main__":
    ModelNetCr12StageChunk(__file__).main()
