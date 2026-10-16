#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Public download checks for the D09 browser bridge. Loopback only; no btxd.

Run: python3 contrib/modelbridge/test_modelbridge.py
"""
from __future__ import annotations

import http.client
import os
import sys
import tempfile
import threading
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
REF = HERE.parent / "modelnet" / "reference"
for p in (HERE, REF):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

import modelbridge as mb  # noqa: E402
from reference_v11 import encode_resource  # noqa: E402

DIGEST = bytes(range(100, 148))
BIG_SPAN = 64 * 1024 * 1024


class PublicDownload(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.file = Path(tmp.name) / DIGEST.hex() / "0"
        self.file.parent.mkdir()
        env = {"BTX_BRIDGE_PUBLIC_DOWNLOAD": "1", "BTX_BRIDGE_VERIFIED_DIR": tmp.name}
        for patcher in (mock.patch.dict(os.environ, env), mock.patch.object(mb.BridgeHandler, "log_message")):
            patcher.start()
            self.addCleanup(patcher.stop)
        mb._rate.clear()
        self.path = "/%s/f/0" % encode_resource(0, DIGEST).split("://", 1)[1]
        server = mb.LoopbackServer(("127.0.0.1", 0), mb.BridgeHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.port = server.server_address[1]

    def fetch(self, rng=None, method="GET", keep=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            conn.request(method, self.path, headers={"Range": rng} if rng else {})
            resp = conn.getresponse()
            body, received = [], 0
            while True:
                block = resp.read(64 * 1024)
                if not block:
                    break
                received += len(block)
                if keep:
                    body.append(block)
            return resp, b"".join(body), received
        finally:
            conn.close()

    def test_spans_match_file(self):
        data = os.urandom(3 * 1024 * 1024 + 123)
        self.file.write_bytes(data)
        size = len(data)
        for rng, status, first, last in (
            (None, 200, 0, size - 1),
            ("bytes=0-", 206, 0, size - 1),
            ("bytes=1048570-2097160", 206, 1048570, 2097160),
            ("bytes=%d-%d" % (size - 1, size + 50), 206, size - 1, size - 1),
        ):
            with self.subTest(rng=rng):
                resp, body, _ = self.fetch(rng)
                self.assertEqual(resp.status, status)
                self.assertEqual(resp.getheader("Content-Length"), str(last - first + 1))
                expected_range = None if rng is None else "bytes %d-%d/%d" % (first, last, size)
                self.assertEqual(resp.getheader("Content-Range"), expected_range)
                self.assertEqual(body, data[first:last + 1])
        resp, body, _ = self.fetch("bytes=%d-" % size)
        self.assertEqual(resp.status, 416)
        resp, body, _ = self.fetch(method="HEAD")
        self.assertEqual((resp.status, resp.getheader("Content-Length"), body), (200, str(size), b""))

    def test_file_shorter_than_its_stat_is_refused(self):
        self.file.write_bytes(b"x" * 5000)
        real = mb.verified_file_stat

        def stale_stat(digest_hex, file_index):
            path, size = real(digest_hex, file_index)
            return path, size + 100

        with mock.patch.object(mb, "verified_file_stat", stale_stat):
            resp, body, _ = self.fetch()
        self.assertEqual(resp.status, 409)
        self.assertIn(b"verified chunks required", body)

    def test_large_download_is_not_buffered(self):
        # A full download used to hold the span twice (block list plus joined
        # copy) before the first byte went out. Streaming holds one 1 MiB block.
        self.file.touch()
        os.truncate(self.file, BIG_SPAN)
        for rng, status in ((None, 200), ("bytes=0-", 206), ("bytes=1-", 206)):
            with self.subTest(rng=rng):
                tracemalloc.start()
                try:
                    resp, _, received = self.fetch(rng, keep=False)
                    peak = tracemalloc.get_traced_memory()[1]
                finally:
                    tracemalloc.stop()
                self.assertEqual(resp.status, status)
                self.assertEqual(received, BIG_SPAN - (1 if rng == "bytes=1-" else 0))
                self.assertLess(peak, BIG_SPAN // 8, "bridge buffered %d bytes for a %d-byte span" % (peak, received))


if __name__ == "__main__":
    unittest.main()
