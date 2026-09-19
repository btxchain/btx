#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""CRF v1.1 SDK tests: 50 operation_ids, 18 type domain separation, HTTP 202.

Does not submit spends, sign, or talk to a wallet. automatic_spend_atoms stays 0.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from btx_cr11 import (  # noqa: E402
    AUTOMATIC_SPEND_ATOMS,
    CognitiveReserveClient,
    Cr11Error,
    OBJECT_TYPES,
    OPERATION_IDS,
    body_id,
    canonical_body,
)

CATALOG = Path(__file__).resolve().parents[1] / "schemas" / "operations-v1.1.json"
EXAMPLES = Path("/home/administrator/btx-0.34.7-private/src/modelnet/crf/examples/valid")


def _noop_auth(_method: str, _url: str) -> dict[str, str]:
    return {}


def _noop_validate(_schema: str, _value: object) -> None:
    return None


class TestCr11BodyId(unittest.TestCase):
    def test_eighteen_types(self):
        self.assertEqual(len(OBJECT_TYPES), 18)
        self.assertEqual(len(set(OBJECT_TYPES)), 18)
        self.assertTrue(all(t.endswith("V1_1") for t in OBJECT_TYPES))

    def test_eighteen_type_domain_separation(self):
        body = {"schema_revision": "1.1", "provider_id": "p", "created_at": "1"}
        ids = {t: body_id(t, body) for t in OBJECT_TYPES}
        self.assertEqual(len(ids), 18)
        self.assertEqual(len(set(ids.values())), 18)
        digest = next(iter(ids.values()))
        self.assertEqual(len(digest), 96)
        self.assertRegex(digest, r"^[0-9a-f]{96}$")
        prefixes = {f"BTX/HCP/{t}/v1" for t in OBJECT_TYPES}
        self.assertEqual(len(prefixes), 18)
        # Same canonical body, different object_type → different body_id.
        canon = canonical_body(body)
        for kind, digest in ids.items():
            expected = hashlib.sha384(
                f"BTX/HCP/{kind}/v1".encode("utf-8") + b"\0" + struct.pack("<Q", len(canon)) + canon
            ).hexdigest()
            self.assertEqual(digest, expected)

    def test_body_id_rejects_unknown_and_v4(self):
        body = {"schema_revision": "1.1", "provider_id": "p", "created_at": "1"}
        with self.assertRaises(ValueError):
            body_id("PortfolioV4", body)
        with self.assertRaises(ValueError):
            body_id("ProviderProfile", body)
        self.assertFalse(any("V4" in t for t in OBJECT_TYPES))

    def test_ops_catalog_count(self):
        ops = json.loads(CATALOG.read_text(encoding="utf-8"))["operations"]
        self.assertEqual(len(ops), 50)
        self.assertEqual(len(OPERATION_IDS), 50)
        self.assertEqual(len(set(OPERATION_IDS)), 50)
        self.assertEqual(tuple(o["operation_id"] for o in ops), OPERATION_IDS)

    def test_fifty_operation_ids_on_client(self):
        client = CognitiveReserveClient(
            "https://exchange.example", _noop_auth, _noop_validate
        )
        self.assertEqual(len(client.operations), 50)
        for op_id in OPERATION_IDS:
            self.assertIn(op_id, client.operations)
            self.assertTrue(callable(getattr(client, op_id)))
        self.assertEqual(set(client.operations), set(OPERATION_IDS))

    def test_no_core_v4_type(self):
        self.assertFalse(any("V4" in t for t in OBJECT_TYPES))

    def test_example_vectors(self):
        files = sorted(EXAMPLES.glob("*.json"))
        self.assertEqual(len(files), 18)
        seen = set()
        for path in files:
            env = json.loads(path.read_text(encoding="utf-8"))
            kind = env["object_type"]
            self.assertIn(kind, OBJECT_TYPES)
            seen.add(kind)
            self.assertEqual(body_id(kind, env["body"]), env["body_id"])
        self.assertEqual(seen, set(OBJECT_TYPES))

    def test_automatic_spend_atoms_zero(self):
        client = CognitiveReserveClient(
            "https://exchange.example", _noop_auth, _noop_validate
        )
        self.assertEqual(AUTOMATIC_SPEND_ATOMS, 0)
        self.assertEqual(client.automatic_spend_atoms, 0)

    def test_no_rpc_passthrough(self):
        paths = [o["path"] for o in json.loads(CATALOG.read_text(encoding="utf-8"))["operations"]]
        self.assertTrue(all(p.startswith("/btx/hcp/v1/") for p in paths))
        self.assertFalse(any(p == "/rpc" or p.startswith("/rpc/") for p in paths))
        client = CognitiveReserveClient(
            "https://exchange.example", _noop_auth, _noop_validate
        )
        with self.assertRaises(ValueError):
            client.call("/rpc")
        with self.assertRaises(ValueError):
            client.call("genericRpc")

    def test_https_default_rejects_http(self):
        with self.assertRaises(ValueError):
            CognitiveReserveClient("http://127.0.0.1", _noop_auth, _noop_validate)
        with self.assertRaises(ValueError):
            CognitiveReserveClient("http://example.com", _noop_auth, _noop_validate)

    def test_lab_origin_loopback_only(self):
        CognitiveReserveClient(
            "http://127.0.0.1:18780",
            _noop_auth,
            _noop_validate,
            lab_origin="http://127.0.0.1",
        )
        CognitiveReserveClient(
            "http://127.0.0.1",
            _noop_auth,
            _noop_validate,
            lab_origin=True,
        )
        for origin, flag in (
            ("http://example.com", "http://example.com"),
            ("http://8.8.8.8", True),
            ("http://localhost", True),
            ("http://127.0.0.1.evil.example", True),
            ("http://[::1]", True),
            ("https://127.0.0.1", True),
        ):
            with self.subTest(origin=origin, flag=flag):
                with self.assertRaises(ValueError):
                    CognitiveReserveClient(origin, _noop_auth, _noop_validate, lab_origin=flag)


class _Hits:
    n = 0
    paths: list[str] = []


class _AcceptedHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        _Hits.n += 1
        _Hits.paths.append(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"job_id":"lab-job","state":"ACCEPTED"}')

    def do_GET(self):
        _Hits.n += 1
        _Hits.paths.append(self.path)
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"job_id":"lab-job","state":"ACCEPTED"}')

    def log_message(self, fmt, *args):  # noqa: ARG002
        return


class TestHttp202Unknown(unittest.TestCase):
    def setUp(self):
        _Hits.n = 0
        _Hits.paths = []
        self.httpd = HTTPServer(("127.0.0.1", 0), _AcceptedHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.client = CognitiveReserveClient(
            f"http://127.0.0.1:{self.port}",
            _noop_auth,
            _noop_validate,
            lab_origin="http://127.0.0.1",
        )

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_execute_allocation_202_is_unknown_no_retry(self):
        digest = "a" * 96
        out = self.client.call(
            "executeAllocation",
            object_id="alloc-1",
            body={"client_operation_id": "op-1", "expected_body_id": digest},
            idempotency_key="idem-1",
        )
        self.assertTrue(out["unknown"])
        self.assertEqual(out.get("status"), 202)
        self.assertEqual(_Hits.n, 1)
        self.assertEqual(_Hits.paths, ["/btx/hcp/v1/capital/allocations/alloc-1/execute"])
        self.assertEqual(self.client.automatic_spend_atoms, 0)
        # SDK must not chain cancel/execute after UNKNOWN.
        self.assertEqual(_Hits.n, 1)

    def test_cancel_202_is_unknown_no_retry(self):
        digest = "b" * 96
        out = self.client.cancelCapitalExecution(
            object_id="exec-1",
            body={"client_operation_id": "op-2", "expected_body_id": digest},
            idempotency_key="idem-2",
        )
        self.assertTrue(out["unknown"])
        self.assertEqual(_Hits.n, 1)
        self.assertTrue(_Hits.paths[0].endswith("/cancel"))
        self.assertEqual(self.client.automatic_spend_atoms, 0)

    def test_timeout_is_unknown_no_retry(self):
        class Boom:
            def open(self, request, timeout=None):  # noqa: ARG002
                raise TimeoutError("timed out")

        self.client.opener = Boom()
        with self.assertRaises(Cr11Error) as ctx:
            self.client.call(
                "executeAllocation",
                object_id="alloc-2",
                body={"client_operation_id": "op-3", "expected_body_id": "c" * 96},
                idempotency_key="idem-3",
            )
        self.assertEqual(ctx.exception.code, "UNKNOWN")
        self.assertTrue(ctx.exception.unknown)
        self.assertEqual(_Hits.n, 0)


if __name__ == "__main__":
    unittest.main()
