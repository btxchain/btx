#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""CRL v1.2 SDK tests: 43 operation_ids, 18 type domain separation.

Does not submit spends, sign, or talk to a wallet. automatic_spend_atoms stays 0.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from btx_crl12 import (  # noqa: E402
    ANALYTICS_SCOPES,
    AUTOMATIC_SPEND_ATOMS,
    Crl12Client,
    Crl12Error,
    OBJECT_TYPES,
    OPERATION_IDS,
    analytics_client,
    body_id,
    canonical_body,
    contains_secrets,
)

CATALOG = Path(__file__).resolve().parents[1] / "schemas" / "operations-v1.2.json"


def _noop_auth(_method: str, _url: str, _body: bytes) -> dict[str, str]:
    return {}


def _noop_validate(_schema: str, _value: object) -> None:
    return None


class TestCrl12BodyId(unittest.TestCase):
    def test_eighteen_types(self):
        self.assertEqual(len(OBJECT_TYPES), 18)
        self.assertEqual(len(set(OBJECT_TYPES)), 18)
        self.assertTrue(all(t.endswith("V1_2") for t in OBJECT_TYPES))

    def test_eighteen_type_domain_separation(self):
        body = {"schema_revision": "1.2", "provider_id": "p", "created_at": "1"}
        ids = {t: body_id(t, body) for t in OBJECT_TYPES}
        self.assertEqual(len(ids), 18)
        self.assertEqual(len(set(ids.values())), 18)
        digest = next(iter(ids.values()))
        self.assertEqual(len(digest), 96)
        self.assertRegex(digest, r"^[0-9a-f]{96}$")
        canon = canonical_body(body)
        for kind, digest in ids.items():
            expected = hashlib.sha384(
                f"BTX/HCP/{kind}/v1".encode("utf-8") + b"\0" + struct.pack("<Q", len(canon)) + canon
            ).hexdigest()
            self.assertEqual(digest, expected)

    def test_body_id_rejects_unknown_and_v4(self):
        body = {"schema_revision": "1.2", "provider_id": "p", "created_at": "1"}
        with self.assertRaises(ValueError):
            body_id("PortfolioV4", body)
        with self.assertRaises(ValueError):
            body_id("ProviderProfile", body)
        self.assertFalse(any("V4" in t for t in OBJECT_TYPES))

    def test_ops_catalog_count(self):
        ops = json.loads(CATALOG.read_text(encoding="utf-8"))["operations"]
        self.assertEqual(len(ops), 43)
        self.assertEqual(len(OPERATION_IDS), 43)
        self.assertEqual(len(set(OPERATION_IDS)), 43)
        self.assertEqual(tuple(o["operation_id"] for o in ops), OPERATION_IDS)
        self.assertNotIn("executeAllocation", OPERATION_IDS)

    def test_forty_three_operation_ids_on_client(self):
        client = Crl12Client("https://exchange.example", _noop_auth, _noop_validate)
        self.assertEqual(len(client.operations), 43)
        for op_id in OPERATION_IDS:
            self.assertIn(op_id, client.operations)
            self.assertTrue(callable(getattr(client, op_id)))
        self.assertEqual(set(client.operations), set(OPERATION_IDS))

    def test_automatic_spend_atoms_zero(self):
        client = Crl12Client("https://exchange.example", _noop_auth, _noop_validate)
        self.assertEqual(AUTOMATIC_SPEND_ATOMS, 0)
        self.assertEqual(client.automatic_spend_atoms, 0)

    def test_no_rpc_passthrough(self):
        paths = [o["path"] for o in json.loads(CATALOG.read_text(encoding="utf-8"))["operations"]]
        self.assertTrue(all(p.startswith("/btx/hcp/v1/") for p in paths))
        self.assertFalse(any(p == "/rpc" or p.startswith("/rpc/") for p in paths))
        client = Crl12Client("https://exchange.example", _noop_auth, _noop_validate)
        with self.assertRaises((ValueError, Crl12Error)):
            client.call("/rpc")
        with self.assertRaises((ValueError, Crl12Error)):
            client.call("genericRpc")

    def test_https_default_rejects_http(self):
        with self.assertRaises(ValueError):
            Crl12Client("http://127.0.0.1", _noop_auth, _noop_validate)
        with self.assertRaises(ValueError):
            Crl12Client("http://example.com", _noop_auth, _noop_validate)

    def test_lab_origin_loopback_only(self):
        Crl12Client(
            "http://127.0.0.1:18780",
            _noop_auth,
            _noop_validate,
            lab_origin="http://127.0.0.1",
        )
        with self.assertRaises(ValueError):
            Crl12Client("http://localhost", _noop_auth, _noop_validate, lab_origin=True)

    def test_refuse_export_secrets(self):
        client = Crl12Client("https://exchange.example", _noop_auth, _noop_validate)
        with self.assertRaises(Crl12Error) as ctx:
            client.createInstitutionalExport(
                body={"access_token": "stolen", "format": "JSONL"},
                idempotency_key="exp-secret-1",
            )
        self.assertEqual(ctx.exception.code, "SECRET_INLINE")
        with self.assertRaises(Crl12Error):
            client.createInstitutionalExport(
                body={"private_key": "-----BEGIN PRIVATE KEY-----\nabc"},
                idempotency_key="exp-secret-2",
            )
        self.assertTrue(contains_secrets({"secret": "x"}))
        self.assertFalse(contains_secrets({"secret_ref": "os:keyring/export"}))

    def test_refuse_execute_from_analytics(self):
        client = analytics_client("https://exchange.example", _noop_auth, validate=_noop_validate)
        self.assertEqual(tuple(client.scopes), ANALYTICS_SCOPES)
        self.assertNotIn("capital:execute", client.scopes)
        with self.assertRaises(Crl12Error) as ctx:
            client.executeAllocation(object_id="alloc-1", idempotency_key="nope")
        self.assertEqual(ctx.exception.code, "SCOPE_DENIED")
        with self.assertRaises(Crl12Error):
            client.call("executeAllocation")

    def test_import_not_custody_credit(self):
        client = Crl12Client("https://exchange.example", _noop_auth, _noop_validate)
        with self.assertRaises(Crl12Error) as ctx:
            client.commitInstitutionalImport(
                object_id="imp-1",
                body={"custody_credit": True},
                idempotency_key="imp-1",
            )
        self.assertEqual(ctx.exception.code, "IMPORT_NOT_CUSTODY")

    def test_no_invented_aum_auc(self):
        client = Crl12Client("https://exchange.example", _noop_auth, _noop_validate)
        with self.assertRaises(Crl12Error) as ctx:
            client.createPortfolioProjection(
                body={"combined_aum_auc": "99"},
                idempotency_key="proj-1",
            )
        self.assertEqual(ctx.exception.code, "INVENTED_TOTAL")

    def test_no_remote_inference(self):
        client = Crl12Client("https://exchange.example", _noop_auth, _noop_validate)
        with self.assertRaises(Crl12Error) as ctx:
            client.preparePortfolioInstruction(
                body={"remote_inference": True},
                idempotency_key="ins-1",
            )
        self.assertEqual(ctx.exception.code, "REMOTE_INFERENCE_FORBIDDEN")

    def test_no_brand_dispatch(self):
        src = Path(__file__).resolve().parent.joinpath("btx_crl12.py").read_text(encoding="utf-8")
        self.assertNotIn("bloomberg", src.lower())
        self.assertNotIn("blackrock", src.lower())
        client = Crl12Client("https://exchange.example", _noop_auth, _noop_validate)
        with self.assertRaises(Crl12Error) as ctx:
            client.publishProviderRoles(
                body={"role": "DISCOVERY", "brand_dispatch": True},
                idempotency_key="role-1",
            )
        self.assertEqual(ctx.exception.code, "BRAND_DISPATCH")

    def test_root_transport_guards(self):
        root = Path(__file__).resolve().parents[1] / "crl_client.py"
        src = root.read_text(encoding="utf-8")
        self.assertIn("AUTOMATIC_SPEND_ATOMS = 0", src)
        self.assertIn("executeAllocation", src)
        self.assertIn("GENERIC_RPC_DISABLED", src)
        self.assertIn("/rpc", src)
        import importlib.util
        spec = importlib.util.spec_from_file_location("crl12_root_transport", root)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        client = mod.CrlClient("https://exchange.example", lambda *_a: {}, lambda *_a: None)
        self.assertEqual(client.automatic_spend_atoms, 0)
        self.assertEqual(len(client.operations), 43)
        with self.assertRaises(mod.ClientError):
            client.executeAllocation()
        with self.assertRaises(mod.ClientError):
            client.call("executeAllocation")
        with self.assertRaises(mod.ClientError):
            client.call("/rpc")

    def test_catalog_paths_have_no_execute_or_rpc(self):
        ops = json.loads(CATALOG.read_text(encoding="utf-8"))["operations"]
        for o in ops:
            self.assertTrue(o["path"].startswith("/btx/hcp/v1/"), o["path"])
            self.assertNotIn("/rpc", o["path"])
            self.assertNotIn("/execute", o["path"])
            self.assertNotEqual(o["operation_id"], "executeAllocation")

    def test_python_ts_body_id_parity_if_node(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("HONEST_NOT_RUN: node not present")
        ts = Path(__file__).resolve().parents[1] / "typescript" / "src" / "compute_body_id.ts"
        body = {"schema_revision": "1.2", "provider_id": "p", "created_at": "1"}
        envelope = {"object_type": "LayerExtensionProfileV1_2", "body": body}
        expected = body_id(envelope["object_type"], body)
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as fh:
            json.dump(envelope, fh)
            path = fh.name
        try:
            env = os.environ.copy()
            env["NODE_NO_WARNINGS"] = "1"
            out = subprocess.check_output(
                [node, "--experimental-strip-types", str(ts), path],
                stderr=subprocess.DEVNULL,
                env=env,
                text=True,
            ).strip()
        except subprocess.CalledProcessError as e:
            self.fail(f"compute_body_id.ts failed: {e}")
        finally:
            Path(path).unlink(missing_ok=True)
        self.assertEqual(out, expected)


if __name__ == "__main__":
    unittest.main()
