# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""SDK lab adapter tests. SIMULATION_ONLY; timeouts are Certainty.UNKNOWN."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REF = HERE.parents[1] / "hcp-reference"
for p in (HERE, REF):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

from adapter_contracts import (  # noqa: E402
    AUTOMATIC_SPEND_ATOMS,
    AdapterError,
    Certainty,
    DisabledProductionSigner,
    EVIDENCE_SIMULATION_ONLY,
    NativeFamily,
)
from lab_adapters import (  # noqa: E402
    EvmGenericCustody,
    LabPartnerAdapters,
    lab_caller,
    reject_live_credentials,
    reject_webhook_url,
)


class SdkLabSafetyTests(unittest.TestCase):
    def test_automatic_spend_atoms_zero(self):
        lab = LabPartnerAdapters()
        self.assertEqual(lab.automatic_spend_atoms, 0)
        self.assertEqual(AUTOMATIC_SPEND_ATOMS, 0)
        self.assertEqual(lab.evidence, EVIDENCE_SIMULATION_ONLY)

    def test_rejects_live_credentials(self):
        with self.assertRaises(AdapterError) as ctx:
            reject_live_credentials(api_key="sk_live_x")
        self.assertEqual(ctx.exception.code, "LIVE_CREDENTIALS_REJECTED")
        with self.assertRaises(AdapterError):
            LabPartnerAdapters(hsm_endpoint="https://hsm.prod.example")
        with self.assertRaises(AdapterError):
            LabPartnerAdapters(production=True)

    def test_disabled_production_signer(self):
        with self.assertRaises(RuntimeError) as ctx:
            DisabledProductionSigner().sign_exact()
        self.assertIn("CUSTODY_UNSUPPORTED", str(ctx.exception))
        lab = LabPartnerAdapters(native_family="DISABLED")
        self.assertIsInstance(lab.custody, DisabledProductionSigner)

    def test_evm_generic_unsupported(self):
        self.assertIsInstance(EvmGenericCustody(), EvmGenericCustody)
        lab = LabPartnerAdapters(native_family=NativeFamily.EVM_GENERIC)
        with self.assertRaises(AdapterError) as ctx:
            lab.custody.sign_exact("op", "d", b"tx", 0)
        self.assertEqual(ctx.exception.code, "CUSTODY_UNSUPPORTED")

    def test_sign_timeout_unknown_no_auto_submit(self):
        lab = LabPartnerAdapters()
        caller = lab_caller()
        lab.faults.sign_timeout = True
        reserved = lab.ledger.reserve(caller, "sdk-digest", "1000", 3)
        signed = lab.custody.sign_exact(
            reserved.operation_id, "sdk-digest", b'{"native_family":"BTX_NATIVE_TEMPLATES"}', 3
        )
        self.assertEqual(signed.certainty, Certainty.UNKNOWN)
        self.assertGreater(lab.ledger.held_atoms(reserved.operation_id), 0)
        with self.assertRaises(AdapterError) as ctx:
            lab.auto_submit_finance(reserved.operation_id)
        self.assertEqual(ctx.exception.code, "UNKNOWN_NOT_SAFE_FAILURE")
        with self.assertRaises(AdapterError) as ctx:
            lab.construct_replacement_spend(reserved.operation_id, b"other")
        self.assertEqual(ctx.exception.code, "REPLACEMENT_SPEND_FORBIDDEN")
        with self.assertRaises(AdapterError) as ctx:
            lab.failover_venue(reserved.operation_id, "other-cex")
        self.assertEqual(ctx.exception.code, "VENUE_FAILOVER_FORBIDDEN")
        with self.assertRaises(AdapterError) as ctx:
            lab.broadcast_exact(reserved.operation_id, b"nope", 3)
        self.assertEqual(ctx.exception.code, "UNKNOWN_NOT_SAFE_FAILURE")

    def test_broadcast_timeout_unknown(self):
        lab = LabPartnerAdapters()
        caller = lab_caller()
        reserved = lab.ledger.reserve(caller, "sdk-bc", "10", 1)
        tx = b'{"native_family":"BTX_NATIVE_TEMPLATES"}'
        signed = lab.custody.sign_exact(reserved.operation_id, "sdk-bc", tx, 1)
        self.assertEqual(signed.certainty, Certainty.APPLIED)
        lab.faults.broadcast_timeout = True
        signed_bytes = lab.store.ops[reserved.operation_id].signed_bytes
        out = lab.broadcast_exact(reserved.operation_id, signed_bytes, 1)
        self.assertEqual(out.certainty, Certainty.UNKNOWN)
        with self.assertRaises(AdapterError) as ctx:
            lab.failover_venue(reserved.operation_id, "venue-b")
        self.assertEqual(ctx.exception.code, "VENUE_FAILOVER_FORBIDDEN")

    def test_fencing(self):
        lab = LabPartnerAdapters()
        caller = lab_caller()
        reserved = lab.ledger.reserve(caller, "sdk-fence", "1", 9)
        with self.assertRaises(AdapterError) as ctx:
            lab.custody.sign_exact(reserved.operation_id, "sdk-fence", b'{"v":1}', 10)
        self.assertEqual(ctx.exception.code, "FENCE_CONFLICT")

    def test_idempotent_reserve(self):
        lab = LabPartnerAdapters()
        caller = lab_caller()
        a = lab.ledger.reserve(caller, "sdk-idemp", "42", 1)
        b = lab.ledger.reserve(caller, "sdk-idemp", "42", 1)
        self.assertEqual(a.operation_id, b.operation_id)
        with self.assertRaises(AdapterError) as ctx:
            lab.ledger.reserve(caller, "sdk-idemp", "43", 1)
        self.assertEqual(ctx.exception.code, "IDEMPOTENCY_CONFLICT")

    def test_webhook_ssrf(self):
        lab = LabPartnerAdapters()
        ok = lab.webhook.enroll("https://hooks.lab.example/x", "sdk-d1")
        self.assertEqual(ok.certainty, Certainty.APPLIED)
        for url in (
            "https://127.0.0.1/x",
            "https://169.254.169.254/latest/meta-data/",
            "https://metadata.google.internal/",
            "http://hooks.lab.example/x",
        ):
            with self.subTest(url=url):
                with self.assertRaises(AdapterError) as ctx:
                    reject_webhook_url(url)
                self.assertEqual(ctx.exception.code, "SSRF_REJECTED")
                with self.assertRaises(AdapterError) as ctx:
                    lab.webhook.enroll(url, "sdk-bad")
                self.assertEqual(ctx.exception.code, "SSRF_REJECTED")

    def test_all_ten_adapters_smoke(self):
        lab = LabPartnerAdapters()
        caller = lab.identity.verify_caller("lab:t:a:p:intents:submit", "hcp.lab", b"")
        decision = lab.eligibility.decide(caller, "CLAIM", "lab-terms-release", "1")
        self.assertTrue(decision["allowed"])
        reserved = lab.ledger.reserve(caller, "sdk-all", "5", 1)
        self.assertEqual(reserved.certainty, Certainty.APPLIED)
        inspected = lab.custody.inspect_native_template(b'{"native_family":"BTX_NATIVE_TEMPLATES"}', b"{}")
        self.assertEqual(inspected["automatic_spend_atoms"], 0)
        signed = lab.custody.sign_exact(
            reserved.operation_id, "sdk-all", b'{"native_family":"BTX_NATIVE_TEMPLATES"}', 1
        )
        self.assertEqual(signed.certainty, Certainty.APPLIED)
        observed = lab.chain.observe("none", [])
        self.assertFalse(observed["confirmed"])
        quote = lab.quote.firm_conversion_quote(caller, "USD", "1", "1")
        self.assertEqual(quote["automatic_spend_atoms"], 0)
        prepared = lab.economy.prepare_exact(caller, "CLAIM", "lab-terms-release", "1", "1")
        self.assertEqual(prepared["automatic_spend_atoms"], 0)
        pkg = lab.package.read_exact_package("1" * 96, 1024)
        self.assertTrue(pkg)
        audit = lab.audit.append_once("sdk-ev", {"kind": "OK"})
        self.assertEqual(audit.certainty, Certainty.APPLIED)
        exported = lab.reporting.export_customer(caller, reserved.operation_id, ["certainty"])
        self.assertEqual(exported["automatic_spend_atoms"], 0)
        self.assertEqual(lab.automatic_spend_atoms, 0)


if __name__ == "__main__":
    unittest.main()
