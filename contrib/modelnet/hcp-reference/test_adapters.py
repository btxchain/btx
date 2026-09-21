# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Partner adapter harness tests: timeout UNKNOWN, fencing, idempotent reserve, SSRF."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SDK_PY = _HERE.parent / "hcp-sdk" / "python"
for _p in (_HERE, _SDK_PY):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

from adapter_contracts import (  # noqa: E402
    AUTOMATIC_SPEND_ATOMS,
    AdapterError,
    Certainty,
    DisabledProductionSigner,
    EVIDENCE_SIMULATION_ONLY,
    NativeFamily,
)
from adapter_harness import AdapterHarness, LabExecutor  # noqa: E402
from lab_adapters import LabPartnerAdapters, lab_caller, reject_webhook_url  # noqa: E402


def _err(code: str, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except AdapterError as exc:
        if exc.code != code:
            raise AssertionError(f"expected {code}, got {exc.code}: {exc}") from exc
        return exc
    except RuntimeError as exc:
        if code not in str(exc):
            raise AssertionError(f"expected {code} in {exc}") from exc
        return exc
    raise AssertionError(f"expected AdapterError {code}")


class DisabledSignerTests(unittest.TestCase):
    def test_sign_exact_unsupported(self):
        with self.assertRaises(RuntimeError) as ctx:
            DisabledProductionSigner().sign_exact("op", "digest", b"tx", 1)
        self.assertIn("CUSTODY_UNSUPPORTED", str(ctx.exception))

    def test_inspect_and_lookup_unsupported(self):
        signer = DisabledProductionSigner()
        with self.assertRaises(RuntimeError) as ctx:
            signer.inspect_native_template(b"tx", b"terms")
        self.assertIn("CUSTODY_UNSUPPORTED", str(ctx.exception))
        with self.assertRaises(RuntimeError) as ctx:
            signer.lookup_signature("op")
        self.assertIn("CUSTODY_UNSUPPORTED", str(ctx.exception))

    def test_disabled_family_uses_production_signer(self):
        lab = LabPartnerAdapters(native_family=NativeFamily.DISABLED)
        self.assertIsInstance(lab.custody, DisabledProductionSigner)


class EvmGenericTests(unittest.TestCase):
    def test_family_constructor(self):
        lab = LabPartnerAdapters(native_family=NativeFamily.EVM_GENERIC)
        _err("CUSTODY_UNSUPPORTED", lab.custody.inspect_native_template, b"{}", b"{}")
        _err("CUSTODY_UNSUPPORTED", lab.custody.sign_exact, "op", "d", b"tx", 1)
        _err("CUSTODY_UNSUPPORTED", lab.custody.lookup_signature, "op")

    def test_template_bytes(self):
        h = AdapterHarness()
        _err(
            "CUSTODY_UNSUPPORTED",
            h.lab.custody.inspect_native_template,
            b'{"native_family":"EVM_GENERIC"}',
            b"{}",
        )

    def test_from_config(self):
        lab = LabPartnerAdapters.from_config({"finance": {"custody_backend": "EVM_GENERIC"}})
        _err("CUSTODY_UNSUPPORTED", lab.custody.sign_exact, "op", "d", b"tx", 0)


class LiveCredentialTests(unittest.TestCase):
    def test_api_key_rejected(self):
        _err("LIVE_CREDENTIALS_REJECTED", LabPartnerAdapters, api_key="sk_live_not_for_lab")

    def test_production_rejected(self):
        _err("LIVE_CREDENTIALS_REJECTED", LabPartnerAdapters, production=True)

    def test_mainnet_rejected(self):
        _err("LIVE_CREDENTIALS_REJECTED", LabPartnerAdapters, environment="MAINNET")

    def test_non_simulation_evidence_rejected(self):
        _err("LIVE_CREDENTIALS_REJECTED", LabPartnerAdapters, evidence="NATIVE_CHAIN")

    def test_config_simulation_only_false(self):
        _err("LIVE_CREDENTIALS_REJECTED", LabPartnerAdapters.from_config, {"simulation_only": False})

    def test_default_is_simulation_only(self):
        lab = LabPartnerAdapters()
        self.assertEqual(lab.evidence, EVIDENCE_SIMULATION_ONLY)
        self.assertEqual(lab.automatic_spend_atoms, 0)
        self.assertEqual(AUTOMATIC_SPEND_ATOMS, 0)


class TimeoutUnknownTests(unittest.TestCase):
    def setUp(self):
        self.h = AdapterHarness()
        self.caller = lab_caller()
        self.tx = b'{"native_family":"BTX_NATIVE_TEMPLATES","v":1}'

    def test_sign_timeout_is_unknown_not_failure(self):
        self.h.inject_sign_timeout()
        reserved = self.h.lab.ledger.reserve(self.caller, "digest-sign", "1000", 1)
        signed = self.h.lab.custody.sign_exact(reserved.operation_id, "digest-sign", self.tx, 1)
        self.assertEqual(signed.certainty, Certainty.UNKNOWN)
        self.h.assert_unknown_not_failure(signed)
        self.assertGreater(self.h.lab.ledger.held_atoms(reserved.operation_id), 0)
        looked = self.h.lab.custody.lookup_signature(reserved.operation_id)
        self.assertEqual(looked.operation_id, reserved.operation_id)
        self.assertEqual(looked.certainty, Certainty.UNKNOWN)
        _err(
            "RECONCILIATION_REQUIRED",
            self.h.lab.ledger.settle,
            reserved.operation_id,
            "1000",
            1,
        )
        self.h.refuse_unsafe_followups(reserved.operation_id)
        self.assertEqual(self.h.lab.automatic_spend_atoms, 0)

    def test_executor_does_not_broadcast_on_sign_unknown(self):
        self.h.inject_sign_timeout()
        out = self.h.executor.reserve_sign_broadcast(
            self.caller, "digest-exec", "500", 1, self.tx, "digest-exec"
        )
        self.assertEqual(out.certainty, Certainty.UNKNOWN)
        self.assertEqual(self.h.executor.submitted, 0)
        self.assertEqual(self.h.executor.broadcasts, 0)

    def test_broadcast_timeout_is_unknown(self):
        reserved = self.h.lab.ledger.reserve(self.caller, "digest-bc", "1000", 1)
        signed = self.h.lab.custody.sign_exact(reserved.operation_id, "digest-bc", self.tx, 1)
        self.assertEqual(signed.certainty, Certainty.APPLIED)
        self.h.inject_broadcast_timeout()
        signed_bytes = self.h.lab.store.ops[reserved.operation_id].signed_bytes
        broadcast = self.h.lab.broadcast_exact(reserved.operation_id, signed_bytes, 1)
        self.assertEqual(broadcast.certainty, Certainty.UNKNOWN)
        txid = "missing"
        observed = self.h.lab.chain.observe(txid, [])
        self.assertFalse(observed["confirmed"])
        self.h.inject_observe_timeout()
        timed = self.h.lab.chain.observe("any", ["aa:0"])
        self.assertEqual(timed["status"], "UNKNOWN")
        self.assertEqual(timed["certainty"], Certainty.UNKNOWN.value)
        self.assertFalse(timed["confirmed"])
        self.assertEqual(timed["automatic_spend_atoms"], 0)
        self.h.refuse_unsafe_followups(reserved.operation_id)

    def test_reserve_timeout_keeps_hold(self):
        self.h.inject_reserve_timeout()
        out = self.h.lab.ledger.reserve(self.caller, "digest-res", "750", 1)
        self.assertEqual(out.certainty, Certainty.UNKNOWN)
        self.assertGreater(self.h.lab.ledger.held_atoms(out.operation_id), 0)
        again = self.h.lab.ledger.reserve(self.caller, "digest-res", "750", 1)
        self.assertEqual(again.operation_id, out.operation_id)

    def test_quote_timeout_no_venue_failover(self):
        quote = self.h.lab.quote.firm_conversion_quote(self.caller, "USD", "100", "50")
        self.h.inject_quote_timeout()
        out = self.h.lab.quote.execute_exact_quote(self.caller, quote["quote_ref"], "op-fx-1")
        self.assertEqual(out.certainty, Certainty.UNKNOWN)
        self.assertEqual(self.h.lab.store.venues_attempted, ["lab-venue-a"])
        _err("VENUE_FAILOVER_FORBIDDEN", self.h.lab.failover_venue, "op-fx-1", "lab-venue-b")
        looked = self.h.lab.quote.lookup_conversion("op-fx-1")
        self.assertEqual(looked.certainty, Certainty.UNKNOWN)


class FencingTests(unittest.TestCase):
    def test_stale_fence_rejected(self):
        h = AdapterHarness()
        caller = lab_caller()
        out = h.lab.ledger.reserve(caller, "digest-fence", "1000", 1)
        _err(
            "FENCE_CONFLICT",
            h.lab.custody.sign_exact,
            out.operation_id,
            "digest-fence",
            b'{"native_family":"BTX_NATIVE_TEMPLATES"}',
            2,
        )
        signed = h.lab.custody.sign_exact(
            out.operation_id, "digest-fence", b'{"native_family":"BTX_NATIVE_TEMPLATES"}', 1
        )
        self.assertEqual(signed.certainty, Certainty.APPLIED)

    def test_unknown_blocks_new_fence(self):
        h = AdapterHarness()
        caller = lab_caller()
        h.inject_sign_timeout()
        reserved = h.lab.ledger.reserve(caller, "digest-unk-fence", "1000", 7)
        signed = h.lab.custody.sign_exact(
            reserved.operation_id, "digest-unk-fence", b'{"native_family":"BTX_NATIVE_TEMPLATES"}', 7
        )
        self.assertEqual(signed.certainty, Certainty.UNKNOWN)
        _err(
            "FENCE_CONFLICT",
            h.lab.custody.sign_exact,
            reserved.operation_id,
            "digest-unk-fence",
            b'{"native_family":"BTX_NATIVE_TEMPLATES"}',
            8,
        )


class IdempotentReserveTests(unittest.TestCase):
    def test_same_digest_same_amount(self):
        h = AdapterHarness()
        caller = lab_caller()
        a = h.lab.ledger.reserve(caller, "digest-idemp", "1000", 1)
        b = h.lab.ledger.reserve(caller, "digest-idemp", "1000", 1)
        self.assertEqual(a.operation_id, b.operation_id)
        self.assertEqual(a.certainty, Certainty.APPLIED)
        self.assertEqual(h.lab.ledger.held_atoms(a.operation_id), 1000)

    def test_same_digest_different_amount_conflicts(self):
        h = AdapterHarness()
        caller = lab_caller()
        h.lab.ledger.reserve(caller, "digest-idemp-amt", "1000", 1)
        _err("IDEMPOTENCY_CONFLICT", h.lab.ledger.reserve, caller, "digest-idemp-amt", "2000", 1)

    def test_replacement_spend_rejected(self):
        h = AdapterHarness()
        caller = lab_caller()
        reserved = h.lab.ledger.reserve(caller, "digest-repl", "1000", 1)
        tx = b'{"native_family":"BTX_NATIVE_TEMPLATES","n":1}'
        h.lab.custody.sign_exact(reserved.operation_id, "digest-repl", tx, 1)
        _err(
            "REPLACEMENT_SPEND_FORBIDDEN",
            h.lab.custody.sign_exact,
            reserved.operation_id,
            "digest-repl",
            b'{"native_family":"BTX_NATIVE_TEMPLATES","n":2}',
            1,
        )
        again = h.lab.custody.sign_exact(reserved.operation_id, "digest-repl", tx, 1)
        self.assertEqual(again.operation_id, reserved.operation_id)


class WebhookSsrfTests(unittest.TestCase):
    def setUp(self):
        self.h = AdapterHarness()

    def test_allowlisted_https(self):
        out = self.h.lab.webhook.enroll("https://hooks.lab.example/delivery/1", "d1")
        self.assertEqual(out.certainty, Certainty.APPLIED)
        again = self.h.lab.audit.enroll_webhook("https://hooks.lab.example/delivery/1", "d1")
        self.assertEqual(again.certainty, Certainty.APPLIED)

    def test_rejects_loopback_metadata_and_http(self):
        cases = [
            "http://127.0.0.1/",
            "https://127.0.0.1/callback",
            "https://localhost/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://metadata.google.internal/",
            "https://[::1]/",
            "https://10.0.0.5/hook",
            "https://192.168.1.9/hook",
            "https://evil.example/hook",
            "http://hooks.lab.example/ok",
            "https://user:pass@hooks.lab.example/ok",
            "https://2130706433/",
            "file:///etc/passwd",
        ]
        for url in cases:
            with self.subTest(url=url):
                _err("SSRF_REJECTED", self.h.lab.webhook.enroll, url, "d-ssrf")
                _err("SSRF_REJECTED", reject_webhook_url, url)


class TypedAdapterSmokeTests(unittest.TestCase):
    def setUp(self):
        self.h = AdapterHarness()
        self.caller = lab_caller()

    def test_identity(self):
        caller = self.h.lab.identity.verify_caller(
            "lab:lab-tenant:lab-account:lab-principal:intents:submit",
            "hcp.finance",
            b"lab-proof",
        )
        self.assertEqual(caller.tenant, "lab-tenant")
        _err("LIVE_CREDENTIALS_REJECTED", self.h.lab.identity.verify_caller, "eyJhbGciOiJIUzI1NiJ9.e30.sig", "hcp.lab", b"")
        _err("AUTH_REQUIRED", self.h.lab.identity.verify_caller, "prod-token", "hcp.lab", b"")

    def test_eligibility(self):
        ok = self.h.lab.eligibility.decide(self.caller, "FUND_RELEASE", "lab-terms-release", "1")
        self.assertTrue(ok["allowed"])
        self.assertEqual(ok["automatic_spend_atoms"], 0)
        denied = self.h.lab.eligibility.decide(self.caller, "FUND_RELEASE", "t", "")
        self.assertFalse(denied["allowed"])

    def test_quote_economy_package(self):
        quote = self.h.lab.quote.firm_conversion_quote(self.caller, "USD", "100", "40")
        self.assertEqual(quote["automatic_spend_atoms"], 0)
        self.assertEqual(quote["evidence"], EVIDENCE_SIMULATION_ONLY)
        executed = self.h.lab.quote.execute_exact_quote(self.caller, quote["quote_ref"], "op-fx-ok")
        self.assertEqual(executed.certainty, Certainty.APPLIED)
        terms = self.h.lab.economy.inspect_terms("lab-regtest", "lab-terms-release")
        self.assertTrue(terms)
        prepared = self.h.lab.economy.prepare_exact(
            self.caller, "FUND_RELEASE", "lab-terms-release", "1000", "30"
        )
        self.assertEqual(prepared["automatic_spend_atoms"], 0)
        self.assertIsNone(prepared["transaction"])
        verified = self.h.lab.economy.verify_frozen_transaction(
            b'{"native_family":"BTX_NATIVE_TEMPLATES"}', terms
        )
        self.assertTrue(verified["ok"])
        _err(
            "CUSTODY_UNSUPPORTED",
            self.h.lab.economy.verify_frozen_transaction,
            b'{"native_family":"EVM_GENERIC"}',
            terms,
        )
        core = "1" * 96
        blob = self.h.lab.package.read_exact_package(core, 4096)
        self.assertTrue(blob)
        search = self.h.lab.package.search_verified("", 10, None)
        self.assertEqual(search["automatic_spend_atoms"], 0)

    def test_audit_idempotent_and_reporting(self):
        event = {"kind": "RESERVE", "operation_id": "op-1"}
        a = self.h.lab.audit.append_once("biz-1", event)
        b = self.h.lab.audit.append_once("biz-1", event)
        self.assertEqual(a.operation_id, b.operation_id)
        _err("IDEMPOTENCY_CONFLICT", self.h.lab.audit.append_once, "biz-1", {"kind": "OTHER"})
        exported = self.h.lab.reporting.export_customer(
            self.caller, a.operation_id, ["operation_id", "certainty", "custody_obligations"]
        )
        self.assertEqual(exported["automatic_spend_atoms"], 0)
        self.assertFalse(exported["secrets"])
        _err(
            "SCOPE_DENIED",
            self.h.lab.reporting.export_customer,
            self.caller,
            a.operation_id,
            ["access_token"],
        )

    def test_chain_absent_not_confirmed(self):
        observed = self.h.lab.chain.observe("no-such-tx", ["aa:0"])
        self.assertEqual(observed["status"], "ABSENT")
        self.assertFalse(observed["confirmed"])
        self.assertEqual(observed["automatic_spend_atoms"], 0)

    def test_happy_executor_path_stays_zero_spend(self):
        out = self.h.executor.reserve_sign_broadcast(
            self.caller,
            "digest-happy",
            "1000",
            1,
            b'{"native_family":"BTX_NATIVE_TEMPLATES","v":1}',
            "digest-happy",
        )
        self.assertEqual(out.certainty, Certainty.APPLIED)
        self.assertEqual(self.h.executor.broadcasts, 1)
        self.assertEqual(self.h.automatic_spend_atoms, 0)
        self.assertEqual(LabExecutor(self.h.lab).lab.automatic_spend_atoms, 0)


if __name__ == "__main__":
    unittest.main()
