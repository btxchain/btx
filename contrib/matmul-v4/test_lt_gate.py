#!/usr/bin/env python3
"""Focused schema tests for the ENC-DR-LT offline gate."""

from __future__ import annotations

import importlib.util
import math
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("lt-gate.py")
SPEC = importlib.util.spec_from_file_location("lt_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
lt_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lt_gate)


def report(
    name: str,
    nps: object,
    *,
    backend: str = "cuda",
    backend_used_device: object = True,
    device_rate_valid: object = True,
    silicon_rate_valid: object = True,
    execution_path: object = "device-resident-qstar-batched",
    assisted_exact: object = True,
    qstar_is_consensus: object = True,
    qstar_device_batched: object = True,
    device_w_generation: object = True,
    device_digest: object = True,
    per_nonce_sync_absent: object = True,
    rate_provenance: object = "device-resident-qstar-batched",
    native_path_eligible: object = True,
    tensor_share_pct: object = 70.0,
    device_tensor_share_pct: object = 70.0,
    device_tensor_timing_valid: object = True,
    device_tensor_counters_valid: object = True,
    device_tensor_timing_domain: object = "device-kernel-timing-and-counters",
    tensor_util_pct: object = 60.0,
    v3_hashrate: object = 0.0,
    asert: object = "n/a (pass --v3-hashrate)",
) -> dict:
    return {
        "_file": name,
        "tool": "matmul-v4-report",
        "schema_version": 3,
        "profile": "bmx4c-lt",
        "host": name.removesuffix(".json"),
        "backend": backend,
        "native_path_eligible": native_path_eligible,
        "device_execution_certified": False,
        "device_tensor_timing_valid": device_tensor_timing_valid,
        "device_tensor_counters_valid": device_tensor_counters_valid,
        "device_tensor_timing_domain": device_tensor_timing_domain,
        "device_tensor_share_pct": device_tensor_share_pct,
        "backend_used_device": backend_used_device,
        "device_rate_valid": device_rate_valid,
        "silicon_rate_valid": silicon_rate_valid,
        "execution_path": execution_path,
        "bit_exact": True,
        "stages": {
            "bit_exact": True,
            "cpu_reference_tensor_share_pct": tensor_share_pct,
            "tensor_share_pct": tensor_share_pct,
            "device_tensor_share_pct": device_tensor_share_pct,
            "tensor_util_pct": tensor_util_pct,
        },
        "cpu_reference_tensor_share_pct": tensor_share_pct,
        "tensor_share_pct": None,
        "tensor_util_pct": tensor_util_pct,
        "device_nonce_per_s": nps,
        "cpu_reference_nonce_per_s": 999999.0,
        "v3_hashrate": v3_hashrate,
        "asert_rescale_num_den_suggestion": asert,
        "lt": {
            "device_native_kernel_wired": False,
            "device_assisted_path_exact": assisted_exact,
            "qstar_is_consensus": qstar_is_consensus,
            "qstar_device_batched": qstar_device_batched,
            "device_w_generation": device_w_generation,
            "device_digest": device_digest,
            "per_nonce_sync_absent": per_nonce_sync_absent,
            "rate_provenance": rate_provenance,
        },
    }


LABELS = {
    "b200.json": ("nvidia", "datacenter", "B200"),
    "5090.json": ("nvidia", "consumer", "RTX5090"),
}


class LtGateSchemaTest(unittest.TestCase):
    def evaluate_pair(self, dc: dict, consumer: dict):
        return lt_gate.evaluate([dc, consumer], LABELS, {}, False)

    def test_positive_resident_batched_rate_and_device_counters_drive_g1_g2(self):
        go, gates, rows, reasons, notes, summary = self.evaluate_pair(
            report("b200.json", 400.0), report("5090.json", 100.0)
        )

        self.assertFalse(go)  # G3-G8 remain deliberately fail-closed.
        self.assertTrue(gates["G1_tensor_majority"])
        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertEqual([row["nps"] for row in rows], [400.0, 100.0])
        self.assertTrue(all(row["device_measured"] for row in rows))
        self.assertTrue(all(row["native_path_eligible"] for row in rows))
        self.assertEqual(summary["g2_evidence"]["ratio"], 4.0)
        self.assertFalse(any("G2 B200/5090 ratio" in reason for reason in reasons))

    def test_g2_silicon_rate_does_not_substitute_for_g1_native_counters(self):
        dc = report(
            "b200.json", 400.0, native_path_eligible=False,
            device_tensor_timing_valid=False, device_tensor_counters_valid=False,
            device_tensor_timing_domain="cpu-reference", device_tensor_share_pct=None,
            tensor_share_pct=97.2,
        )
        consumer = report(
            "5090.json", 100.0, native_path_eligible=False,
            device_tensor_timing_valid=False, device_tensor_counters_valid=False,
            device_tensor_timing_domain="cpu-reference", device_tensor_share_pct=None,
            tensor_share_pct=97.2,
        )

        _, gates, rows, reasons, _, _ = self.evaluate_pair(dc, consumer)

        self.assertFalse(gates["G1_tensor_majority"])
        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertTrue(all(r["cpu_reference_tensor_share_pct"] == 97.2 for r in rows))
        self.assertTrue(all(r["device_tensor_share_pct"] is None for r in rows))
        self.assertTrue(any("cpu_reference_tensor_share_pct=97.2% does not count" in reason
                            for reason in reasons))

    def test_null_and_invalid_device_rates_fail_closed(self):
        invalid = [None, 0, -1, math.nan, math.inf, -math.inf, "100"]
        for value in invalid:
            with self.subTest(value=value):
                candidate = report("b200.json", value)
                self.assertFalse(lt_gate.device_measured(candidate))
                self.assertIsNone(lt_gate.device_nps(candidate))

        _, gates, rows, reasons, _, summary = self.evaluate_pair(
            report("b200.json", None), report("5090.json", 100.0)
        )
        self.assertFalse(gates["G2_b200_5090_ratio"])
        self.assertIsNone(rows[0]["nps"])
        self.assertIsNone(summary["g2_evidence"]["ratio"])
        self.assertTrue(any("UNVERIFIED" in reason and "G2" in reason for reason in reasons))

    def test_rate_requires_complete_exact_device_assisted_provenance(self):
        self.assertFalse(
            lt_gate.device_measured(report("b200.json", 400.0, backend_used_device=False))
        )
        self.assertFalse(
            lt_gate.device_measured(report("b200.json", 400.0, device_rate_valid=False))
        )
        self.assertFalse(
            lt_gate.device_measured(report("b200.json", 400.0, silicon_rate_valid=False))
        )
        self.assertFalse(
            lt_gate.device_measured(report("b200.json", 400.0, execution_path="device-assisted-end-to-end"))
        )
        self.assertFalse(
            lt_gate.device_measured(report("b200.json", 400.0, assisted_exact=False))
        )
        self.assertFalse(lt_gate.device_measured(report("b200.json", 400.0, backend="cpu")))
        wrong_type = report("b200.json", 400.0)
        wrong_type["backend_used_device"] = 1
        self.assertFalse(lt_gate.device_measured(wrong_type))

        for top_level in ("backend_used_device", "device_rate_valid", "silicon_rate_valid", "execution_path"):
            with self.subTest(missing=top_level):
                missing = report("b200.json", 400.0)
                del missing[top_level]
                self.assertFalse(lt_gate.device_measured(missing))
        missing_nested = report("b200.json", 400.0)
        del missing_nested["lt"]["device_assisted_path_exact"]
        self.assertFalse(lt_gate.device_measured(missing_nested))

        for field in (
            "qstar_is_consensus",
            "qstar_device_batched",
            "device_w_generation",
            "device_digest",
            "per_nonce_sync_absent",
        ):
            with self.subTest(false_provenance=field):
                candidate = report("b200.json", 400.0)
                candidate["lt"][field] = False
                self.assertFalse(lt_gate.device_measured(candidate))
            with self.subTest(missing_provenance=field):
                candidate = report("b200.json", 400.0)
                del candidate["lt"][field]
                self.assertFalse(lt_gate.device_measured(candidate))

        wrong_provenance = report("b200.json", 400.0)
        wrong_provenance["lt"]["rate_provenance"] = "cuda/hip-device-assisted-status-ok"
        self.assertFalse(lt_gate.device_measured(wrong_provenance))

    def test_host_orchestrated_1ca87fb_rates_are_diagnostic_only(self):
        dc = report(
            "b200.json",
            None,
            device_rate_valid=False,
            silicon_rate_valid=False,
            execution_path="device-assisted-per-nonce-host-orchestrated",
            qstar_device_batched=False,
            device_w_generation=False,
            device_digest=False,
            per_nonce_sync_absent=False,
            rate_provenance="host-orchestrated-single-nonce-diagnostic",
            native_path_eligible=False,
            device_tensor_timing_valid=False,
            device_tensor_counters_valid=False,
            device_tensor_timing_domain="cpu-reference",
            device_tensor_share_pct=None,
        )
        dc["host_orchestrated_nonce_per_s"] = 118.92
        dc["asert_rescale_num_den_suggestion"] = "100/1"
        consumer = report(
            "5090.json",
            None,
            device_rate_valid=False,
            silicon_rate_valid=False,
            execution_path="device-assisted-per-nonce-host-orchestrated",
            qstar_device_batched=False,
            device_w_generation=False,
            device_digest=False,
            per_nonce_sync_absent=False,
            rate_provenance="host-orchestrated-single-nonce-diagnostic",
            native_path_eligible=False,
            device_tensor_timing_valid=False,
            device_tensor_counters_valid=False,
            device_tensor_timing_domain="cpu-reference",
            device_tensor_share_pct=None,
        )
        consumer["host_orchestrated_nonce_per_s"] = 77.08

        _, gates, rows, reasons, notes, summary = lt_gate.evaluate(
            [dc, consumer], LABELS, {"B200": 7.0, "RTX5090": 0.5}, False
        )

        self.assertFalse(gates["G1_tensor_majority"])
        self.assertFalse(gates["G2_b200_5090_ratio"])
        self.assertFalse(gates["G3_nonce_per_dollar"])
        self.assertEqual([r["host_orchestrated_nps"] for r in rows], [118.92, 77.08])
        self.assertEqual([r["nps"] for r in rows], [None, None])
        self.assertIsNone(summary["g2_evidence"]["ratio"])
        self.assertTrue(any("G2" in reason and "UNVERIFIED" in reason for reason in reasons))
        self.assertTrue(any("G3" in reason and "UNVERIFIED" in reason for reason in reasons))
        self.assertTrue(any("diagnostic only" in note for note in notes))
        self.assertTrue(any("exclude it from calibration" in note for note in notes))

    def test_tensor_util_is_diagnostic_not_g1_input(self):
        dc = report("b200.json", 400.0, tensor_util_pct="unknown")
        dc["tensor_util_pct"] = None
        consumer = report("5090.json", 100.0, tensor_util_pct=None)
        consumer["stages"]["tensor_util_pct"] = 47.5

        _, gates, rows, _, _, _ = self.evaluate_pair(dc, consumer)
        self.assertTrue(gates["G1_tensor_majority"])
        self.assertIsNone(rows[0]["tensor_util_pct"])
        self.assertEqual(rows[1]["tensor_util_pct"], 47.5)

    def test_device_tensor_share_must_be_strict_majority_and_counter_backed(self):
        for kwargs in (
            {"device_tensor_share_pct": 50.0},
            {"device_tensor_timing_valid": False},
            {"device_tensor_counters_valid": False},
            {"device_tensor_timing_domain": "cpu-reference"},
            {"native_path_eligible": False},
        ):
            with self.subTest(kwargs=kwargs):
                dc = report("b200.json", 400.0, **kwargs)
                _, gates, _, reasons, _, _ = self.evaluate_pair(
                    dc, report("5090.json", 100.0)
                )
                self.assertFalse(gates["G1_tensor_majority"])
                self.assertTrue(any("G1 native tensor-majority" in reason for reason in reasons))

    def test_commit_only_s5_cannot_pass_phase_b_review(self):
        dc = report("b200.json", 400.0)
        consumer = report("5090.json", 100.0)
        for candidate in (dc, consumer):
            candidate["stages"]["s5_qstar_seal_ms"] = 1.0
            # Even a forged/legacy optimistic field cannot make the offline
            # aggregator treat a commit-only clock as consensus-equivalent.
            candidate["phase_b_seal_rate_valid"] = True
            candidate["phase_b_consensus_equivalent"] = True

        _, gates, _, reasons, _, _ = self.evaluate_pair(dc, consumer)

        self.assertFalse(gates["G8_seal_as_pow_review"])
        self.assertTrue(any("G8 Phase B" in reason and "UNVERIFIED" in reason
                            for reason in reasons))

    def test_asert_suggestion_is_checked_against_measured_ratio(self):
        dc = report("b200.json", 400.0, v3_hashrate=1200.0, asert="3/1")
        consumer = report("5090.json", 100.0, v3_hashrate=1200.0, asert="12/1")

        _, gates, rows, _, notes, summary = self.evaluate_pair(dc, consumer)
        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertEqual(rows[0]["asert_expected"], "3/1")
        self.assertTrue(rows[0]["asert_consistent"])
        self.assertEqual(rows[1]["asert_expected"], "12/1")
        self.assertTrue(rows[1]["asert_consistent"])
        self.assertFalse(notes)
        self.assertEqual(len(summary["asert_calibration"]), 2)

        bad = report("b200.json", 100.0, v3_hashrate=1200.0, asert="24/2")
        self.assertIsNone(lt_gate.asert_suggestion(bad))
        self.assertEqual(lt_gate.expected_asert_suggestion(bad), "12/1")


if __name__ == "__main__":
    unittest.main()
