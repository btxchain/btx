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
    execution_path: object = "device-assisted-end-to-end",
    assisted_exact: object = True,
    tensor_share_pct: object = 70.0,
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
        # Device-assisted timing does not claim fully native/resident execution.
        "native_path_eligible": False,
        "device_execution_certified": False,
        "backend_used_device": backend_used_device,
        "device_rate_valid": device_rate_valid,
        "execution_path": execution_path,
        "bit_exact": True,
        "stages": {
            "bit_exact": True,
            "tensor_share_pct": tensor_share_pct,
            "tensor_util_pct": tensor_util_pct,
        },
        "tensor_share_pct": tensor_share_pct,
        "tensor_util_pct": tensor_util_pct,
        "device_nonce_per_s": nps,
        "cpu_reference_nonce_per_s": 999999.0,
        "v3_hashrate": v3_hashrate,
        "asert_rescale_num_den_suggestion": asert,
        "lt": {
            "device_native_kernel_wired": False,
            "device_assisted_path_exact": assisted_exact,
        },
    }


LABELS = {
    "b200.json": ("nvidia", "datacenter", "B200"),
    "5090.json": ("nvidia", "consumer", "RTX5090"),
}


class LtGateSchemaTest(unittest.TestCase):
    def evaluate_pair(self, dc: dict, consumer: dict):
        return lt_gate.evaluate([dc, consumer], LABELS, {}, False)

    def test_positive_device_assisted_rate_drives_g2_without_native_claim(self):
        go, gates, rows, reasons, notes, summary = self.evaluate_pair(
            report("b200.json", 400.0), report("5090.json", 100.0)
        )

        self.assertFalse(go)  # G3-G8 remain deliberately fail-closed.
        self.assertTrue(gates["G1_tensor_majority"])
        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertEqual([row["nps"] for row in rows], [400.0, 100.0])
        self.assertTrue(all(row["device_measured"] for row in rows))
        self.assertTrue(all(not row["native_path_eligible"] for row in rows))
        self.assertEqual(summary["g2_evidence"]["ratio"], 4.0)
        self.assertFalse(any("G2 B200/5090 ratio" in reason for reason in reasons))

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
            lt_gate.device_measured(report("b200.json", 400.0, execution_path="device-native"))
        )
        self.assertFalse(
            lt_gate.device_measured(report("b200.json", 400.0, assisted_exact=False))
        )
        self.assertFalse(lt_gate.device_measured(report("b200.json", 400.0, backend="cpu")))
        wrong_type = report("b200.json", 400.0)
        wrong_type["backend_used_device"] = 1
        self.assertFalse(lt_gate.device_measured(wrong_type))

        for top_level in ("backend_used_device", "device_rate_valid", "execution_path"):
            with self.subTest(missing=top_level):
                missing = report("b200.json", 400.0)
                del missing[top_level]
                self.assertFalse(lt_gate.device_measured(missing))
        missing_nested = report("b200.json", 400.0)
        del missing_nested["lt"]["device_assisted_path_exact"]
        self.assertFalse(lt_gate.device_measured(missing_nested))

    def test_tensor_util_is_diagnostic_not_g1_input(self):
        dc = report("b200.json", 400.0, tensor_util_pct="unknown")
        dc["tensor_util_pct"] = None
        consumer = report("5090.json", 100.0, tensor_util_pct=None)
        consumer["stages"]["tensor_util_pct"] = 47.5

        _, gates, rows, _, _, _ = self.evaluate_pair(dc, consumer)
        self.assertTrue(gates["G1_tensor_majority"])
        self.assertIsNone(rows[0]["tensor_util_pct"])
        self.assertEqual(rows[1]["tensor_util_pct"], 47.5)

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
