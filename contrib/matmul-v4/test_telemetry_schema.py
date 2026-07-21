#!/usr/bin/env python3
"""Telemetry schema vs emitted-field agreement (WS-F).

matmul-v4-report --telemetry-only emits schema_version 3 JSON with a fixed
field contract. Readiness gates must treat telemetry as diagnostic — never
as certification evidence. This check pins the contract without fabricating
hardware measurements.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

LT_GATE_PATH = Path(__file__).with_name("lt-gate.py")
SPEC = importlib.util.spec_from_file_location("lt_gate", LT_GATE_PATH)
assert SPEC is not None and SPEC.loader is not None
lt_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lt_gate)

# Fields matmul-v4-report.cpp EmitLtTelemetryReport always writes (schema v3).
# Keep in sync with src/matmul-v4-report.cpp telemetry-only JSON path.
TELEMETRY_ROOT_REQUIRED = {
    "tool",
    "schema_version",
    "source_revision",
    "host",
    "host_cpu_arch",
    "host_cpu",
    "host_cpu_provenance_complete",
    "backend",
    "device",
    "n",
    "window",
    "rounds",
    "profile",
    "measurement_mode",
    "telemetry_only",
    "telemetry_device_nonce_per_s",
    "telemetry_rate_valid",
    "device_nonce_per_s",
    "device_rate_valid",
    "device_execution_certified",
    "native_path_eligible",
    "lt",
    "verdict",
}

TELEMETRY_LT_REQUIRED = {
    "qstar_window",
    "qstar_device_batched",
    "device_w_generation",
    "device_digest",
    "per_nonce_sync_absent",
    "native_mxfp4_qualified",
    "native_fp8_qualified",
    "peak_status_measured",
    "peak_ready",
    "rate_provenance",
}


def telemetry_report(**extra):
    """Minimal honest telemetry-only fixture matching report emit contract."""
    base = {
        "tool": "matmul-v4-report",
        "schema_version": 3,
        "source_revision": "deadbeef",
        "host": "test-host",
        "host_cpu_arch": "x86_64",
        "host_cpu": {
            "model": "test CPU",
            "cpu_affinity_list": "0-7",
            "logical_cpus": 8,
        },
        "host_cpu_provenance_complete": True,
        "backend": "cuda",
        "device": {
            "compiled": True,
            "available": True,
            "admissible": True,
            "reason": "test",
        },
        "n": 256,
        "window": 128,
        "rounds": 1,
        "profile": "bmx4c-lt",
        "measurement_mode": "telemetry-only-device-resident-qstar",
        "telemetry_only": True,
        "telemetry_device_nonce_per_s": 1000.0,
        "telemetry_rate_valid": True,
        # Certification / readiness fields must stay ineligible.
        "device_nonce_per_s": None,
        "device_rate_valid": False,
        "device_execution_certified": False,
        "native_path_eligible": False,
        "lt": {
            "qstar_window": 128,
            "qstar_device_batched": True,
            "device_w_generation": True,
            "device_digest": True,
            "per_nonce_sync_absent": True,
            "native_mxfp4_qualified": False,
            "native_fp8_qualified": False,
            "peak_status_measured": False,
            "peak_ready": None,
            "rate_provenance": "telemetry-only-device-resident-qstar-batched",
        },
        "verdict": (
            "TELEMETRY-ONLY: resident Q* host-wall timing obtained; all silicon-rate, "
            "certification, readiness, tensor-majority, and ASERT claims are withheld"
        ),
    }
    base.update(extra)
    return base


class TelemetrySchemaAgreementTests(unittest.TestCase):
    def test_required_root_and_lt_fields_present(self):
        rep = telemetry_report()
        missing_root = TELEMETRY_ROOT_REQUIRED - set(rep)
        self.assertFalse(missing_root, f"missing root fields: {sorted(missing_root)}")
        missing_lt = TELEMETRY_LT_REQUIRED - set(rep["lt"])
        self.assertFalse(missing_lt, f"missing lt fields: {sorted(missing_lt)}")
        self.assertEqual(rep["schema_version"], 3)
        self.assertEqual(rep["profile"], "bmx4c-lt")
        self.assertTrue(rep["telemetry_only"])
        self.assertEqual(
            rep["measurement_mode"], "telemetry-only-device-resident-qstar"
        )

    def test_telemetry_never_certifies_native_or_device_rate(self):
        rep = telemetry_report()
        self.assertIsNone(rep["device_nonce_per_s"])
        self.assertFalse(rep["device_rate_valid"])
        self.assertFalse(rep["device_execution_certified"])
        self.assertFalse(rep["native_path_eligible"])
        self.assertFalse(rep["lt"]["native_mxfp4_qualified"])
        self.assertFalse(rep["lt"]["peak_status_measured"])

    def test_lt_gate_treats_telemetry_as_diagnostic_not_go(self):
        """Missing certification evidence stays fail-closed — never GO."""
        labels = {
            "telemetry.json": ("nvidia", "datacenter", "B200 telemetry"),
        }
        rep = telemetry_report()
        rep["_file"] = "telemetry.json"
        go, gates, _rows, reasons, notes, _extra = lt_gate.evaluate(
            [rep], labels, {}, False
        )
        self.assertFalse(go)
        self.assertTrue(rep["host_cpu_provenance_complete"] is True)
        self.assertIn("model", rep["host_cpu"])
        self.assertTrue(
            any("telemetry" in n.lower() for n in notes)
            or any("telemetry" in r.lower() for r in reasons)
            or not gates.get("G1_tensor_majority", True),
            msg=f"notes={notes} reasons={reasons} gates={gates}",
        )


if __name__ == "__main__":
    raise SystemExit(unittest.main(verbosity=2))
