#!/usr/bin/env python3
"""Focused checks for ENC_RC rc-gate nonempty → numeric-threshold rule."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("rc-gate.py")
SPEC = importlib.util.spec_from_file_location("rc_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
rc_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rc_gate)


def toy_report(**extra):
    base = {
        "_file": "toy.json",
        "tool": "rc-episode-harness",
        "stub": False,
        "toy": True,
        "extractmx_self_qual": {"status": "pass"},
        "allocation_cap_verdicts": {
            "512MiB": "skip",
            "2GiB": "skip",
            "8GiB": "skip",
        },
        "residency_sweep": [{"working_set_bytes": 128 * 1024 * 1024, "wall_s": 1.0}],
        "k_curve": {"mode": "toy_synthetic_structure"},
        "phase_wall_s": {"total": 1.0, "verify": 0.0},
        "wall_clock_provenance": "toy_chrono_measured",
        "evidence_kind": "toy_measured_wall_clock",
    }
    base.update(extra)
    return base


class RCGateNumericThresholdTests(unittest.TestCase):
    def test_empty_g2_never_pass(self):
        rep = toy_report()
        rep["residency_sweep"] = None
        g = rc_gate.gate_report(rep)
        self.assertEqual(g["g2"], "fail")
        self.assertFalse(g["full_pass"])

    def test_nonempty_toy_is_partial_not_go(self):
        g = rc_gate.gate_report(toy_report())
        self.assertIn(g["g2"], ("toy-pass", "partial", "fail"))
        self.assertNotEqual(g["g2"], "pass")
        self.assertFalse(g["full_pass"])
        summary = rc_gate.aggregate([toy_report()])
        self.assertNotEqual(summary["verdict"], "GO")
        self.assertFalse(summary["go"])

    def test_pass_requires_numeric_go_path(self):
        # Non-toy missing measured thresholds must not GO.
        rep = {
            "_file": "prod.json",
            "tool": "rc-episode-harness",
            "stub": False,
            "toy": False,
            "production_dims": True,
            "source_revision": "deadbeef",
            "device_resident": True,
            "native_path_eligible": True,
            "wall_clock_provenance": "chrono_measured",
            "extractmx_self_qual": {"status": "pass", "native_mxfp4_qualified": True},
            "allocation_cap_verdicts": {
                "512MiB": "pass",
                "2GiB": "pass",
                "8GiB": "pass",
            },
            # Nonempty but insufficient for numeric GO thresholds.
            "residency_sweep": [{"note": "placeholder"}],
            "k_curve": {"mode": "measured"},
            "phase_wall_s": {"total": 1.0},
        }
        g = rc_gate.gate_report(rep)
        self.assertNotEqual(g["g2"], "pass")
        self.assertFalse(g["full_pass"])


if __name__ == "__main__":
    raise SystemExit(unittest.main(verbosity=2))
