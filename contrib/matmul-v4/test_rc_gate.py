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

    def test_campaign_simulated_interconnect_never_go(self):
        rep = toy_report(
            tool="rc-stage-g-campaign",
            gpu_campaign_present=False,
            nvlink_campaign_present=False,
            device_resident=False,
            run_variance={"episode_cv": 0.01, "n_runs": 5},
            interconnect_sim={
                "simulated": True,
                "stage_i_gate4_evidence": False,
                "exchange_slowdown_factor": 16.0,
                "stage_i_gate4_pass": False,
            },
            stage_g_blockers=["GPU campaign missing"],
        )
        g = rc_gate.gate_report(rep)
        self.assertFalse(g["full_pass"])
        blob = " ".join(g["reasons"])
        self.assertIn("SIMULATED", blob)
        self.assertIn("GPU", blob)

    def test_omitted_campaign_fields_never_go(self):
        """Assessment #6: missing campaign evidence must not GO (only True passes)."""
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
            "evidence_kind": "measured",
            "extractmx_self_qual": {"status": "pass", "native_mxfp4_qualified": True},
            "allocation_cap_verdicts": {
                "512MiB": "pass",
                "2GiB": "pass",
                "8GiB": "pass",
            },
            "residency_sweep": {
                "cliff_ratio": 2.0,
                "stream_util_frac": 0.5,
                "points": [
                    {"working_set_bytes": 128 * 1024 * 1024, "wall_s": 2.0},
                    {"working_set_bytes": 200 * 1024 * 1024, "wall_s": 1.0},
                ],
            },
            "k_curve": {
                "mode": "measured",
                "digests_match": True,
                "k_at_24gb": 1.5,
                "k_variance": 0.01,
            },
            "phase_wall_s": {"total": 10.0, "verify": 0.05},
            "verifier_floor": {
                "measured": True,
                "full_episode_wall_s": 10.0,
                "full_verify_wall_s": 0.05,
            },
            "run_variance": {"episode_cv": 0.02, "max_cv": 0.02},
            # Intentionally omit gpu_campaign_present / nvlink_campaign_present.
        }
        g = rc_gate.gate_report(rep)
        self.assertFalse(g["full_pass"])
        blob = " ".join(g["reasons"])
        self.assertIn("gpu_campaign_present", blob)
        self.assertIn("nvlink_campaign_present", blob)

    def test_nonempty_string_walls_not_numeric_pass(self):
        """Nonempty string wall/variance values are not a numeric GO pass."""
        rep = toy_report(
            toy=False,
            production_dims=True,
            source_revision="deadbeef",
            device_resident=True,
            native_path_eligible=True,
            wall_clock_provenance="chrono_measured",
            extractmx_self_qual={"status": "pass", "native_mxfp4_qualified": True},
            allocation_cap_verdicts={
                "512MiB": "pass",
                "2GiB": "pass",
                "8GiB": "pass",
            },
            phase_wall_s={"total": "fast", "verify": "ok"},
            run_variance={"episode_cv": "low"},
            residency_sweep=[{"note": "present"}],
            k_curve={"mode": "measured"},
            gpu_campaign_present=True,
            nvlink_campaign_present=True,
        )
        g = rc_gate.gate_report(rep)
        self.assertFalse(g["full_pass"])
        self.assertNotEqual(g["g4"], "pass")
        self.assertFalse(rc_gate._walls_measured(rep["phase_wall_s"]))

    def test_load_accepts_campaign_tool(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c.json"
            p.write_text(
                __import__("json").dumps(
                    {
                        "tool": "rc-stage-g-campaign",
                        "stub": False,
                        "toy": True,
                        "extractmx_self_qual": {"status": "pass"},
                        "allocation_cap_verdicts": {
                            "512MiB": "skip",
                            "2GiB": "skip",
                            "8GiB": "skip",
                        },
                        "residency_sweep": [
                            {"working_set_bytes": 128 * 1024 * 1024, "wall_s": 1.0}
                        ],
                        "k_curve": {"mode": "toy_synthetic_structure"},
                        "phase_wall_s": {"total": 1.0},
                        "wall_clock_provenance": "toy_chrono_measured",
                        "evidence_kind": "toy_measured_wall_clock",
                        "device_resident": False,
                        "run_variance": {"episode_cv": 0.02, "n_runs": 5},
                        "gpu_campaign_present": False,
                        "nvlink_campaign_present": False,
                    }
                ),
                encoding="utf-8",
            )
            reps = rc_gate.load_reports([str(p)])
            self.assertEqual(len(reps), 1)
            self.assertEqual(reps[0]["tool"], "rc-stage-g-campaign")

    def test_scalar_fp4_native_claim_never_go(self):
        """Scalar-decode MXFP4 labeled as native_mxfp4_qualified must not GO."""
        rep = toy_report(
            toy=False,
            production_dims=True,
            source_revision="deadbeef",
            device_resident=True,
            native_path_eligible=True,
            wall_clock_provenance="chrono_measured",
            evidence_kind="measured",
            extractmx_self_qual={
                "status": "pass",
                "native_mxfp4_qualified": True,  # fabricated
                "mx_backend": "mxfp4_blockscaled_device_scalar-decode",
            },
            allocation_cap_verdicts={
                "512MiB": "pass",
                "2GiB": "pass",
                "8GiB": "pass",
            },
            phase_wall_s={"total": 10.0, "verify": 0.05},
            run_variance={"episode_cv": 0.02},
            residency_sweep={
                "cliff_ratio": 2.0,
                "stream_util_frac": 0.5,
                "points": [
                    {"working_set_bytes": 128 * 1024 * 1024, "wall_s": 2.0},
                    {"working_set_bytes": 200 * 1024 * 1024, "wall_s": 1.0},
                ],
            },
            k_curve={
                "mode": "measured",
                "digests_match": True,
                "k_at_24gb": 1.5,
                "k_variance": 0.01,
            },
            verifier_floor={
                "measured": True,
                "full_episode_wall_s": 10.0,
                "full_verify_wall_s": 0.05,
            },
            gpu_campaign_present=True,
            nvlink_campaign_present=True,
        )
        g = rc_gate.gate_report(rep)
        self.assertFalse(g["full_pass"])
        blob = " ".join(g["reasons"])
        self.assertTrue(
            "scalar" in blob.lower() or "native" in blob.lower() or g["g1"] != "pass",
            msg=blob,
        )

    def test_fabricated_projection_label_never_go(self):
        """Fabricated evidence_kind that is projected/MAC must hard-fail GO."""
        rep = toy_report(
            toy=False,
            production_dims=True,
            source_revision="deadbeef",
            device_resident=True,
            native_path_eligible=True,
            wall_clock_provenance="chrono_measured",
            evidence_kind="projected_mac_count",  # fabricated projection label
            extractmx_self_qual={"status": "pass", "native_mxfp4_qualified": True},
            allocation_cap_verdicts={
                "512MiB": "pass",
                "2GiB": "pass",
                "8GiB": "pass",
            },
            phase_wall_s={"total": 10.0, "verify": 0.05},
            run_variance={"episode_cv": 0.02},
            residency_sweep=[{"working_set_bytes": 128 * 1024 * 1024, "wall_s": 1.0}],
            k_curve={"mode": "measured", "digests_match": True},
            gpu_campaign_present=True,
            nvlink_campaign_present=True,
        )
        g = rc_gate.gate_report(rep)
        self.assertFalse(g["full_pass"])
        blob = " ".join(g["reasons"])
        self.assertTrue(
            "REFUSE" in blob or "projected" in blob.lower() or "mac" in blob.lower(),
            msg=blob,
        )


if __name__ == "__main__":
    raise SystemExit(unittest.main(verbosity=2))
