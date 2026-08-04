#!/usr/bin/env python3
"""Focused fail-closed tests for the Epoch-A activation evidence binder."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "contrib/matmul-v4/verify-epoch-a-activation-gate.py"
SPEC = importlib.util.spec_from_file_location("epoch_a_activation_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REVISION = "1" * 40
FINGERPRINT = "2" * 64
BINARY_HASHES = {
    "btxd": "3" * 64,
    "btx_cli": "4" * 64,
    "parent_calibration": "5" * 64,
    "cuda_rc_harness": "6" * 64,
    "metal_rc_harness": "7" * 64,
}


def policy() -> dict:
    return {
        "activation_tuple": {
            "height": 185000,
            "nMatMulRCAsertRescaleNum": 4007014530,
            "nMatMulRCAsertRescaleDen": 1,
        },
        "ratification": {
            "BTX_MATMUL_NO_INVERSION_GATE_RATIFIED": True,
            "BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED": True,
        },
        "provider_policy": {
            "asert_calibration": ["cuda"],
            "production_goldens": ["cuda", "metal"],
            "lifecycle": ["cuda"],
        },
        "lifecycle_policy": {
            "regtest_activation_height": 6,
            "minimum_complete_samples": 2,
            "maximum_p99_s": 90,
            "maximum_max_s": 100,
            "maximum_incomplete_samples": 0,
            "minimum_contention_samples": 1,
            "required_phases": ["steady_mine_relay", "competing_tip"],
        },
    }


def runtime_node(*, validation: bool) -> dict:
    result = {
        "resolved_provider": "cuda_rc_exact_test",
        "production_canary": {
            "outcome": "passed",
            "attempted": True,
            "passed": True,
            "manifest_has_reviewed_goldens": True,
            "build_provenance_matches": True,
            "build_source_dirty": False,
            "build_source_revision": REVISION,
            "build_source_tree_fingerprint": FINGERPRINT,
            "exact_manifest_match": True,
            "provider": "cuda_rc_exact_test",
            "provider_family": "cuda",
            "device_architecture": "sm_120",
            "epoch_activation_height": 6,
            "epoch_profile": 1,
            "epoch_matmul_dimension": 4096,
            "device_macs": 141149805215744,
            "device_xof_fallbacks": 0,
            "host_xof_calls": 0,
            "cpu_fallbacks": 0,
            "reason": "passed",
        },
        "last_validation": {},
        "provider_health": {
            "quarantined": False,
            "validator_readiness_lost": False,
            "provider": "cuda_rc_exact_test",
            "reason": "ready",
        },
    }
    if validation:
        result["last_validation"] = {
            "available": True,
            "outcome": "valid",
            "execution_policy": "strict-device",
            "require_device": True,
            "provider": "cuda_rc_exact_test",
            "fully_accelerated": True,
            "device_gemm_calls": 136,
            "device_gemm_macs": 141149805215744,
            "device_xof_fallbacks": 0,
            "host_xof_calls": 0,
            "cpu_gemm_calls": 0,
            "cpu_gemm_fallbacks": 0,
            "acceleration_failure": "",
            "failure_kind": "none",
            "adjudication": "none",
            "wall_s": 20,
        }
    return result


def lifecycle() -> dict:
    samples = []
    for phase, wall in (("steady_mine_relay", 80), ("competing_tip", 85)):
        components = {
            "candidate_execution_s": wall - 7,
            "candidate_queue_wait_s": 1,
            "winner_reseal_s": 1,
            "reseal_queue_wait_s": 1,
            "winner_authority_handoff_s": 1,
            "authenticated_relay_s": 1,
            "tip_validation_s": 1,
            "validation_queue_wait_s": 1,
        }
        samples.append({
            "complete": True,
            "phase": phase,
            "complete_lifecycle_s": wall,
            "components": components,
            "authority_measured": True,
            "counter_gaps": [],
            "block_hash": f"{len(samples) + 1:064x}",
            "miner_provider": "cuda_rc_exact_test",
            "validator_provider": "cuda_rc_exact_test",
            "validator_execution_policy": "strict-device",
            "validator_fully_accelerated": True,
            "validator_cpu_gemm_calls": 0,
            "validator_cpu_gemm_fallbacks": 0,
        })
    return {
        "tool": MODULE.LIFECYCLE_TOOL,
        "schema_version": MODULE.LIFECYCLE_SCHEMA_VERSION,
        "evidence_kind": "cuda_complete_lifecycle_asert_calibration",
        "source_revision": REVISION,
        "source_tree_fingerprint": FINGERPRINT,
        "binary_sha256": {
            "btxd": BINARY_HASHES["btxd"],
            "btx_cli": BINARY_HASHES["btx_cli"],
        },
        "execution_policy": "strict-device",
        "mode": "production",
        "profile": 1,
        "matmul_dim": 4096,
        "nodes": 2,
        "activation_height_regtest": 6,
        "ratification": {
            "campaign_authorizes_no_inversion_gate": False,
            "campaign_authorizes_gpu_lifecycle_gate": False,
            "installs_rc_asert_ratio": False,
            "operationally_ready_claim": False,
        },
        "component_definition": [
            "candidate_execution_s", "candidate_queue_wait_s",
            "winner_reseal_s", "reseal_queue_wait_s",
            "winner_authority_handoff_s", "authenticated_relay_s",
            "tip_validation_s", "validation_queue_wait_s",
        ],
        "complete_sample_count": 2,
        "incomplete_sample_count": 0,
        "samples": samples,
        "complete_lifecycle_summary_s": {
            "n": 2, "min": 80, "p50": 80, "p95": 85, "p99": 85,
            "max": 85, "mean": 82.5,
        },
        "runtime_builds": {
            "miner": runtime_node(validation=False),
            "validator": runtime_node(validation=True),
        },
    }


class EpochAActivationGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_lifecycle(self, value: dict) -> Path:
        path = self.root / "lifecycle.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_imports_dataclass_based_golden_verifier(self) -> None:
        verifier = MODULE.import_tool(
            REPO_ROOT / "contrib/matmul-v4/verify-production-golden-seal.py",
            "epoch_a_gate_test_golden_verifier",
        )
        self.assertEqual(verifier.MANIFEST_MAGIC, "BTX_RC_PRODUCTION_GOLDEN_V1")

    def assert_lifecycle_rejected(self, value: dict, pattern: str) -> None:
        with self.assertRaisesRegex(MODULE.GateError, pattern):
            MODULE.validate_lifecycle(
                self.write_lifecycle(value), policy(), REVISION, FINGERPRINT,
                BINARY_HASHES,
            )

    def test_source_tuple_binds_height_coefficient_and_both_flags(self) -> None:
        (self.root / "src/kernel").mkdir(parents=True)
        (self.root / "src/consensus").mkdir(parents=True)
        (self.root / "src/kernel/chainparams.cpp").write_text(
            "static constexpr int64_t kRCEpochAAsertRescaleNum{4007014530};\n"
            "static constexpr int64_t kRCEpochAAsertRescaleDen{1};\n"
            "static constexpr int32_t BTX_MATMUL_V47_EPOCH_A_HEIGHT{185'000};\n"
            "consensus.nMatMulV4Height = BTX_MATMUL_V47_EPOCH_A_HEIGHT;\n"
            "consensus.nMatMulBMX4CHeight = BTX_MATMUL_V47_EPOCH_A_HEIGHT;\n"
            "consensus.nMatMulRCHeight = BTX_MATMUL_V47_EPOCH_A_HEIGHT;\n"
            "consensus.nMatMulRCAsertRescaleNum = kRCEpochAAsertRescaleNum;\n",
            encoding="utf-8",
        )
        (self.root / "src/consensus/params.h").write_text(
            "static constexpr bool BTX_MATMUL_NO_INVERSION_GATE_RATIFIED{true};\n"
            "static constexpr bool BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED{true};\n",
            encoding="utf-8",
        )
        MODULE.validate_source_tuple(self.root, policy())
        changed = policy()
        changed["activation_tuple"]["height"] += 1
        with self.assertRaisesRegex(MODULE.GateError, "activation height"):
            MODULE.validate_source_tuple(self.root, changed)
        changed = policy()
        changed["ratification"]["BTX_MATMUL_NO_INVERSION_GATE_RATIFIED"] = False
        with self.assertRaisesRegex(MODULE.GateError, "must be true"):
            MODULE.validate_source_tuple(self.root, changed)

    def test_coefficient_is_signed_consensus_bounded(self) -> None:
        self.assertEqual(MODULE.exact_int(MODULE.INT64_MAX, "coefficient"), MODULE.INT64_MAX)
        with self.assertRaisesRegex(MODULE.GateError, "integer"):
            MODULE.exact_int(MODULE.INT64_MAX + 1, "coefficient")

    def test_calibration_and_correctness_cohorts_are_distinct_and_fixed(self) -> None:
        MODULE.validate_provider_policy(policy())
        for field, replacement in (
            ("asert_calibration", ["cuda", "metal"]),
            ("production_goldens", ["cuda"]),
            ("lifecycle", ["metal"]),
        ):
            changed = policy()
            changed["provider_policy"][field] = replacement
            with self.subTest(field=field):
                with self.assertRaises(MODULE.GateError):
                    MODULE.validate_provider_policy(changed)

    def test_lifecycle_binds_exact_builds_strict_execution_and_policy(self) -> None:
        MODULE.validate_lifecycle(
            self.write_lifecycle(lifecycle()), policy(), REVISION, FINGERPRINT,
            BINARY_HASHES,
        )
        changed = lifecycle()
        changed["runtime_builds"]["validator"]["production_canary"][
            "build_source_tree_fingerprint"
        ] = "f" * 64
        self.assert_lifecycle_rejected(changed, "fingerprint mismatch")
        changed = lifecycle()
        changed["samples"][0]["validator_cpu_gemm_fallbacks"] = 1
        self.assert_lifecycle_rejected(changed, "cpu_gemm_fallbacks mismatch")

    def test_lifecycle_thresholds_and_contention_fail_closed(self) -> None:
        changed = lifecycle()
        changed["samples"][1]["complete_lifecycle_s"] = 91
        changed["samples"][1]["components"]["candidate_execution_s"] += 6
        changed["complete_lifecycle_summary_s"].update({
            "p95": 91, "p99": 91, "max": 91, "mean": 85.5,
        })
        self.assert_lifecycle_rejected(changed, "p99 exceeds")
        changed = lifecycle()
        changed["samples"][1]["phase"] = "steady_mine_relay"
        self.assert_lifecycle_rejected(changed, "required phases")

    def test_measurement_artifact_cannot_self_ratify(self) -> None:
        changed = lifecycle()
        changed["ratification"]["campaign_authorizes_gpu_lifecycle_gate"] = True
        self.assert_lifecycle_rejected(changed, "must not self-authorize")


if __name__ == "__main__":
    unittest.main()
