#!/usr/bin/env python3
"""Fail-closed tests for exact-build Epoch-A ASERT derivation."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "contrib/matmul-v4/derive-epoch-a-asert.py"
IDENTITY_SCRIPT = REPO_ROOT / "contrib/matmul-v4/evidence_source_identity.py"
LEGACY_EVIDENCE = (
    REPO_ROOT
    / "doc/evidence/asert-two-rig-calibration-2026-08-03/raw/two-rig-v3-vs-rc.json"
)
SPEC = importlib.util.spec_from_file_location("derive_epoch_a_asert", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
IDENTITY_SPEC = importlib.util.spec_from_file_location(
    "evidence_source_identity_for_asert_test", IDENTITY_SCRIPT
)
assert IDENTITY_SPEC is not None and IDENTITY_SPEC.loader is not None
IDENTITY_MODULE = importlib.util.module_from_spec(IDENTITY_SPEC)
IDENTITY_SPEC.loader.exec_module(IDENTITY_MODULE)
REVISION = subprocess.run(
    ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
    capture_output=True, text=True, check=True,
).stdout.strip()
FINGERPRINT = MODULE.tree_fingerprint(REPO_ROOT, REVISION)
MACS = MODULE.CANONICAL_RC_EPISODE_MACS
POLICY = {
    "method": MODULE.COEFFICIENT_POLICY_METHOD,
    "safety_margin_bps": 1000,
    "coefficient_quantum": 100,
}


def identity() -> dict:
    return {
        "source_revision": REVISION,
        "source_tree_fingerprint": FINGERPRINT,
        "embedded_source_revision": REVISION,
        "embedded_source_dirty": False,
    }


def parent_sample(
    provider: str, binary: str, *, seed: int, wall: int,
) -> dict:
    other = "metal" if provider == "cuda" else "cuda"
    digest_requests = 2
    return {
        **identity(),
        "tool": MODULE.PARENT_TOOL,
        "schema_version": MODULE.PARENT_SCHEMA_VERSION,
        "binary_sha256": binary,
        "mode": "mixed",
        "eps": 18,
        "nBits": "1c487c56",
        "matmul_dimension": 512,
        "transcript_block_size": 16,
        "noise_rank": 8,
        "seed": seed,
        "height": 200000,
        "parent_mtp": 1779999910,
        "tries": 100,
        "attempts_done": 100,
        "wall_s": wall,
        "attempts_per_s": 100 / wall,
        "solved": False,
        "solve_runtime_attempts": 1,
        "solve_runtime_solved_attempts": 0,
        "solve_runtime_failed_attempts": 1,
        "requested_backend": provider,
        "active_backend": provider,
        "backend_selection_reason": "explicit_required_backend",
        "required_backend_enabled": True,
        "required_backend_satisfied": True,
        "digest_requests": digest_requests,
        "requested_cpu": 0,
        "requested_unknown": 0,
        f"requested_{provider}": digest_requests,
        f"requested_{other}": 0,
        f"{provider}_successes": digest_requests,
        f"{other}_successes": 0,
        "metal_digest_mismatches": 0,
        "metal_fallbacks_to_cpu": 0,
        "cuda_fallbacks_to_cpu": 0,
        "cpu_fallbacks": 0,
        "gpu_input_generation_attempts": 1,
        "gpu_input_generation_successes": 1,
        "gpu_input_generation_failures": 0,
        "last_metal_fallback_error": "",
        "last_cuda_fallback_error": "",
        "last_gpu_input_error": "",
    }


def rc_artifact(
    provider: str, architecture: str, harness: str,
    *, nonces: tuple[int, ...] = (1, 2, 3),
    walls: tuple[int, ...] = (9, 10, 11),
) -> dict:
    resolved = f"{provider}_rc_exact_test"
    headers = []
    for nonce, wall in zip(nonces, walls):
        headers.append({
            "header_family": "production_canary",
            "header_nonce": nonce,
            "matmul_dim": 4096,
            "exact_replay_digest": f"{nonce:064x}",
            "wall_s": wall,
            "fully_accelerated": True,
            "require_device": True,
            "device_macs": MACS,
            "cpu_calls": 0,
            "cpu_macs": 0,
            "cpu_fallbacks": 0,
            "first_failure": "",
        })
    return {
        **identity(),
        "tool": MODULE.RC_TOOL,
        "schema_version": MODULE.RC_SCHEMA_VERSION,
        "harness_sha256": harness,
        "backend_requested": provider,
        "backend": resolved,
        "production_provider_identity": {
            "provider_family": provider,
            "device_architecture": architecture,
            "driver_identity": "driver_public_class",
            "runtime_identity": "runtime_public_class",
            "complete": True,
            "reason": "complete",
        },
        "profile": "episode",
        "toy": False,
        "medium": False,
        "production_dims": True,
        "episode_profile": 1,
        "header_matmul_dim": 4096,
        "rounds_override": 0,
        "evidence_kind": "production_chrono_measured",
        "params": copy.deepcopy(MODULE.EXPECTED_RC_PARAMS),
        "run_variance": {
            "n_runs": len(walls),
            "episode_wall_samples_s": list(walls),
        },
        "frozen_headers": headers,
        "exact_replay_acceleration": {
            "provider": resolved,
            "resolution_reason": "strict_self_qualified",
            "device_backend_present": True,
            "require_device": True,
            "fully_accelerated": True,
            "all_consensus_macs_on_device": True,
            "expected_macs": MACS * len(walls),
            "device_calls": 136 * len(walls),
            "device_macs": MACS * len(walls),
            "cpu_calls": 0,
            "cpu_macs": 0,
            "cpu_fallbacks": 0,
            "first_failure": "",
        },
    }


def rig(provider: str, architecture: str, *, parent_wall: int) -> dict:
    binary = "a" * 64 if provider == "cuda" else "b" * 64
    harness = "c" * 64 if provider == "cuda" else "d" * 64
    return {
        **identity(),
        "provider_family": provider,
        "device_architecture": architecture,
        "parent_binary_sha256": binary,
        "rc_harness_sha256": harness,
        "mixed_mode_samples": [
            parent_sample(provider, binary, seed=seed, wall=parent_wall)
            for seed in range(1, 6)
        ],
        "rc_episode_samples": [rc_artifact(provider, architecture, harness)],
    }


def payload(*, include_metal: bool = False) -> dict:
    rigs = [rig("cuda", "sm_120", parent_wall=2)]
    if include_metal:
        rigs.append(rig("metal", "m4_class", parent_wall=5))
    return {
        **identity(),
        "tool": MODULE.ROOT_TOOL,
        "schema_version": MODULE.ROOT_SCHEMA_VERSION,
        "consensus_context": copy.deepcopy(MODULE.EXPECTED_CONTEXT),
        "coefficient_policy": copy.deepcopy(POLICY),
        "rigs": rigs,
    }


class EpochAAsertCalibrationTest(unittest.TestCase):
    def derive(self, value: dict, *, input_hash: str | None = None) -> dict:
        return MODULE.derive(
            value, expected_revision=REVISION,
            expected_fingerprint=FINGERPRINT,
            input_file_sha256=input_hash,
        )

    def assert_rejected(self, value: dict, pattern: str) -> None:
        with self.assertRaisesRegex(MODULE.CalibrationError, pattern):
            self.derive(value)

    def test_raw_samples_derive_exact_coefficient_and_hashes(self) -> None:
        value = payload()
        result = self.derive(value, input_hash="e" * 64)
        self.assertEqual(result["selected_provider_family"], "cuda")
        self.assertEqual(result["nMatMulRCAsertRescaleNum"], 700)
        self.assertEqual(result["nMatMulRCAsertRescaleDen"], 1)
        self.assertEqual(result["input_file_sha256"], "e" * 64)
        self.assertEqual(
            result["input_payload_sha256"], MODULE.canonical_payload_sha256(value)
        )
        cuda = result["providers"][0]
        self.assertEqual(cuda["parent_binary_sha256"], "a" * 64)
        self.assertEqual(cuda["rc_harness_sha256"], "c" * 64)
        self.assertEqual(cuda["parent_seeds"], [1, 2, 3, 4, 5])
        self.assertEqual(cuda["rc_episode_nonces"], [1, 2, 3])
        self.assertEqual(cuda["coefficient_point_estimate"], "500")
        self.assertEqual(cuda["observed_upper_envelope"], "550")
        self.assertEqual(cuda["coefficient_quantized_up"], 700)

    def test_policy_is_explicit_and_fail_closed(self) -> None:
        value = payload()
        del value["coefficient_policy"]
        self.assert_rejected(value, "coefficient_policy must be an object")
        for field, replacement in (
            ("method", "mean_round_half_up"),
            ("safety_margin_bps", -1),
            ("coefficient_quantum", 0),
        ):
            with self.subTest(field=field):
                value = payload()
                value["coefficient_policy"][field] = replacement
                self.assert_rejected(value, f"coefficient_policy.{field}")

    def test_quantization_is_stable_inside_reviewed_bucket(self) -> None:
        value = payload()
        first = self.derive(value)["nMatMulRCAsertRescaleNum"]
        sample = value["rigs"][0]["rc_episode_samples"][0]
        sample["frozen_headers"][2]["wall_s"] = "11.5"
        sample["run_variance"]["episode_wall_samples_s"][2] = "11.5"
        second = self.derive(value)["nMatMulRCAsertRescaleNum"]
        self.assertEqual((first, second), (700, 700))

        sample["frozen_headers"][2]["wall_s"] = 13
        sample["run_variance"]["episode_wall_samples_s"][2] = 13
        self.assertEqual(self.derive(value)["nMatMulRCAsertRescaleNum"], 800)

    def test_exact_quantum_boundary_does_not_add_an_extra_quantum(self) -> None:
        value = payload()
        value["coefficient_policy"]["safety_margin_bps"] = 0
        value["coefficient_policy"]["coefficient_quantum"] = 50
        self.assertEqual(self.derive(value)["nMatMulRCAsertRescaleNum"], 550)

    def test_equal_provider_coefficients_have_stable_selection(self) -> None:
        value = payload(include_metal=True)
        value["rigs"][1] = rig("metal", "m4_class", parent_wall=2)
        with mock.patch.object(MODULE, "REQUIRED_PROVIDERS", ("cuda", "metal")):
            result = self.derive(value)
        self.assertEqual(
            result["providers"][0]["coefficient_quantized_up"],
            result["providers"][1]["coefficient_quantized_up"],
        )
        self.assertEqual(result["selected_provider_family"], "cuda")

    def test_legacy_self_asserted_evidence_fails_closed(self) -> None:
        legacy = json.loads(LEGACY_EVIDENCE.read_text(encoding="utf-8"))
        self.assert_rejected(legacy, "schema_version=4")

    def test_missing_required_provider_fails_closed(self) -> None:
        value = payload()
        with mock.patch.object(MODULE, "REQUIRED_PROVIDERS", ("cuda", "metal")):
            self.assert_rejected(value, "missing required providers")

    def test_duplicate_provider_fails_closed(self) -> None:
        value = payload()
        value["rigs"].append(copy.deepcopy(value["rigs"][0]))
        self.assert_rejected(value, "duplicate required provider")

    def test_unknown_provider_fails_closed(self) -> None:
        value = payload()
        value["rigs"][0]["provider_family"] = "hip"
        self.assert_rejected(value, "provider_family is unsupported")

    def test_noncanonical_context_fails_closed(self) -> None:
        value = payload()
        value["consensus_context"]["assumed_nbits"] = "1d00ffff"
        self.assert_rejected(value, "consensus_context")

    def test_every_parent_identity_is_bound(self) -> None:
        value = payload()
        value["rigs"][0]["mixed_mode_samples"][0]["embedded_source_revision"] = "f" * 40
        self.assert_rejected(value, "embedded_source_revision mismatch")

    def test_every_rc_identity_is_bound(self) -> None:
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["source_tree_fingerprint"] = "f" * 64
        self.assert_rejected(value, "source_tree_fingerprint mismatch")

    def test_parent_binary_mismatch_fails_closed(self) -> None:
        value = payload()
        value["rigs"][0]["mixed_mode_samples"][0]["binary_sha256"] = "f" * 64
        self.assert_rejected(value, "binary_sha256 mismatch")

    def test_parent_context_mismatch_fails_closed(self) -> None:
        for field, replacement in (("mode", "sigma"), ("eps", 17),
                                   ("nBits", "1d00ffff"),
                                   ("matmul_dimension", 1024)):
            with self.subTest(field=field):
                value = payload()
                value["rigs"][0]["mixed_mode_samples"][0][field] = replacement
                self.assert_rejected(value, field)

    def test_parent_incomplete_or_solved_fails_closed(self) -> None:
        value = payload()
        value["rigs"][0]["mixed_mode_samples"][0]["attempts_done"] = 99
        self.assert_rejected(value, "complete every requested attempt")
        value = payload()
        value["rigs"][0]["mixed_mode_samples"][0]["solved"] = True
        self.assert_rejected(value, "solved must be false")

    def test_parent_cpu_or_provider_fallback_fails_closed(self) -> None:
        value = payload()
        value["rigs"][0]["mixed_mode_samples"][0]["cpu_fallbacks"] = 1
        self.assert_rejected(value, "cpu_fallbacks must be zero")
        value = payload()
        value["rigs"][0]["mixed_mode_samples"][0]["active_backend"] = "cpu"
        self.assert_rejected(value, "did not select cuda")

    def test_parent_counter_inconsistency_fails_closed(self) -> None:
        value = payload()
        value["rigs"][0]["mixed_mode_samples"][0]["cuda_successes"] = 1
        self.assert_rejected(value, "cuda_successes must equal digest_requests")
        value = payload()
        value["rigs"][0]["mixed_mode_samples"][0]["attempts_per_s"] = 1
        self.assert_rejected(value, "does not match raw attempts/wall")
        value = payload()
        value["rigs"][0]["mixed_mode_samples"][0][
            "gpu_input_generation_successes"
        ] = 0
        self.assert_rejected(value, "incomplete GPU-input accounting")

    def test_duplicate_and_cross_provider_parent_seeds_fail_closed(self) -> None:
        value = payload()
        value["rigs"][0]["mixed_mode_samples"][1]["seed"] = 1
        self.assert_rejected(value, "duplicate seeds")
        value = payload(include_metal=True)
        value["rigs"][1]["mixed_mode_samples"][0]["seed"] = 100
        with mock.patch.object(MODULE, "REQUIRED_PROVIDERS", ("cuda", "metal")):
            self.assert_rejected(value, "same parent seed set")

    def test_rc_harness_hash_and_provider_are_bound(self) -> None:
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["harness_sha256"] = "f" * 64
        self.assert_rejected(value, "harness_sha256 mismatch")
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["backend"] = "metal_rc_exact_test"
        self.assert_rejected(value, "backend is not a cuda provider")

    def test_rc_profile_dimension_and_params_are_bound(self) -> None:
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["episode_profile"] = 2
        self.assert_rejected(value, "episode_profile")
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["header_matmul_dim"] = 2048
        self.assert_rejected(value, "header_matmul_dim")
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["params"]["n_ctx"] = 1
        self.assert_rejected(value, "params does not match")
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["params"]["d_ff"] = 8192
        self.assert_rejected(value, "params does not match")

    def test_rc_exact_canonical_macs_are_required(self) -> None:
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["exact_replay_acceleration"]["device_macs"] -= 1
        self.assert_rejected(value, "canonical TotalRCEpisodeMacs")
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["frozen_headers"][0]["device_macs"] -= 1
        self.assert_rejected(value, "not strict production Profile 1")

    def test_rc_cpu_failure_or_dirty_fails_closed(self) -> None:
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["exact_replay_acceleration"]["cpu_calls"] = 1
        self.assert_rejected(value, "cpu_calls must be zero")
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["exact_replay_acceleration"]["first_failure"] = "device_error"
        self.assert_rejected(value, "first_failure must be empty")
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["embedded_source_dirty"] = True
        self.assert_rejected(value, "embedded_source_dirty must be false")

    def test_rc_wall_and_run_count_are_raw_and_consistent(self) -> None:
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["frozen_headers"][0]["wall_s"] = 99
        self.assert_rejected(value, "does not match run_variance")
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["run_variance"]["n_runs"] = 2
        self.assert_rejected(value, "counts do not match")

    def test_duplicate_and_cross_provider_rc_nonces_fail_closed(self) -> None:
        value = payload()
        value["rigs"][0]["rc_episode_samples"][0]["frozen_headers"][1]["header_nonce"] = 1
        self.assert_rejected(value, "duplicate nonces")
        value = payload(include_metal=True)
        value["rigs"][1]["rc_episode_samples"][0]["frozen_headers"][0]["header_nonce"] = 100
        with mock.patch.object(MODULE, "REQUIRED_PROVIDERS", ("cuda", "metal")):
            self.assert_rejected(value, "same RC nonce set")

    def test_cross_provider_rc_digest_mismatch_fails_closed(self) -> None:
        value = payload(include_metal=True)
        value["rigs"][1]["rc_episode_samples"][0]["frozen_headers"][0][
            "exact_replay_digest"
        ] = "f" * 64
        with mock.patch.object(MODULE, "REQUIRED_PROVIDERS", ("cuda", "metal")):
            self.assert_rejected(value, "byte-identical RC digests")

    def test_at_least_three_rc_runs_are_required(self) -> None:
        value = payload()
        sample = value["rigs"][0]["rc_episode_samples"][0]
        sample["frozen_headers"] = sample["frozen_headers"][:2]
        sample["run_variance"]["episode_wall_samples_s"] = [9, 10]
        sample["run_variance"]["n_runs"] = 2
        sample["exact_replay_acceleration"]["expected_macs"] = MACS * 2
        sample["exact_replay_acceleration"]["device_macs"] = MACS * 2
        self.assert_rejected(value, "at least three RC episode runs")

    def test_coefficient_must_fit_uint64(self) -> None:
        value = payload()
        for sample in value["rigs"][0]["mixed_mode_samples"]:
            sample["tries"] = MODULE.UINT64_MAX
            sample["attempts_done"] = MODULE.UINT64_MAX
            sample["wall_s"] = "0.000000000000000001"
            sample["attempts_per_s"] = str(
                MODULE.Decimal(MODULE.UINT64_MAX) / MODULE.Decimal("0.000000000000000001")
            )
        self.assert_rejected(value, "outside uint64 range")

    def test_revision_must_resolve_to_that_exact_commit(self) -> None:
        tree = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD^{tree}"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        with self.assertRaisesRegex(MODULE.CalibrationError, "exact commit"):
            MODULE.resolve_commit(REPO_ROOT, tree)

    def test_shared_and_asert_fingerprint_policies_match(self) -> None:
        self.assertEqual(
            MODULE.tree_fingerprint(REPO_ROOT, REVISION),
            IDENTITY_MODULE.tree_fingerprint(REPO_ROOT, REVISION),
        )

    def test_uint64_cli_parser_is_strict(self) -> None:
        self.assertEqual(MODULE.parse_uint64("0"), 0)
        self.assertEqual(MODULE.parse_uint64(str(MODULE.UINT64_MAX)), MODULE.UINT64_MAX)
        for value in ("-1", "+1", "01", "1.0", str(MODULE.UINT64_MAX + 1)):
            with self.subTest(value=value):
                with self.assertRaises(Exception):
                    MODULE.parse_uint64(value)


if __name__ == "__main__":
    unittest.main()
