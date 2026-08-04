#!/usr/bin/env python3
"""Focused tests for exact-build Epoch-A ASERT corpus assembly."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "contrib/matmul-v4/assemble-epoch-a-asert-corpus.py"
SPEC = importlib.util.spec_from_file_location("assemble_epoch_a_asert", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
DERIVE = MODULE.DERIVE
REVISION = subprocess.run(
    ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
    capture_output=True,
    text=True,
    check=True,
).stdout.strip()
FINGERPRINT = DERIVE.tree_fingerprint(REPO_ROOT, REVISION)
MACS = DERIVE.CANONICAL_RC_EPISODE_MACS
POLICY_KW = {"safety_margin_bps": 1000, "coefficient_quantum": 100}


def identity() -> dict:
    return {
        "source_revision": REVISION,
        "source_tree_fingerprint": FINGERPRINT,
        "embedded_source_revision": REVISION,
        "embedded_source_dirty": False,
    }


def parent_sample(provider: str, binary: str, seed: int, wall: int) -> dict:
    other = "metal" if provider == "cuda" else "cuda"
    digest_requests = 2
    return {
        **identity(),
        "tool": DERIVE.PARENT_TOOL,
        "schema_version": DERIVE.PARENT_SCHEMA_VERSION,
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
        "untrusted_local_path": "/not/published/from-input",
    }


def rc_artifact(
    provider: str,
    architecture: str,
    harness: str,
    nonces: tuple[int, ...] = (1, 2, 3),
) -> dict:
    resolved = f"{provider}_rc_exact_test"
    walls = list(range(9, 9 + len(nonces)))
    headers = [
        {
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
            "untrusted_host": "not-published",
        }
        for nonce, wall in zip(nonces, walls)
    ]
    return {
        **identity(),
        "tool": DERIVE.RC_TOOL,
        "schema_version": DERIVE.RC_SCHEMA_VERSION,
        "harness_sha256": harness,
        "backend_requested": provider,
        "backend": resolved,
        "production_provider_identity": {
            "provider_family": provider,
            "device_architecture": architecture,
            "driver_identity": "public_driver_class",
            "runtime_identity": "public_runtime_class",
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
        "params": copy.deepcopy(DERIVE.EXPECTED_RC_PARAMS),
        "run_variance": {
            "n_runs": len(nonces),
            "episode_wall_samples_s": walls,
            "untrusted_note": "/not/published/from-input",
        },
        "frozen_headers": headers,
        "exact_replay_acceleration": {
            "provider": resolved,
            "resolution_reason": "strict_self_qualified",
            "device_backend_present": True,
            "require_device": True,
            "fully_accelerated": True,
            "all_consensus_macs_on_device": True,
            "expected_macs": MACS * len(nonces),
            "device_calls": 136 * len(nonces),
            "device_macs": MACS * len(nonces),
            "cpu_calls": 0,
            "cpu_macs": 0,
            "cpu_fallbacks": 0,
            "first_failure": "",
            "untrusted_note": "/not/published/from-input",
        },
    }


def build_rig(
    provider: str,
    architecture: str,
    *,
    seeds: tuple[int, ...] = (1, 2, 3, 4, 5),
    nonces: tuple[int, ...] = (1, 2, 3),
) -> dict:
    binary = "a" * 64 if provider == "cuda" else "b" * 64
    harness = "c" * 64 if provider == "cuda" else "d" * 64
    return MODULE.assemble_rig(
        provider,
        [parent_sample(provider, binary, seed, 2 if provider == "cuda" else 5)
         for seed in seeds],
        [rc_artifact(provider, architecture, harness, nonces)],
        expected_revision=REVISION,
        expected_fingerprint=FINGERPRINT,
    )


class EpochAAsertAssemblyTest(unittest.TestCase):
    def assert_rejected(self, callback, pattern: str) -> None:
        with self.assertRaisesRegex(
            (MODULE.AssemblyError, DERIVE.CalibrationError), pattern
        ):
            callback()

    def test_success_is_sanitized_and_accepted_by_deriver(self) -> None:
        cuda = build_rig("cuda", "sm_120")
        self.assertNotIn("untrusted_local_path", cuda["mixed_mode_samples"][0])
        self.assertNotIn(
            "untrusted_note", cuda["rc_episode_samples"][0]["run_variance"]
        )
        self.assertNotIn(
            "untrusted_host",
            cuda["rc_episode_samples"][0]["frozen_headers"][0],
        )
        self.assertNotIn("/not/published", json.dumps(cuda, sort_keys=True))
        root = MODULE.merge_rigs(
            [cuda],
            expected_revision=REVISION,
            expected_fingerprint=FINGERPRINT,
            **POLICY_KW,
        )
        self.assertEqual(root["tool"], DERIVE.ROOT_TOOL)
        self.assertEqual(root["schema_version"], DERIVE.ROOT_SCHEMA_VERSION)
        self.assertEqual(root["consensus_context"], DERIVE.EXPECTED_CONTEXT)
        self.assertEqual(
            [rig["provider_family"] for rig in root["rigs"]], ["cuda"]
        )
        result = DERIVE.derive(
            root,
            expected_revision=REVISION,
            expected_fingerprint=FINGERPRINT,
        )
        self.assertEqual(result["selected_provider_family"], "cuda")

    def test_revision_and_fingerprint_mismatch_fail_closed(self) -> None:
        binary = "a" * 64
        harness = "c" * 64
        parents = [parent_sample("cuda", binary, seed, 2) for seed in range(1, 6)]
        artifacts = [rc_artifact("cuda", "sm_120", harness)]
        parents[0]["source_tree_fingerprint"] = "f" * 64
        self.assert_rejected(
            lambda: MODULE.assemble_rig(
                "cuda", parents, artifacts,
                expected_revision=REVISION,
                expected_fingerprint=FINGERPRINT,
            ),
            "source_tree_fingerprint mismatch",
        )
        parents = [parent_sample("cuda", binary, seed, 2) for seed in range(1, 6)]
        parents[0]["source_revision"] = "f" * 40
        self.assert_rejected(
            lambda: MODULE.assemble_rig(
                "cuda", parents, artifacts,
                expected_revision=REVISION,
                expected_fingerprint=FINGERPRINT,
            ),
            "source_revision does not match",
        )

    def test_binary_and_architecture_mismatch_fail_closed(self) -> None:
        parents = [parent_sample("cuda", "a" * 64, seed, 2)
                   for seed in range(1, 6)]
        parents[4]["binary_sha256"] = "e" * 64
        self.assert_rejected(
            lambda: MODULE.assemble_rig(
                "cuda", parents, [rc_artifact("cuda", "sm_120", "c" * 64)],
                expected_revision=REVISION,
                expected_fingerprint=FINGERPRINT,
            ),
            "one exact binary_sha256",
        )
        parents = [parent_sample("cuda", "a" * 64, seed, 2)
                   for seed in range(1, 6)]
        self.assert_rejected(
            lambda: MODULE.assemble_rig(
                "cuda",
                parents,
                [rc_artifact("cuda", "sm_120", "c" * 64),
                 rc_artifact("cuda", "sm_121", "c" * 64, (4, 5, 6))],
                expected_revision=REVISION,
                expected_fingerprint=FINGERPRINT,
            ),
            "one exact architecture",
        )

    def test_provider_relabel_fails_closed(self) -> None:
        binary = "a" * 64
        parents = [parent_sample("cuda", binary, seed, 2) for seed in range(1, 6)]
        artifact = rc_artifact("cuda", "sm_120", "c" * 64)
        artifact["backend_requested"] = "metal"
        self.assert_rejected(
            lambda: MODULE.assemble_rig(
                "cuda", parents, [artifact],
                expected_revision=REVISION,
                expected_fingerprint=FINGERPRINT,
            ),
            "backend_requested is not cuda",
        )

    def test_cross_provider_seed_mismatch_fails_closed(self) -> None:
        with mock.patch.object(DERIVE, "REQUIRED_PROVIDERS", ("cuda", "metal")):
            cuda = build_rig("cuda", "sm_120")
            metal = build_rig("metal", "m4_class", seeds=(2, 3, 4, 5, 6))
            self.assert_rejected(
                lambda: MODULE.merge_rigs(
                    [cuda, metal],
                    expected_revision=REVISION,
                    expected_fingerprint=FINGERPRINT,
                    **POLICY_KW,
                ),
                "same parent seed set",
            )

    def test_cross_provider_nonce_mismatch_fails_closed(self) -> None:
        with mock.patch.object(DERIVE, "REQUIRED_PROVIDERS", ("cuda", "metal")):
            cuda = build_rig("cuda", "sm_120")
            metal = build_rig("metal", "m4_class", nonces=(2, 3, 4))
            self.assert_rejected(
                lambda: MODULE.merge_rigs(
                    [cuda, metal],
                    expected_revision=REVISION,
                    expected_fingerprint=FINGERPRINT,
                    **POLICY_KW,
                ),
                "same RC nonce set",
            )

    def test_cross_provider_digest_mismatch_fails_closed(self) -> None:
        with mock.patch.object(DERIVE, "REQUIRED_PROVIDERS", ("cuda", "metal")):
            cuda = build_rig("cuda", "sm_120")
            metal = build_rig("metal", "m4_class")
            metal["rc_episode_samples"][0]["frozen_headers"][0][
                "exact_replay_digest"
            ] = "f" * 64
            self.assert_rejected(
                lambda: MODULE.merge_rigs(
                    [cuda, metal],
                    expected_revision=REVISION,
                    expected_fingerprint=FINGERPRINT,
                    **POLICY_KW,
                ),
                "byte-identical RC digests",
            )

    def test_merge_requires_exact_policy_cohort(self) -> None:
        cuda = build_rig("cuda", "sm_120")
        self.assert_rejected(
            lambda: MODULE.merge_rigs(
                [], expected_revision=REVISION,
                expected_fingerprint=FINGERPRINT,
                **POLICY_KW,
            ),
            "one rig JSON object per required provider",
        )
        with mock.patch.object(DERIVE, "REQUIRED_PROVIDERS", ("cuda", "metal")):
            self.assert_rejected(
                lambda: MODULE.merge_rigs(
                    [cuda, copy.deepcopy(cuda)], expected_revision=REVISION,
                    expected_fingerprint=FINGERPRINT,
                    **POLICY_KW,
                ),
                "exactly one CUDA and one Metal",
            )


if __name__ == "__main__":
    unittest.main()
