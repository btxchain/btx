#!/usr/bin/env python3
"""Focused fail-closed tests for the Epoch-A activation evidence binder."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


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
        "implementation_fingerprint": "8" * 64,
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
        "artifact_sources": {
            "asert": {
                "source_revision": REVISION,
                "source_tree_fingerprint": FINGERPRINT,
                "binary_sha256": {
                    "parent_calibration": BINARY_HASHES["parent_calibration"],
                    "cuda_rc_harness": BINARY_HASHES["cuda_rc_harness"],
                },
            },
            "production_goldens": {
                "source_revision": REVISION,
                "source_tree_fingerprint": FINGERPRINT,
                "binary_sha256": {
                    "cuda_rc_harness": BINARY_HASHES["cuda_rc_harness"],
                    "metal_rc_harness": BINARY_HASHES["metal_rc_harness"],
                },
            },
            "lifecycle": {
                "source_revision": REVISION,
                "source_tree_fingerprint": FINGERPRINT,
                "binary_sha256": {
                    "btxd": BINARY_HASHES["btxd"],
                    "btx_cli": BINARY_HASHES["btx_cli"],
                },
            },
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
        block_hash = f"{len(samples) + 1:064x}"
        samples.append({
            "complete": True,
            "phase": phase,
            "height": 6 + len(samples),
            "complete_lifecycle_s": wall,
            "observer_solve_rpc_to_authenticated_tip_s": wall,
            "observer_measurement": {
                "clock": "monotonic_ns",
                "start_event": (
                    "before_concurrent_competing_sibling_rpc_submission"
                    if phase == "competing_tip"
                    else "before_generatetodescriptor_rpc"
                ),
                "stop_event": "both_nodes_exact_authenticated_tip",
                "elapsed_ns": wall * 1_000_000_000,
            },
            "authority_measured": True,
            "block_hash": block_hash,
            "rpc_correlated_end_to_end_sample": True,
            "correlation_block_hash": block_hash,
            "miner_authority": {
                "block_hash": block_hash,
                "block_height": 6 + len(samples),
                "solve_attempts": 3 if phase == "competing_tip" else 1,
                "solve_to_reseal_s": 60,
                "reseal_to_consume_s": 1,
                "solve_to_consume_s": 61,
                "provider": "cuda_rc_exact_test",
            },
            "authenticated_relay": {
                "block_hash": block_hash,
                "relay_s": 1,
            },
            "validator_exact_replay": {
                "block_hash": block_hash,
                "block_height": 6 + len(samples),
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
                "wall_s": 20,
            },
            "competing_block_hashes": (
                ["f" * 64] if phase == "competing_tip" else []
            ),
            "contention_reorg_tip_hash": (
                "e" * 64 if phase == "competing_tip" else None
            ),
            "contention_trace": ({
                "common_parent_hash": "a" * 64,
                "winning_branch_hash": "b" * 64,
                "winning_branch_parent_hash": "a" * 64,
                "losing_branch_hash": "f" * 64,
                "losing_branch_parent_hash": "a" * 64,
                "reorg_tip_hash": "e" * 64,
                "reorg_tip_parent_hash": "b" * 64,
                "measured_block_parent_hash": "e" * 64,
            } if phase == "competing_tip" else None),
            "contention_timing": ({
                "clock": "monotonic_ns",
                "start_mode": "concurrent_sibling_rpc_submission",
                "winning_sibling_local_accept_elapsed_ns": 20_000_000_000,
                "losing_sibling_local_accept_elapsed_ns": 21_000_000_000,
                "winning_extension_local_accept_elapsed_ns": 42_000_000_000,
                "reorg_convergence_elapsed_ns": 63_000_000_000,
                "measured_child_authenticated_elapsed_ns": 85_000_000_000,
            } if phase == "competing_tip" else None),
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
        "correlation": {
            "model": "exact_per_block_v2_concurrent_contention",
            "activation_eligible": True,
        },
        "ratification": {
            "campaign_authorizes_no_inversion_gate": False,
            "campaign_authorizes_gpu_lifecycle_gate": False,
            "installs_rc_asert_ratio": False,
            "operationally_ready_claim": False,
        },
        "component_definition": [
            "observer_solve_rpc_to_authenticated_tip_s",
            "solve_to_reseal_s", "reseal_to_consume_s",
            "authenticated_relay_s", "tip_validation_s",
        ],
        "complete_sample_count": 2,
        "core_sample_count_without_authority": 0,
        "incomplete_sample_count": 0,
        "attempts": 2,
        "samples": samples,
        "core_samples_without_authority": [],
        "incomplete_samples": [],
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

    def test_golden_validation_targets_manifest_bearing_seal_revision(self) -> None:
        corpus = self.root / "evidence"
        corpus.mkdir()
        comparison = corpus / "multi-gpu-digest-compare.json"
        comparison.write_text(json.dumps({
            "evidence_kind": "multi_gpu_profile1_exactreplay_golden_compare",
            "schema_version": 2,
            "tip_sha": REVISION,
            "source_tree_fingerprint": FINGERPRINT,
            "required_for_manifest": ["cuda", "metal"],
            "complete_multi_gpu_match": True,
            "cuda_metal_match": True,
            "allow_partial": False,
            "mismatches": [],
            "coverage_failures": [],
            "backends_succeeded": ["cuda", "metal"],
            "by_backend": {
                "cuda": {"harness_sha256": BINARY_HASHES["cuda_rc_harness"]},
                "metal": {"harness_sha256": BINARY_HASHES["metal_rc_harness"]},
            },
        }), encoding="utf-8")
        captured: list[object] = []
        verifier = SimpleNamespace(
            MANIFEST_RELATIVE=Path("manifest.data"),
            parse_manifest=lambda _: [SimpleNamespace(evidence_path="evidence")],
            seal_command=lambda args: captured.append(args) or 0,
        )
        seal_revision = "9" * 40
        with mock.patch.object(MODULE, "import_tool", return_value=verifier):
            MODULE.validate_golden(
                self.root,
                comparison,
                REVISION,
                FINGERPRINT,
                {
                    "cuda_rc_harness": BINARY_HASHES["cuda_rc_harness"],
                    "metal_rc_harness": BINARY_HASHES["metal_rc_harness"],
                },
                seal_revision=seal_revision,
            )
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].seal_revision, seal_revision)

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
            "class CMainParams {\n"
            "consensus.nMatMulV4Height = BTX_MATMUL_V47_EPOCH_A_HEIGHT;\n"
            "consensus.nMatMulBMX4CHeight = BTX_MATMUL_V47_EPOCH_A_HEIGHT;\n"
            "consensus.nMatMulRCHeight = BTX_MATMUL_V47_EPOCH_A_HEIGHT;\n"
            "consensus.nMatMulRCAsertRescaleNum = kRCEpochAAsertRescaleNum;\n"
            "consensus.nMatMulRCAsertRescaleDen = kRCEpochAAsertRescaleDen;\n"
            "};\nclass CTestNetParams {};\n",
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

    def test_disabled_source_cannot_satisfy_a_finite_activation_policy(self) -> None:
        (self.root / "src/kernel").mkdir(parents=True)
        (self.root / "src/consensus").mkdir(parents=True)
        (self.root / "src/kernel/chainparams.cpp").write_text(
            "static constexpr int64_t kRCEpochAAsertRescaleNum{4007014530};\n"
            "static constexpr int64_t kRCEpochAAsertRescaleDen{1};\n"
            "static constexpr int32_t BTX_MATMUL_V47_EPOCH_A_HEIGHT{\n"
            "    std::numeric_limits<int32_t>::max()};\n"
            "class CMainParams {\n"
            "consensus.nMatMulV4Height = BTX_MATMUL_V47_EPOCH_A_HEIGHT;\n"
            "consensus.nMatMulBMX4CHeight = BTX_MATMUL_V47_EPOCH_A_HEIGHT;\n"
            "consensus.nMatMulRCHeight = BTX_MATMUL_V47_EPOCH_A_HEIGHT;\n"
            "consensus.nMatMulRCAsertRescaleNum = 1;\n"
            "consensus.nMatMulRCAsertRescaleDen = 1;\n"
            "};\nclass CTestNetParams {};\n",
            encoding="utf-8",
        )
        (self.root / "src/consensus/params.h").write_text(
            "static constexpr bool BTX_MATMUL_NO_INVERSION_GATE_RATIFIED{true};\n"
            "static constexpr bool BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED{false};\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            MODULE.GateError, "source Epoch-A activation is disabled"
        ):
            MODULE.validate_source_tuple(self.root, policy())

    def test_source_tuple_denominator_wiring_is_mainnet_scoped(self) -> None:
        (self.root / "src/kernel").mkdir(parents=True)
        (self.root / "src/consensus").mkdir(parents=True)
        prefix = (
            "static constexpr int64_t kRCEpochAAsertRescaleNum{4007014530};\n"
            "static constexpr int64_t kRCEpochAAsertRescaleDen{1};\n"
            "static constexpr int32_t BTX_MATMUL_V47_EPOCH_A_HEIGHT{185'000};\n"
        )
        assignments = (
            "consensus.nMatMulV4Height = BTX_MATMUL_V47_EPOCH_A_HEIGHT;\n"
            "consensus.nMatMulBMX4CHeight = BTX_MATMUL_V47_EPOCH_A_HEIGHT;\n"
            "consensus.nMatMulRCHeight = BTX_MATMUL_V47_EPOCH_A_HEIGHT;\n"
            "consensus.nMatMulRCAsertRescaleNum = kRCEpochAAsertRescaleNum;\n"
        )
        (self.root / "src/consensus/params.h").write_text(
            "static constexpr bool BTX_MATMUL_NO_INVERSION_GATE_RATIFIED{true};\n"
            "static constexpr bool BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED{true};\n",
            encoding="utf-8",
        )
        for label, mainnet_tail in (
            ("missing", ""),
            ("commented", "// consensus.nMatMulRCAsertRescaleDen = "
                          "kRCEpochAAsertRescaleDen;\n"),
        ):
            with self.subTest(label=label):
                (self.root / "src/kernel/chainparams.cpp").write_text(
                    prefix + "class CMainParams {\n" + assignments + mainnet_tail
                    + "};\nclass CTestNetParams {\n"
                    + "consensus.nMatMulRCAsertRescaleDen = "
                    "kRCEpochAAsertRescaleDen;\n};\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(MODULE.GateError, "mainnet ASERT denominator"):
                    MODULE.validate_source_tuple(self.root, policy())

    def test_relevant_worktree_must_be_clean_before_imports(self) -> None:
        repo = self.root / "repo"
        source = repo / "src/example.cpp"
        source.parent.mkdir(parents=True)
        source.write_text("int clean = 1;\n", encoding="utf-8")
        for command in (
            ["git", "init", "-q"],
            ["git", "config", "user.name", "Gate Test"],
            ["git", "config", "user.email", "gate-test@users.noreply.github.com"],
            ["git", "add", "src/example.cpp"],
            ["git", "commit", "-q", "-m", "fixture"],
        ):
            subprocess.run(command, cwd=repo, check=True)
        MODULE.require_clean_relevant_worktree(repo)
        source.write_text("int dirty = 1;\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.GateError, "dirty"):
            MODULE.require_clean_relevant_worktree(repo)
        source.write_text("int clean = 1;\n", encoding="utf-8")
        (repo / "contrib/matmul-v4/untracked.py").parent.mkdir(parents=True)
        (repo / "contrib/matmul-v4/untracked.py").write_text(
            "# untracked\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(MODULE.GateError, "dirty"):
            MODULE.require_clean_relevant_worktree(repo)

    def test_artifact_source_chronology_accepts_a_to_b_to_c_only(self) -> None:
        repo = self.root / "chronology"
        (repo / "src/matmul").mkdir(parents=True)
        (repo / "src/kernel").mkdir(parents=True)
        (repo / "src/consensus").mkdir(parents=True)
        (repo / "contrib/matmul-v4").mkdir(parents=True)
        (repo / "CMakeLists.txt").write_text(
            "project(epoch_a_chronology)\n", encoding="utf-8"
        )
        (repo / "src/matmul/implementation.cpp").write_text(
            "int frozen_implementation = 1;\n", encoding="utf-8"
        )
        (repo / "src/kernel/chainparams.cpp").write_text(
            "[[maybe_unused]] static constexpr int64_t "
            "kRCEpochAAsertRescaleNum{1};\n"
            "[[maybe_unused]] static constexpr int64_t "
            "kRCEpochAAsertRescaleDen{1};\n"
            "static constexpr int32_t BTX_MATMUL_V47_EPOCH_A_HEIGHT{\n"
            "    std::numeric_limits<int32_t>::max()\n"
            "};\n",
            encoding="utf-8",
        )
        (repo / "src/consensus/params.h").write_text(
            "static constexpr bool "
            "BTX_MATMUL_NO_INVERSION_GATE_RATIFIED{false};\n"
            "static constexpr bool "
            "BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED{false};\n",
            encoding="utf-8",
        )
        (repo / "contrib/matmul-v4/evidence_source_identity.py").write_text(
            (REPO_ROOT / "contrib/matmul-v4/evidence_source_identity.py").read_text(
                encoding="utf-8"
            ),
            encoding="utf-8",
        )

        def run(*args: str) -> str:
            result = subprocess.run(
                ["git", *args], cwd=repo, capture_output=True, text=True,
                check=True,
            )
            return result.stdout.strip()

        run("init", "-q")
        run("config", "user.name", "Gate Test")
        run("config", "user.email", "gate-test@users.noreply.github.com")
        run("add", ".")
        run("commit", "-q", "-m", "A: freeze executable implementation")
        revision_a = run("rev-parse", "HEAD")
        branch = run("rev-parse", "--abbrev-ref", "HEAD")

        identity = MODULE.import_tool(
            repo / "contrib/matmul-v4/evidence_source_identity.py",
            "epoch_a_gate_chronology_fixture_identity",
        )
        fingerprint = identity.tree_fingerprint(repo, revision_a)
        shutil.rmtree(repo / "contrib/matmul-v4/__pycache__", ignore_errors=True)

        manifest = repo / "src/matmul/matmul_v4_rc_production_golden_manifest.data"
        manifest.write_text("sealed manifest from A\n", encoding="utf-8")
        (repo / "doc/evidence/golden").mkdir(parents=True)
        (repo / "doc/evidence/golden/result.json").write_text(
            "{}\n", encoding="utf-8"
        )
        run(
            "add",
            "src/matmul/matmul_v4_rc_production_golden_manifest.data",
            "doc/evidence/golden/result.json",
        )
        run("commit", "-q", "-m", "B: seal golden evidence")

        (repo / "doc/evidence/lifecycle").mkdir(parents=True)
        (repo / "doc/evidence/lifecycle/result.json").write_text(
            "{}\n", encoding="utf-8"
        )
        run("add", "doc/evidence/lifecycle/result.json")
        run("commit", "-q", "-m", "C: record manifest-bearing lifecycle")
        revision_c = run("rev-parse", "HEAD")
        self.assertEqual(identity.tree_fingerprint(repo, revision_c), fingerprint)
        frozen_implementation = MODULE.implementation_fingerprint(
            repo, revision_c
        )

        reviewed = policy()
        reviewed["source_revision"] = revision_c
        reviewed["source_tree_fingerprint"] = fingerprint
        reviewed["implementation_fingerprint"] = frozen_implementation
        for role, revision in (
            ("asert", revision_a),
            ("production_goldens", revision_a),
            ("lifecycle", revision_c),
        ):
            reviewed["artifact_sources"][role]["source_revision"] = revision
            reviewed["artifact_sources"][role][
                "source_tree_fingerprint"
            ] = fingerprint

        release = MODULE.validate_source_identity(repo, reviewed)
        self.assertEqual(
            MODULE.validate_implementation_identity(repo, reviewed, revision_c),
            frozen_implementation,
        )
        sources, binaries = MODULE.validate_artifact_sources(
            repo, reviewed, revision_c, frozen_implementation
        )
        self.assertEqual(sources["production_goldens"][0], revision_a)
        self.assertEqual(sources["lifecycle"][0], revision_c)
        self.assertEqual(set(binaries), MODULE.EXPECTED_ARTIFACT_SOURCE_KEYS)

        # A revision on a side branch is not acceptable merely because it
        # resolves and has a valid fingerprint of its own.
        run("switch", "-q", "-c", "unreachable-artifact", revision_a)
        (repo / "src/matmul/implementation.cpp").write_text(
            "int divergent_implementation = 2;\n", encoding="utf-8"
        )
        run("add", "src/matmul/implementation.cpp")
        run("commit", "-q", "-m", "unreachable implementation")
        unreachable = run("rev-parse", "HEAD")
        unreachable_fingerprint = identity.tree_fingerprint(repo, unreachable)
        run("switch", "-q", branch)
        rejected = json.loads(json.dumps(reviewed))
        rejected["artifact_sources"]["asert"]["source_revision"] = unreachable
        rejected["artifact_sources"]["asert"][
            "source_tree_fingerprint"
        ] = unreachable_fingerprint
        with self.assertRaisesRegex(MODULE.GateError, "reviewed chronology"):
            MODULE.validate_artifact_sources(
                repo, rejected, revision_c, frozen_implementation
            )

        distinct = json.loads(json.dumps(reviewed))
        distinct["artifact_sources"]["production_goldens"][
            "binary_sha256"
        ]["cuda_rc_harness"] = "f" * 64
        _, distinct_binaries = MODULE.validate_artifact_sources(
            repo, distinct, revision_c, frozen_implementation
        )
        self.assertNotEqual(
            distinct_binaries["asert"]["cuda_rc_harness"],
            distinct_binaries["production_goldens"]["cuda_rc_harness"],
        )

        # D is the honest release-final change: only the normalized height,
        # coefficient, and ratification literals change after lifecycle.
        (repo / "src/kernel/chainparams.cpp").write_text(
            "static constexpr int64_t kRCEpochAAsertRescaleNum{4'007'014'530};\n"
            "static constexpr int64_t kRCEpochAAsertRescaleDen{1};\n"
            "static constexpr int32_t BTX_MATMUL_V47_EPOCH_A_HEIGHT{185'000};\n",
            encoding="utf-8",
        )
        (repo / "src/consensus/params.h").write_text(
            "static constexpr bool "
            "BTX_MATMUL_NO_INVERSION_GATE_RATIFIED{true};\n"
            "static constexpr bool "
            "BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED{true};\n",
            encoding="utf-8",
        )
        run("add", "src/kernel/chainparams.cpp", "src/consensus/params.h")
        run("commit", "-q", "-m", "D: authorize activation tuple")
        revision_d = run("rev-parse", "HEAD")
        fingerprint_d = identity.tree_fingerprint(repo, revision_d)
        self.assertNotEqual(fingerprint_d, fingerprint)
        self.assertEqual(
            MODULE.implementation_fingerprint(repo, revision_d),
            frozen_implementation,
        )
        release_ready = json.loads(json.dumps(reviewed))
        release_ready["source_revision"] = revision_d
        release_ready["source_tree_fingerprint"] = fingerprint_d
        release_ready["implementation_fingerprint"] = frozen_implementation
        MODULE.validate_artifact_sources(
            repo, release_ready, revision_d, frozen_implementation
        )

        # Reachability alone is insufficient: any other executable-source
        # change invalidates the earlier artifacts even though A remains an
        # ancestor.
        (repo / "src/matmul/implementation.cpp").write_text(
            "int changed_after_evidence = 3;\n", encoding="utf-8"
        )
        run("add", "src/matmul/implementation.cpp")
        run("commit", "-q", "-m", "E: change executable implementation")
        revision_e = run("rev-parse", "HEAD")
        implementation_e = MODULE.implementation_fingerprint(repo, revision_e)
        unrelated_release = json.loads(json.dumps(release_ready))
        unrelated_release["source_revision"] = revision_e
        unrelated_release["source_tree_fingerprint"] = identity.tree_fingerprint(
            repo, revision_e
        )
        with self.assertRaisesRegex(
            MODULE.GateError, "implementation_fingerprint does not match"
        ):
            MODULE.validate_implementation_identity(
                repo, unrelated_release, revision_e
            )
        stale = json.loads(json.dumps(reviewed))
        stale["artifact_sources"]["lifecycle"]["source_revision"] = revision_e
        stale["artifact_sources"]["lifecycle"][
            "source_tree_fingerprint"
        ] = identity.tree_fingerprint(repo, revision_e)
        with self.assertRaisesRegex(MODULE.GateError, "implementation differs"):
            MODULE.validate_artifact_sources(
                repo, stale, revision_e, implementation_e
            )

    def test_coefficient_is_signed_consensus_bounded(self) -> None:
        self.assertEqual(MODULE.exact_int(MODULE.INT64_MAX, "coefficient"), MODULE.INT64_MAX)
        with self.assertRaisesRegex(MODULE.GateError, "integer"):
            MODULE.exact_int(MODULE.INT64_MAX + 1, "coefficient")

    def test_role_specific_binary_paths_are_hashed_independently(self) -> None:
        binaries: dict[str, Path] = {}
        for index, name in enumerate(sorted(MODULE.EXPECTED_BINARY_KEYS), start=1):
            path = self.root / name
            path.write_bytes(f"role-specific-binary-{index}\n".encode())
            binaries[name] = path
        expected = {
            role: {
                local_name: MODULE.sha256_file(
                    binaries[MODULE.ARTIFACT_BINARY_ARGUMENTS[role][local_name]]
                )
                for local_name in MODULE.ARTIFACT_BINARY_KEYS[role]
            }
            for role in MODULE.EXPECTED_ARTIFACT_SOURCE_KEYS
        }
        self.assertEqual(MODULE.validate_binaries(expected, binaries), expected)
        mismatched = dict(binaries)
        mismatched["golden_cuda_rc_harness"] = binaries[
            "asert_cuda_rc_harness"
        ]
        with self.assertRaisesRegex(MODULE.GateError, "binary SHA256 mismatch"):
            MODULE.validate_binaries(expected, mismatched)

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
        self.assertEqual(
            lifecycle()["samples"][1]["miner_authority"]["solve_attempts"], 3
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
        changed["samples"][1]["observer_solve_rpc_to_authenticated_tip_s"] = 91
        changed["samples"][1]["observer_measurement"]["elapsed_ns"] = 91_000_000_000
        changed["samples"][1]["contention_timing"][
            "measured_child_authenticated_elapsed_ns"
        ] = 91_000_000_000
        changed["complete_lifecycle_summary_s"].update({
            "p95": 91, "p99": 91, "max": 91, "mean": 85.5,
        })
        self.assert_lifecycle_rejected(changed, "p99 exceeds")
        changed = lifecycle()
        changed["samples"][1]["phase"] = "steady_mine_relay"
        self.assert_lifecycle_rejected(changed, "required phases")

    def test_lifecycle_rejects_uncorrelated_current_campaign_schema(self) -> None:
        changed = lifecycle()
        changed["schema_version"] = 2
        changed["correlation"] = {
            "model": "independent_latest_components",
            "activation_eligible": False,
        }
        for sample in changed["samples"]:
            sample["rpc_correlated_end_to_end_sample"] = False
            sample.pop("correlation_block_hash")
        self.assert_lifecycle_rejected(changed, "lacks exact per-block correlation")

    def test_lifecycle_incomplete_accounting_is_canonical_and_reconciled(self) -> None:
        changed = lifecycle()
        changed["incomplete_sample_count"] = -1
        self.assert_lifecycle_rejected(changed, "incomplete_sample_count must be an integer")
        changed = lifecycle()
        changed["incomplete_samples"] = [{
            "attempt": 3, "phase": "steady_mine_relay", "reason": "failed"
        }]
        self.assert_lifecycle_rejected(changed, "incomplete sample count mismatch")
        changed = lifecycle()
        changed["attempts"] = 3
        self.assert_lifecycle_rejected(changed, "attempts do not reconcile")
        changed = lifecycle()
        changed["core_sample_count_without_authority"] = 1
        changed["core_samples_without_authority"] = [{
            "attempt": 3,
            "phase": "steady_mine_relay",
            "reason": "production authority unavailable",
        }]
        changed["attempts"] = 3
        self.assert_lifecycle_rejected(changed, "must not contain core-only samples")

    def test_lifecycle_stage_hashes_must_match_exact_block(self) -> None:
        changed = lifecycle()
        changed["samples"][0]["miner_authority"]["block_hash"] = "f" * 64
        self.assert_lifecycle_rejected(changed, "authority block mismatch")
        changed = lifecycle()
        changed["samples"][0]["authenticated_relay"]["block_hash"] = "f" * 64
        self.assert_lifecycle_rejected(changed, "relay block mismatch")
        changed = lifecycle()
        changed["samples"][0]["validator_exact_replay"]["block_hash"] = "f" * 64
        self.assert_lifecycle_rejected(changed, "validation block mismatch")

    def test_lifecycle_multi_attempt_authority_and_observer_fail_closed(self) -> None:
        changed = lifecycle()
        changed["samples"][1]["miner_authority"].pop("solve_attempts")
        self.assert_lifecycle_rejected(changed, "authority schema mismatch")
        changed = lifecycle()
        changed["samples"][1]["miner_authority"]["solve_attempts"] = 0
        self.assert_lifecycle_rejected(changed, "solve_attempts must be an integer")
        changed = lifecycle()
        changed["samples"][1]["miner_authority"]["solve_to_consume_s"] = 62
        self.assert_lifecycle_rejected(changed, "authority timings do not reconcile")
        changed = lifecycle()
        changed["samples"][0]["observer_measurement"]["elapsed_ns"] += 1_000_000_000
        self.assert_lifecycle_rejected(changed, "observer elapsed_ns mismatch")
        changed = lifecycle()
        sample = changed["samples"][0]
        summed = (
            sample["miner_authority"]["solve_to_consume_s"]
            + sample["authenticated_relay"]["relay_s"]
            + sample["validator_exact_replay"]["wall_s"]
        )
        sample["complete_lifecycle_s"] = summed
        sample["observer_solve_rpc_to_authenticated_tip_s"] = summed
        sample["observer_measurement"]["elapsed_ns"] = int(summed * 1_000_000_000)
        changed["complete_lifecycle_summary_s"].update({
            "min": summed, "p50": summed, "mean": (summed + 85) / 2,
        })
        self.assert_lifecycle_rejected(changed, "substitutes summed stages")

    def test_lifecycle_missing_cancelled_and_fake_contention_fail_closed(self) -> None:
        changed = lifecycle()
        changed["samples"][0].pop("authenticated_relay")
        self.assert_lifecycle_rejected(changed, "relay block mismatch")
        changed = lifecycle()
        changed["samples"][0]["validator_exact_replay"]["outcome"] = "cancelled"
        self.assert_lifecycle_rejected(changed, "validation.outcome mismatch")
        changed = lifecycle()
        changed["samples"][1]["competing_block_hashes"] = []
        self.assert_lifecycle_rejected(changed, "lacks a distinct competing block")
        changed = lifecycle()
        changed["samples"][1]["contention_reorg_tip_hash"] = None
        self.assert_lifecycle_rejected(changed, "contention reorg tip")
        changed = lifecycle()
        changed["samples"][1]["contention_reorg_tip_hash"] = changed["samples"][1]["block_hash"]
        self.assert_lifecycle_rejected(changed, "reorg tip is not distinct")
        changed = lifecycle()
        changed["samples"][1]["contention_trace"]["reorg_tip_parent_hash"] = "c" * 64
        self.assert_lifecycle_rejected(changed, "contention ancestry mismatch")
        changed = lifecycle()
        changed["samples"][1]["observer_measurement"]["start_event"] = (
            "before_generatetodescriptor_rpc"
        )
        self.assert_lifecycle_rejected(changed, "observer measurement schema")
        changed = lifecycle()
        changed["samples"][1]["contention_timing"] = None
        self.assert_lifecycle_rejected(changed, "contention timing schema")
        changed = lifecycle()
        changed["samples"][1]["contention_timing"][
            "winning_extension_local_accept_elapsed_ns"
        ] = 20_000_000_000
        self.assert_lifecycle_rejected(changed, "checkpoints are not ordered")

    def test_measurement_artifact_cannot_self_ratify(self) -> None:
        changed = lifecycle()
        changed["ratification"]["campaign_authorizes_gpu_lifecycle_gate"] = True
        self.assert_lifecycle_rejected(changed, "must not self-authorize")


if __name__ == "__main__":
    unittest.main()
