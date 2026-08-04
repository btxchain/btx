#!/usr/bin/env python3
"""Focused tests for MatMul lifecycle and trusted-mirror command-line tools."""

import copy
import importlib.util
import copy
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
REHEARSAL = REPO_ROOT / "contrib/matmul-v4/two-node-trusted-mirror-rehearsal.py"
LIFECYCLE = REPO_ROOT / "contrib/matmul-v4/measure-cuda-lifecycle-campaign.py"


def load_rehearsal():
    spec = importlib.util.spec_from_file_location("trusted_mirror_rehearsal", REHEARSAL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_lifecycle():
    spec = importlib.util.spec_from_file_location("cuda_lifecycle", LIFECYCLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TrustedMirrorToolsTest(unittest.TestCase):
    def test_rehearsal_help_requires_no_deployment_environment(self):
        env = dict(os.environ)
        for name in (
            "ARCHIVE_HOST",
            "ARCHIVE_USER",
            "ARCHIVE_BTXD",
            "ARCHIVE_CLI",
            "ARCHIVE_SIGNER_WIF_FILE",
            "MIRROR_BTXD",
            "MIRROR_CLI",
            "SIGNER_WIF_FILE",
            "SIGNER_PUB_FILE",
            "BTX_SOURCE_REVISION",
            "ARCHIVE_BTXD_SHA256",
            "ARCHIVE_CLI_SHA256",
            "MIRROR_BTXD_SHA256",
            "MIRROR_CLI_SHA256",
            "BTX_TRUSTED_MIRROR_ARCHIVE_LOCAL",
            "BTX_TRUSTED_MIRROR_ARCHIVE_BACKEND",
            "BTX_TRUSTED_MIRROR_STRICT_PROOF_MODE",
        ):
            env.pop(name, None)
        result = subprocess.run(
            [sys.executable, str(REHEARSAL), "--help"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--archive-host", result.stdout)
        self.assertIn("--archive-local", result.stdout)
        self.assertIn("--archive-backend", result.stdout)
        self.assertIn("--strict-proof-mode", result.stdout)
        self.assertIn("--mirror-cli", result.stdout)

    def test_lifecycle_uses_semantic_btx_cli_option(self):
        result = subprocess.run(
            [sys.executable, str(LIFECYCLE), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--btx-cli", result.stdout)
        self.assertNotIn("--/", result.stdout)

    def test_lifecycle_execution_policy_matches_mode(self):
        module = load_lifecycle()
        self.assertEqual(module.execution_policy_for_mode("toy"), "auto-fallback")
        self.assertEqual(
            module.execution_policy_for_mode("production"), "strict-device"
        )
        with self.assertRaisesRegex(ValueError, "unsupported lifecycle mode"):
            module.execution_policy_for_mode("unknown")

    def test_lifecycle_public_errors_omit_private_exception_detail(self):
        module = load_lifecycle()
        private_detail = "/Users/" + "fixture-operator/private-build/bin/btxd"
        public = module.public_exception_name(RuntimeError(private_detail))
        self.assertEqual(public, "RuntimeError")
        self.assertNotIn("fixture-operator", public)
        self.assertNotIn("/Users/", public)

    def test_lifecycle_exact_block_records_cannot_mix_or_cancel(self):
        module = load_lifecycle()
        block_hash = "1" * 64
        authority = {
            "block_hash": block_hash,
            "block_height": 6,
            "solve_attempts": 3,
            "solve_to_reseal_s": 40.0,
            "reseal_to_consume_s": 1.0,
            "solve_to_consume_s": 41.0,
            "provider": "cuda_rc_exact_test",
        }
        relay = {"block_hash": block_hash, "relay_s": 0.5}
        validation = {
            "block_hash": block_hash,
            "block_height": 6,
            "outcome": "valid",
            "execution_policy": "strict-device",
            "require_device": True,
            "provider": "cuda_rc_exact_test",
            "fully_accelerated": True,
            "device_gemm_calls": 136,
            "device_gemm_macs": 1,
            "device_xof_fallbacks": 0,
            "host_xof_calls": 0,
            "cpu_gemm_calls": 0,
            "cpu_gemm_fallbacks": 0,
            "wall_s": 20.0,
        }
        miner = {"backend_runtime": {"rc_accelerator_scheduler": {
            "winner_reseal_authority": {"recent_consumed": [authority]},
        }}}
        validator = {"backend_runtime": {
            "rc_accelerator_scheduler": {
                "recent_authenticated_relays": [relay],
            },
            "rc_exact_replay": {"recent_validations": [validation]},
        }}
        actual = module.extract_exact_block_lifecycle(
            miner, validator, block_hash=block_hash,
            block_height=6, observer_wall_s=50.0,
            observer_elapsed_ns=50_000_000_000,
        )
        self.assertTrue(actual["rpc_correlated_end_to_end_sample"])
        self.assertEqual(actual["correlation_block_hash"], block_hash)
        self.assertEqual(actual["miner_authority"]["solve_attempts"], 3)
        core = module.extract_exact_block_core_lifecycle(
            validator, block_hash=block_hash, block_height=6,
            observer_wall_s=50.0,
            observer_elapsed_ns=50_000_000_000,
        )
        self.assertTrue(core["core_complete_without_authority"])
        self.assertFalse(core["authority_measured"])

        stale = copy.deepcopy(validator)
        stale_relay = copy.deepcopy(relay)
        stale_relay["block_hash"] = "9" * 64
        stale["backend_runtime"]["rc_accelerator_scheduler"][
            "recent_authenticated_relays"
        ].insert(0, stale_relay)
        selected = module.extract_exact_block_lifecycle(
            miner, stale, block_hash=block_hash,
            block_height=6, observer_wall_s=50.0,
            observer_elapsed_ns=50_000_000_000,
        )
        self.assertEqual(
            selected["authenticated_relay"]["block_hash"], block_hash
        )

        duplicate = copy.deepcopy(validator)
        duplicate["backend_runtime"]["rc_accelerator_scheduler"][
            "recent_authenticated_relays"
        ].append(copy.deepcopy(relay))
        with self.assertRaisesRegex(RuntimeError, "2 records for exact block hash"):
            module.extract_exact_block_lifecycle(
                miner, duplicate, block_hash=block_hash,
                block_height=6, observer_wall_s=50.0,
                observer_elapsed_ns=50_000_000_000,
            )

        mixed = copy.deepcopy(validator)
        mixed["backend_runtime"]["rc_accelerator_scheduler"][
            "recent_authenticated_relays"
        ][0]["block_hash"] = "2" * 64
        with self.assertRaisesRegex(RuntimeError, "0 records for exact block hash"):
            module.extract_exact_block_lifecycle(
                miner, mixed, block_hash=block_hash,
                block_height=6, observer_wall_s=50.0,
                observer_elapsed_ns=50_000_000_000,
            )

        missing_attempts = copy.deepcopy(miner)
        missing_attempts["backend_runtime"]["rc_accelerator_scheduler"][
            "winner_reseal_authority"
        ]["recent_consumed"][0].pop("solve_attempts")
        with self.assertRaisesRegex(RuntimeError, "solve_attempts"):
            module.extract_exact_block_lifecycle(
                missing_attempts, validator, block_hash=block_hash,
                block_height=6, observer_wall_s=50.0,
                observer_elapsed_ns=50_000_000_000,
            )

        cancelled = copy.deepcopy(validator)
        cancelled["backend_runtime"]["rc_exact_replay"][
            "recent_validations"
        ][0]["outcome"] = "cancelled"
        with self.assertRaisesRegex(RuntimeError, "outcome mismatch"):
            module.extract_exact_block_lifecycle(
                miner, cancelled, block_hash=block_hash,
                block_height=6, observer_wall_s=50.0,
                observer_elapsed_ns=50_000_000_000,
            )

        missing = copy.deepcopy(miner)
        missing["backend_runtime"]["rc_accelerator_scheduler"][
            "winner_reseal_authority"
        ]["recent_consumed"] = []
        with self.assertRaisesRegex(RuntimeError, "0 records for exact block hash"):
            module.extract_exact_block_lifecycle(
                missing, validator, block_hash=block_hash,
                block_height=6, observer_wall_s=50.0,
                observer_elapsed_ns=50_000_000_000,
            )

    def test_lifecycle_exports_both_runtime_build_and_validation_facts(self):
        module = load_lifecycle()
        revision = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        fingerprint = module.EVIDENCE_IDENTITY.tree_fingerprint(REPO_ROOT, revision)
        canary = {
            "outcome": "passed",
            "attempted": True,
            "passed": True,
            "manifest_has_reviewed_goldens": True,
            "build_provenance_matches": True,
            "build_source_dirty": False,
            "build_source_revision": revision,
            "build_source_tree_fingerprint": fingerprint,
            "exact_manifest_match": True,
            "provider": "cuda_rc_exact_test",
            "provider_family": "cuda",
            "device_architecture": "sm_120",
            "epoch_activation_height": 6,
            "epoch_profile": 1,
            "epoch_matmul_dimension": 4096,
            "device_macs": 1,
            "device_xof_fallbacks": 0,
            "host_xof_calls": 0,
            "cpu_fallbacks": 0,
            "reason": "passed",
        }
        response = {
            "backend_runtime": {
                "rc_exact_replay": {
                    "resolved_provider": "cuda_rc_exact_test",
                    "production_canary": canary,
                    "last_validation": {
                        "available": True,
                        "outcome": "valid",
                        "execution_policy": "strict-device",
                        "require_device": True,
                        "provider": "cuda_rc_exact_test",
                        "fully_accelerated": True,
                        "cpu_gemm_calls": 0,
                        "cpu_gemm_fallbacks": 0,
                    },
                    "provider_health": {
                        "quarantined": False,
                        "validator_readiness_lost": False,
                    },
                }
            }
        }
        evidence = module.extract_public_runtime_evidence(
            response, revision=revision, fingerprint=fingerprint,
            label="validator",
        )
        self.assertEqual(evidence["resolved_provider"], "cuda_rc_exact_test")
        self.assertTrue(evidence["production_canary"]["exact_manifest_match"])
        self.assertEqual(evidence["last_validation"]["execution_policy"], "strict-device")

    def test_rehearsal_parses_explicit_local_deployment_arguments(self):
        module = load_rehearsal()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = {}
            for name in (
                "archive-btxd", "archive-cli", "mirror-btxd", "mirror-cli",
                "signer-wif", "signer-pub",
            ):
                paths[name] = root / name
                paths[name].write_text("test\n", encoding="utf-8")
            paths["signer-wif"].chmod(0o600)
            revision = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            binary_hash = module.EVIDENCE_IDENTITY.sha256_file(paths["mirror-btxd"])
            args = module.validate_args(
                module.build_arg_parser(),
                module.build_arg_parser().parse_args(
                    [
                        "--archive-local",
                        "--archive-btxd",
                        str(paths["archive-btxd"]),
                        "--archive-cli",
                        str(paths["archive-cli"]),
                        "--archive-backend",
                        "metal",
                        "--strict-proof-mode",
                        "winner-reseal-authority",
                        "--mirror-btxd",
                        str(paths["mirror-btxd"]),
                        "--mirror-cli",
                        str(paths["mirror-cli"]),
                        "--signer-wif-file",
                        str(paths["signer-wif"]),
                        "--signer-pub-file",
                        str(paths["signer-pub"]),
                        "--runtime-root",
                        str(root),
                        "--source-revision",
                        revision,
                        "--archive-btxd-sha256",
                        binary_hash,
                        "--archive-cli-sha256",
                        binary_hash,
                        "--mirror-btxd-sha256",
                        binary_hash,
                        "--mirror-cli-sha256",
                        binary_hash,
                    ]
                ),
            )
        self.assertIsNone(args.archive_host)
        self.assertTrue(args.archive_local)
        self.assertEqual(args.archive_backend, "metal")
        self.assertEqual(args.archive_cli.name, "archive-cli")
        self.assertEqual(args.mirror_cli.name, "mirror-cli")
        self.assertEqual(args.source_revision, revision)

    def test_rehearsal_remote_mode_requires_archive_owned_signer(self):
        module = load_rehearsal()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mirror_btxd = root / "mirror-btxd"
            mirror_cli = root / "mirror-cli"
            signer_pub = root / "signer-pub"
            for path in (mirror_btxd, mirror_cli, signer_pub):
                path.write_text("test\n", encoding="utf-8")
            revision = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            binary_hash = module.EVIDENCE_IDENTITY.sha256_file(mirror_btxd)
            common = [
                "--archive-host", "gpu-archive.example.invalid",
                "--archive-user", "operator",
                "--archive-btxd", "/opt/btx/bin/btxd",
                "--archive-cli", "/opt/btx/bin/btx-cli",
                "--archive-backend", "metal",
                "--strict-proof-mode", "winner-reseal-authority",
                "--mirror-btxd", str(mirror_btxd),
                "--mirror-cli", str(mirror_cli),
                "--signer-pub-file", str(signer_pub),
                "--runtime-root", str(root),
                "--source-revision", revision,
                "--archive-btxd-sha256", "a" * 64,
                "--archive-cli-sha256", "b" * 64,
                "--mirror-btxd-sha256", binary_hash,
                "--mirror-cli-sha256", binary_hash,
            ]
            parser = module.build_arg_parser()
            args = module.validate_args(
                parser,
                parser.parse_args(
                    [*common, "--archive-signer-wif-file", "/secure/signer.wif"]
                ),
            )
            self.assertEqual(args.archive_signer_wif_file, "/secure/signer.wif")

            local_wif = root / "signer.wif"
            local_wif.write_text("private\n", encoding="utf-8")
            parser = module.build_arg_parser()
            with self.assertRaises(SystemExit):
                module.validate_args(
                    parser,
                    parser.parse_args(
                        [*common, "--archive-signer-wif-file", "/secure/signer.wif",
                         "--signer-wif-file", str(local_wif)]
                    ),
                )

    def test_extracts_nested_strict_replay_evidence(self):
        module = load_rehearsal()
        rc = {
            "production_eligible": True,
            "startup_canary_passed": True,
            "activation_ready": True,
            "resolved_provider": "cuda_rc_exact_fused_extract",
            "production_canary": {
                "passed": True,
                "exact_manifest_match": True,
                "device_macs": 1,
                "cpu_fallbacks": 0,
                "provider": "cuda_rc_exact_fused_extract",
                "provider_family": "cuda",
                "device_architecture": "sm_120",
            },
            "last_validation": {
                "available": True,
                "require_device": True,
                "fully_accelerated": True,
                "cpu_gemm_calls": 0,
                "cpu_gemm_fallbacks": 0,
                "provider": "cuda_rc_exact_fused_extract",
            },
        }
        actual, canary, validation = module.extract_strict_replay_evidence(
            {"backend_runtime": {"rc_exact_replay": rc}}
        )
        self.assertIs(actual, rc)
        self.assertTrue(canary["passed"])
        self.assertEqual(validation["cpu_gemm_fallbacks"], 0)

    def test_strict_replay_allows_unavailable_last_validation_for_miner(self):
        module = load_rehearsal()
        rc = {
            "production_eligible": True,
            "startup_canary_passed": True,
            "activation_ready": True,
            "resolved_provider": "metal_rc_exact",
            "production_canary": {
                "passed": True,
                "exact_manifest_match": True,
                "device_macs": 1,
                "cpu_fallbacks": 0,
                "provider": "metal_rc_exact",
                "provider_family": "metal",
                "device_architecture": "m4_class",
            },
            "last_validation": {"available": False},
        }
        _, canary, validation = module.extract_strict_replay_evidence(
            {"backend_runtime": {"rc_exact_replay": rc}},
            expected_provider_family="metal",
        )
        self.assertFalse(validation["available"])
        self.assertEqual(
            module.derive_archive_host_class(canary, "metal"),
            "metal_m4_class_exactreplay_archive",
        )
        with self.assertRaisesRegex(RuntimeError, "provider family"):
            module.extract_strict_replay_evidence(
                {"backend_runtime": {"rc_exact_replay": rc}},
                expected_provider_family="cuda",
            )

    def test_winner_reseal_authority_proof_is_fresh_and_header_bound(self):
        module = load_rehearsal()

        def mining_info(*, candidate, reseal, published, consumed, provider):
            return {
                "backend_runtime": {
                    "rc_accelerator_scheduler": {
                        "release_invariant_violations": 0,
                        "lanes": {
                            "candidate_mining": {
                                "completions": candidate,
                                "last_execution_s": 21.0 if candidate else 0.0,
                            },
                            "winner_reseal": {
                                "completions": reseal,
                                "last_execution_s": 21.0 if reseal else 0.0,
                            },
                        },
                        "winner_reseal_authority": {
                            "published": published,
                            "consumed": consumed,
                            "rejected_not_block_target": 0,
                            "rejected_not_production_ready": 0,
                            "invalidated_before_consume": 0,
                            "expired": 0,
                            "evicted": 0,
                            "misses": 0,
                            "entries": 0,
                            "last_provider": provider,
                            "consumed_by_provider": (
                                {provider: consumed} if provider else {}
                            ),
                        },
                    }
                }
            }

        baseline = mining_info(
            candidate=0, reseal=0, published=0, consumed=0, provider=""
        )
        final = mining_info(
            candidate=5, reseal=3, published=3, consumed=3,
            provider="metal_rc_exact",
        )
        proof = module.validate_archive_strict_proof(
            mode="winner-reseal-authority",
            baseline_mining_info=baseline,
            final_mining_info=final,
            expected_provider="metal_rc_exact",
        )
        self.assertEqual(proof["authority_consumed"], 3)
        self.assertEqual(proof["winner_reseal_completions"], 3)

        cases = []
        too_few = copy.deepcopy(final)
        too_few["backend_runtime"]["rc_accelerator_scheduler"]["winner_reseal_authority"]["consumed"] = 2
        cases.append(("expected exactly 3", too_few))
        too_many_reseals = copy.deepcopy(final)
        too_many_reseals["backend_runtime"]["rc_accelerator_scheduler"]["lanes"]["winner_reseal"]["completions"] = 4
        cases.append(("expected exactly 3", too_many_reseals))
        residual = copy.deepcopy(final)
        residual["backend_runtime"]["rc_accelerator_scheduler"]["winner_reseal_authority"]["entries"] = 1
        cases.append(("store must be empty", residual))
        wrong_provider = copy.deepcopy(final)
        wrong_provider["backend_runtime"]["rc_accelerator_scheduler"]["winner_reseal_authority"]["last_provider"] = "cuda_rc_exact_fused_extract"
        cases.append(("provider differs", wrong_provider))
        mixed_provider = copy.deepcopy(final)
        mixed_authority = mixed_provider["backend_runtime"]["rc_accelerator_scheduler"]["winner_reseal_authority"]
        mixed_authority["consumed_by_provider"] = {
            "metal_rc_exact": 2,
            "cuda_rc_exact_fused_extract": 1,
        }
        cases.append(("do not bind all three", mixed_provider))
        invariant = copy.deepcopy(final)
        invariant["backend_runtime"]["rc_accelerator_scheduler"]["release_invariant_violations"] = 1
        cases.append(("invariant", invariant))
        missed = copy.deepcopy(final)
        missed["backend_runtime"]["rc_accelerator_scheduler"]["winner_reseal_authority"]["misses"] = 1
        cases.append(("misses changed", missed))
        invalidated = copy.deepcopy(final)
        invalidated["backend_runtime"]["rc_accelerator_scheduler"]["winner_reseal_authority"]["invalidated_before_consume"] = 1
        cases.append(("invalidated_before_consume changed", invalidated))
        for error, changed in cases:
            with self.subTest(error=error):
                with self.assertRaisesRegex(RuntimeError, error):
                    module.validate_archive_strict_proof(
                        mode="winner-reseal-authority",
                        baseline_mining_info=baseline,
                        final_mining_info=changed,
                        expected_provider="metal_rc_exact",
                    )

    def test_self_mining_runner_rejects_receiving_validation_mode(self):
        module = load_rehearsal()
        with self.assertRaisesRegex(RuntimeError, "supports only"):
            module.validate_archive_strict_proof(
                mode="receiving-validation",
                baseline_mining_info={},
                final_mining_info={},
                expected_provider="metal_rc_exact",
            )

    def test_rehearsal_requires_proven_archive_mirror_trust_boundary(self):
        module = load_rehearsal()
        context = "a" * 64
        archive_status = {
            "configured": True,
            "trusted_mirror": False,
            "serves_attestations": True,
            "local_signer": True,
            "attestation_version": 2,
            "threshold": 1,
            "trusted_signers": 1,
            "replay_authority_context": context,
        }
        mirror_status = {
            "configured": True,
            "trusted_mirror": True,
            "serves_attestations": False,
            "local_signer": False,
            "attestation_version": 2,
            "threshold": 1,
            "trusted_signers": 1,
            "replay_authority_context": context,
            "accepted": 1,
            "blocks_with_quorum": 1,
        }
        kwargs = {
            "archive_services": [
                "NETWORK", "MATMUL_CONSENSUS", "MATMUL_ATTESTATION_ARCHIVE"
            ],
            "mirror_services": ["NETWORK", "MATMUL_TRUSTED_MIRROR"],
            "archive_status": archive_status,
            "mirror_status": mirror_status,
            "mirror_mode": "trusted",
        }
        module.validate_trusted_mirror_rehearsal(**kwargs)
        cases = (
            ("archive service", {**kwargs, "archive_services": ["NETWORK"]}),
            ("mirror service", {**kwargs, "mirror_services": ["MATMUL_CONSENSUS"]}),
            ("validation mode", {**kwargs, "mirror_mode": "consensus"}),
            ("threshold", {
                **kwargs,
                "mirror_status": {**mirror_status, "threshold": 0},
            }),
            ("boolean threshold", {
                **kwargs,
                "mirror_status": {**mirror_status, "threshold": True},
            }),
            ("numeric configured", {
                **kwargs,
                "mirror_status": {**mirror_status, "configured": 1},
            }),
            ("contexts", {
                **kwargs,
                "mirror_status": {
                    **mirror_status, "replay_authority_context": "b" * 64,
                },
            }),
            ("accepted", {
                **kwargs,
                "mirror_status": {**mirror_status, "accepted": 0},
            }),
            ("quorum", {
                **kwargs,
                "mirror_status": {**mirror_status, "blocks_with_quorum": 0},
            }),
        )
        for label, changed in cases:
            with self.subTest(label=label):
                with self.assertRaises(RuntimeError):
                    module.validate_trusted_mirror_rehearsal(**changed)

    def test_rejects_old_flat_rpc_shape(self):
        module = load_rehearsal()
        with self.assertRaisesRegex(RuntimeError, "backend_runtime"):
            module.extract_strict_replay_evidence({"rc_exact_replay": {}})

    def test_runtime_canary_identity_is_bound(self):
        module = load_rehearsal()
        revision = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        fingerprint = module.EVIDENCE_IDENTITY.tree_fingerprint(REPO_ROOT, revision)
        canary = {
            "passed": True,
            "exact_manifest_match": True,
            "device_macs": 1,
            "cpu_fallbacks": 0,
            "provider": "cuda_rc_exact_fused_extract",
            "provider_family": "cuda",
            "device_architecture": "sm_120",
            "build_source_revision": revision,
            "build_source_tree_fingerprint": fingerprint,
            "build_source_dirty": False,
            "build_provenance_matches": True,
        }
        rc = {
            "production_eligible": True,
            "startup_canary_passed": True,
            "activation_ready": True,
            "resolved_provider": "cuda_rc_exact_fused_extract",
            "production_canary": canary,
            "last_validation": {
                "available": True,
                "require_device": True,
                "fully_accelerated": True,
                "cpu_gemm_calls": 0,
                "cpu_gemm_fallbacks": 0,
                "provider": "cuda_rc_exact_fused_extract",
            },
        }
        module.extract_strict_replay_evidence(
            {"backend_runtime": {"rc_exact_replay": rc}},
            expected_revision=revision,
            expected_fingerprint=fingerprint,
        )
        canary["build_source_dirty"] = True
        with self.assertRaisesRegex(RuntimeError, "build_source_dirty"):
            module.extract_strict_replay_evidence(
                {"backend_runtime": {"rc_exact_replay": rc}},
                expected_revision=revision,
                expected_fingerprint=fingerprint,
            )

    def test_binary_hash_mismatch_fails_closed(self):
        module = load_rehearsal()
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "btxd"
            binary.write_bytes(b"exact binary bytes")
            with self.assertRaisesRegex(Exception, "SHA256 mismatch"):
                module.EVIDENCE_IDENTITY.verify_binary(
                    binary, "0" * 64, "btxd_sha256"
                )

    def test_remote_sha256_quotes_the_exact_path(self):
        module = load_rehearsal()
        seen = []
        module.sh_remote = lambda command: seen.append(command) or ("a" * 64 + "  file")
        self.assertEqual(
            module.remote_sha256("/tmp/bin; touch /tmp/not-run"), "a" * 64
        )
        self.assertIn(
            "sha256sum -- '/tmp/bin; touch /tmp/not-run'", seen[0]
        )
        self.assertIn(
            "shasum -a 256 -- '/tmp/bin; touch /tmp/not-run'", seen[0]
        )

    def test_remote_cleanup_directory_shape_is_fail_closed(self):
        module = load_rehearsal()
        self.assertEqual(
            module.validate_remote_archive_dir(
                "/tmp/btx-trusted-archive.A1b2C3"
            ),
            "/tmp/btx-trusted-archive.A1b2C3",
        )
        for value in (
            "/", "/tmp", "/tmp/unrelated.A1b2C3",
            "/btx-trusted-archive.A1b2C3", "/tmp/btx-trusted-archive.bad/name",
            "/tmp/../var/btx-trusted-archive.A1b2C3",
            "/tmp/btx-trusted-archive.A1b2C3\n/tmp/other",
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "unsafe archive datadir"):
                    module.validate_remote_archive_dir(value)

    def test_remote_pid_and_bounded_stop_command_are_fail_closed(self):
        module = load_rehearsal()
        self.assertEqual(module.validate_remote_pid("12345\n"), "12345")
        start = "Tue Aug 4 00:00:00 2026"
        self.assertEqual(
            module.validate_remote_launch_output(f"12345\n{start}\n"),
            ("12345", start),
        )
        for value in ("", "0", "-1", "1 2", "1; touch /tmp/no", "12\n13"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "valid process ID"):
                    module.validate_remote_pid(value)
        for value in ("12345", "12345\n", "12345\nbad\n", "1\nstart\nextra\n"):
            with self.subTest(launch_output=value):
                with self.assertRaisesRegex(RuntimeError, "launch identity|not valid"):
                    module.validate_remote_launch_output(value)
        command = module.remote_stop_archive_command(
            "12345", "/tmp/btx-trusted-archive.A1b2C3",
            expected_start_identity=start,
        )
        self.assertIn('ps -p "$pid" -o command=', command)
        self.assertIn('kill -TERM "$pid"', command)
        self.assertIn('kill -KILL "$pid"', command)
        self.assertIn("exit 14", command)
        self.assertLess(command.index("kill -TERM"), command.index("kill -KILL"))

    def test_ssh_destination_and_argv_reject_option_injection(self):
        module = load_rehearsal()
        for user, host in (
            ("operator", "gpu-archive.example.invalid"),
            ("user.name", "127.0.0.1"),
            ("u_1", "2001:db8::1"),
            ("u+1", "[2001:db8::1]"),
            ("u", "fe80::1%en0"),
        ):
            with self.subTest(user=user, host=host):
                self.assertEqual(
                    module.validate_ssh_destination(user, host),
                    f"{user}@{host}",
                )
        for user, host in (
            ("-F/tmp/config", "example.invalid"),
            ("-oProxyCommand=touch /tmp/no", "example.invalid"),
            ("user name", "example.invalid"),
            ("user@other", "example.invalid"),
            ("operator", "-oProxyCommand=touch"),
            ("operator", "host name"),
            ("operator", "host@example.invalid"),
            ("operator", "example..invalid"),
            ("operator", "bad/host"),
            ("operator", "[::1"),
            ("operator", "::1]"),
            ("operator", "$(touch-no)"),
            ("operator", "\N{SNOWMAN}.invalid"),
            ("operator", "\N{LATIN SMALL LETTER E WITH ACUTE}xample.invalid"),
        ):
            with self.subTest(user=user, host=host):
                with self.assertRaisesRegex(RuntimeError, "safe|valid|malformed"):
                    module.validate_ssh_destination(user, host)

        module.ARCHIVE_USER = "operator"
        module.ARCHIVE_HOST = "gpu-archive.example.invalid"
        for argv in (
            module.remote_ssh_argv("true"), module.tunnel_ssh_argv(),
        ):
            delimiter = argv.index("--")
            self.assertEqual(
                argv[delimiter + 1], "operator@gpu-archive.example.invalid"
            )
            self.assertFalse(any(arg.startswith("-oProxyCommand")
                                 for arg in argv[delimiter + 1:]))

    def test_remote_stop_shell_terminates_and_refuses_changed_identity(self):
        module = load_rehearsal()
        original_term = module.REMOTE_TERM_WAIT_SECONDS
        original_kill = module.REMOTE_KILL_WAIT_SECONDS
        module.REMOTE_TERM_WAIT_SECONDS = 1
        module.REMOTE_KILL_WAIT_SECONDS = 1
        try:
            with tempfile.TemporaryDirectory() as tmp:
                datadir = Path(tmp) / "btx-trusted-archive.A1b2C3"
                regtest = datadir / "regtest"
                regtest.mkdir(parents=True)
                pidfile = regtest / "btxd.pid"

                def launch(ignore_term):
                    handler = (
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
                        if ignore_term else ""
                    )
                    process = subprocess.Popen(
                        [
                            sys.executable, "-c",
                            "import signal,sys,time;" + handler +
                            "print('ready', flush=True);time.sleep(60)",
                            str(datadir),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True,
                    )
                    self.assertEqual(process.stdout.readline().strip(), "ready")
                    process.stdout.close()
                    pidfile.write_text(f"{process.pid}\n", encoding="utf-8")
                    return process

                def start_identity(process):
                    return subprocess.run(
                        ["ps", "-p", str(process.pid), "-o", "lstart="],
                        check=True, capture_output=True, text=True,
                    ).stdout.strip()

                process = launch(False)
                command = module.remote_stop_archive_command(
                    str(process.pid), str(datadir),
                    expected_start_identity=start_identity(process),
                    require_pidfile=True,
                )
                result = subprocess.run(
                    ["/bin/sh", "-c", command], capture_output=True,
                    text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                process.wait(timeout=5)

                process = launch(True)
                pidfile.unlink()
                command = module.remote_stop_archive_command(
                    str(process.pid), str(datadir),
                    expected_start_identity=start_identity(process),
                    require_pidfile=True,
                )
                result = subprocess.run(
                    ["/bin/sh", "-c", command], capture_output=True,
                    text=True, check=False,
                )
                self.assertEqual(result.returncode, 17, result.stderr)
                self.assertIsNone(process.poll())
                process.kill()
                process.wait(timeout=5)

                process = launch(True)
                fake_bin = Path(tmp) / "fake-bin"
                fake_bin.mkdir()
                counter = Path(tmp) / "lstart-count"
                fake_ps = fake_bin / "ps"
                fake_ps.write_text(
                    "#!/bin/sh\n"
                    "case \" $* \" in\n"
                    "  *' lstart='*)\n"
                    "    n=$(cat \"$PS_COUNTER\" 2>/dev/null || echo 0)\n"
                    "    n=$((n + 1)); printf '%s\\n' \"$n\" > \"$PS_COUNTER\"\n"
                    "    if test \"$n\" -gt 1; then echo changed-identity; exit 0; fi\n"
                    "    ;;\n"
                    "esac\n"
                    "exec /bin/ps \"$@\"\n",
                    encoding="utf-8",
                )
                fake_ps.chmod(0o700)
                command = module.remote_stop_archive_command(
                    str(process.pid), str(datadir),
                    expected_start_identity=start_identity(process),
                    require_pidfile=True,
                )
                env = dict(os.environ)
                env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
                env["PS_COUNTER"] = str(counter)
                result = subprocess.run(
                    ["/bin/sh", "-c", command], capture_output=True,
                    text=True, check=False, env=env,
                )
                self.assertEqual(result.returncode, 18, result.stderr)
                self.assertIsNone(process.poll())
                process.kill()
                process.wait(timeout=5)
        finally:
            module.REMOTE_TERM_WAIT_SECONDS = original_term
            module.REMOTE_KILL_WAIT_SECONDS = original_kill

    def test_remote_cleanup_stops_before_removing_datadir(self):
        module = load_rehearsal()
        commands = []
        original = {
            name: getattr(module, name)
            for name in (
                "ARCHIVE_DD", "ARCHIVE_LOCAL", "ARCHIVE_REMOTE_PID",
                "ARCHIVE_REMOTE_START_IDENTITY",
                "ARCHIVE_REMOTE_LAUNCH_ATTEMPTED", "KEEP_ARTIFACTS",
                "sh_remote",
            )
        }
        try:
            module.ARCHIVE_DD = "/tmp/btx-trusted-archive.A1b2C3"
            module.ARCHIVE_LOCAL = False
            module.ARCHIVE_REMOTE_PID = "12345"
            module.ARCHIVE_REMOTE_START_IDENTITY = "Tue Aug 4 00:00:00 2026"
            module.ARCHIVE_REMOTE_LAUNCH_ATTEMPTED = True
            module.KEEP_ARTIFACTS = False
            module.sh_remote = (
                lambda command, **kwargs: commands.append(command) or ""
            )
            module.cleanup_archive()
            self.assertEqual(len(commands), 2)
            self.assertIn("kill -TERM", commands[0])
            self.assertTrue(commands[1].startswith("rm -rf -- "))
            self.assertFalse(module.ARCHIVE_REMOTE_LAUNCH_ATTEMPTED)
        finally:
            for name, value in original.items():
                setattr(module, name, value)

    def test_remote_cleanup_never_removes_after_unverified_stop(self):
        module = load_rehearsal()
        commands = []
        original = {
            name: getattr(module, name)
            for name in (
                "ARCHIVE_DD", "ARCHIVE_LOCAL", "ARCHIVE_REMOTE_PID",
                "ARCHIVE_REMOTE_START_IDENTITY",
                "ARCHIVE_REMOTE_LAUNCH_ATTEMPTED", "KEEP_ARTIFACTS",
                "sh_remote",
            )
        }
        try:
            module.ARCHIVE_DD = "/tmp/btx-trusted-archive.A1b2C3"
            module.ARCHIVE_LOCAL = False
            module.ARCHIVE_REMOTE_PID = "12345"
            module.ARCHIVE_REMOTE_START_IDENTITY = "Tue Aug 4 00:00:00 2026"
            module.ARCHIVE_REMOTE_LAUNCH_ATTEMPTED = True
            module.KEEP_ARTIFACTS = False

            def fail_stop(command, **kwargs):
                commands.append(command)
                raise subprocess.CalledProcessError(14, command)

            module.sh_remote = fail_stop
            with self.assertRaisesRegex(RuntimeError, "verified stopped state"):
                module.cleanup_archive()
            self.assertEqual(len(commands), 1)
            self.assertNotIn("rm -rf", commands[0])
        finally:
            for name, value in original.items():
                setattr(module, name, value)

    def test_remote_signer_path_is_absolute_and_injection_safe(self):
        module = load_rehearsal()
        self.assertEqual(
            module.validate_remote_file_path(
                "/secure/archive/signer.wif", "--archive-signer-wif-file"
            ),
            "/secure/archive/signer.wif",
        )
        for value in (
            "relative/signer.wif", "/signer.wif", "/secure/../signer.wif",
            "/secure/signer.wif\nserver=0", "/secure/signer.wif\rserver=0",
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "absolute|safe"):
                    module.validate_remote_file_path(
                        value, "--archive-signer-wif-file"
                    )
        command = module.remote_private_file_check_command(
            "/secure/archive/signer file.wif"
        )
        self.assertIn("test -f '/secure/archive/signer file.wif'", command)
        self.assertIn("stat -c '%a' '/secure/archive/signer file.wif'", command)
        self.assertIn("stat -f '%Lp' '/secure/archive/signer file.wif'", command)

    def test_local_signer_permissions_fail_closed(self):
        module = load_rehearsal()
        with tempfile.TemporaryDirectory() as tmp:
            signer = Path(tmp) / "signer.wif"
            signer.write_text("private\n", encoding="utf-8")
            signer.chmod(0o600)
            module.require_private_local_file(signer, "--signer-wif-file")
            self.assertEqual(
                subprocess.run(
                    ["sh", "-c", module.remote_private_file_check_command(str(signer))],
                    check=False,
                ).returncode,
                0,
            )
            signer.chmod(0o640)
            with self.assertRaisesRegex(RuntimeError, "group or others"):
                module.require_private_local_file(signer, "--signer-wif-file")
            self.assertNotEqual(
                subprocess.run(
                    ["sh", "-c", module.remote_private_file_check_command(str(signer))],
                    check=False,
                ).returncode,
                0,
            )

    def test_signer_pubkey_rejects_config_injection(self):
        module = load_rehearsal()
        valid = "02" + "A1" * 32
        self.assertEqual(module.validate_signer_pubkey(valid), valid.lower())
        for value in ("", "04" + "11" * 64, valid + "\nserver=0", "02zz"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "compressed secp256k1"):
                    module.validate_signer_pubkey(value)

    def test_cuda_soak_identity_preserves_toy_mode_and_binds_production(self):
        module = load_rehearsal()
        identity = module.EVIDENCE_IDENTITY
        revision = "1" * 40
        fingerprint = "2" * 64
        toy = {
            "node": "A",
            "active_backend": "cuda",
            "required_backend_satisfied": True,
            "resolved_provider": "cpu_reference",
            "cuda_fallbacks_to_cpu": 0,
        }
        identity.validate_cuda_soak_metric(
            toy, mode="toy", revision=revision, fingerprint=fingerprint
        )
        with self.assertRaisesRegex(Exception, "non-CUDA ExactReplay"):
            identity.validate_cuda_soak_metric(
                toy, mode="production", revision=revision,
                fingerprint=fingerprint,
            )
        production = {
            **toy,
            "resolved_provider": "cuda_rc_exact_fused_extract",
            "build_source_revision": revision,
            "build_source_tree_fingerprint": fingerprint,
            "build_source_dirty": False,
            "build_provenance_matches": True,
        }
        identity.validate_cuda_soak_metric(
            production, mode="production", revision=revision,
            fingerprint=fingerprint,
        )
        for field, replacement, error in (
            ("cuda_fallbacks_to_cpu", None, "integer zero"),
            ("cuda_fallbacks_to_cpu", True, "cuda_fallbacks_to_cpu"),
            ("resolved_provider", "not_cuda_cpu", "non-CUDA ExactReplay"),
        ):
            with self.subTest(field=field, replacement=replacement):
                invalid = {**production, field: replacement}
                with self.assertRaisesRegex(Exception, error):
                    identity.validate_cuda_soak_metric(
                        invalid, mode="production", revision=revision,
                        fingerprint=fingerprint,
                    )
        missing = dict(production)
        del missing["cuda_fallbacks_to_cpu"]
        with self.assertRaisesRegex(Exception, "integer zero"):
            identity.validate_cuda_soak_metric(
                missing, mode="production", revision=revision,
                fingerprint=fingerprint,
            )

    def test_machine_class_is_runtime_derived_and_privacy_bounded(self):
        module = load_rehearsal()
        identity = module.EVIDENCE_IDENTITY
        actual = identity.public_machine_class(
            provider_family="cuda",
            resolved_providers=["cuda_rc_exact_fused_extract"],
            device_architectures=["sm_120"],
            system="Linux",
            machine="aarch64",
        )
        self.assertEqual(actual["os_class"], "Linux aarch64")
        self.assertEqual(actual["device_architecture_classes"], ["sm_120"])
        with self.assertRaisesRegex(Exception, "not a public machine class"):
            identity.public_machine_class(
                provider_family="cuda",
                resolved_providers=["/private/device"],
                device_architectures=["sm_120"],
                system="Linux",
                machine="x86_64",
            )

    def test_rejects_incomplete_validation_schema(self):
        module = load_rehearsal()
        with self.assertRaisesRegex(RuntimeError, "cpu_gemm_fallbacks"):
            module.extract_strict_replay_evidence(
                {
                    "backend_runtime": {
                        "rc_exact_replay": {
                            "production_eligible": True,
                            "startup_canary_passed": True,
                            "activation_ready": True,
                            "resolved_provider": "cuda_rc_exact_fused_extract",
                            "production_canary": {
                                "passed": True,
                                "exact_manifest_match": True,
                                "device_macs": 1,
                                "cpu_fallbacks": 0,
                                "provider": "cuda_rc_exact_fused_extract",
                                "provider_family": "cuda",
                                "device_architecture": "sm_120",
                            },
                            "last_validation": {
                                "available": True,
                                "require_device": True,
                                "fully_accelerated": True,
                                "cpu_gemm_calls": 0,
                                "provider": "cuda_rc_exact_fused_extract",
                            },
                        }
                    }
                }
            )

    def test_lifecycle_binds_runtime_build_identity(self):
        module = load_lifecycle()
        revision = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        fingerprint = module.EVIDENCE_IDENTITY.tree_fingerprint(REPO_ROOT, revision)
        canary = {
            "build_source_revision": revision,
            "build_source_tree_fingerprint": fingerprint,
            "build_source_dirty": False,
            "build_provenance_matches": True,
        }
        actual = module.validate_runtime_build_identity(
            {"backend_runtime": {"rc_exact_replay": {"production_canary": canary}}},
            revision=revision,
            fingerprint=fingerprint,
            label="miner",
        )
        self.assertIs(actual, canary)
        canary["build_provenance_matches"] = False
        # A pre-manifest production build may collect explicitly non-authority
        # core samples as long as its clean source identity is exact.
        self.assertIs(
            module.validate_runtime_build_identity(
                {"backend_runtime": {"rc_exact_replay": {"production_canary": canary}}},
                revision=revision,
                fingerprint=fingerprint,
                label="miner",
            ),
            canary,
        )
        with self.assertRaisesRegex(Exception, "build_provenance_matches"):
            module.EVIDENCE_IDENTITY.validate_canary_build_identity(
                canary, revision=revision, fingerprint=fingerprint,
                prefix="final_campaign",
            )
        canary["build_source_dirty"] = True
        with self.assertRaisesRegex(Exception, "build_source_dirty"):
            module.validate_runtime_build_identity(
                {"backend_runtime": {"rc_exact_replay": {"production_canary": canary}}},
                revision=revision,
                fingerprint=fingerprint,
                label="miner",
            )

    def test_lifecycle_toy_mode_does_not_require_production_canary(self):
        module = load_lifecycle()
        self.assertEqual(
            module.validate_runtime_build_identity(
                {},
                revision="0" * 40,
                fingerprint="0" * 64,
                label="miner",
                require_production_canary=False,
            ),
            {},
        )


if __name__ == "__main__":
    unittest.main()
