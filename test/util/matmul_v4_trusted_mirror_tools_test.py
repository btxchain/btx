#!/usr/bin/env python3
"""Focused tests for MatMul lifecycle and trusted-mirror command-line tools."""

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
                            "expired": 0,
                            "evicted": 0,
                            "misses": 0,
                            "entries": 0,
                            "last_provider": provider,
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
            validation={"available": False},
            expected_provider="metal_rc_exact",
        )
        self.assertEqual(proof["authority_consumed"], 3)
        self.assertEqual(proof["winner_reseal_completions"], 3)

        cases = []
        too_few = copy.deepcopy(final)
        too_few["backend_runtime"]["rc_accelerator_scheduler"]["winner_reseal_authority"]["consumed"] = 2
        cases.append(("at least 3", too_few))
        wrong_provider = copy.deepcopy(final)
        wrong_provider["backend_runtime"]["rc_accelerator_scheduler"]["winner_reseal_authority"]["last_provider"] = "cuda_rc_exact_fused_extract"
        cases.append(("provider differs", wrong_provider))
        invariant = copy.deepcopy(final)
        invariant["backend_runtime"]["rc_accelerator_scheduler"]["release_invariant_violations"] = 1
        cases.append(("invariant", invariant))
        missed = copy.deepcopy(final)
        missed["backend_runtime"]["rc_accelerator_scheduler"]["winner_reseal_authority"]["misses"] = 1
        cases.append(("misses changed", missed))
        for error, changed in cases:
            with self.subTest(error=error):
                with self.assertRaisesRegex(RuntimeError, error):
                    module.validate_archive_strict_proof(
                        mode="winner-reseal-authority",
                        baseline_mining_info=baseline,
                        final_mining_info=changed,
                        validation={"available": False},
                        expected_provider="metal_rc_exact",
                    )

    def test_receiving_validation_proof_fails_closed_when_unavailable(self):
        module = load_rehearsal()
        with self.assertRaisesRegex(RuntimeError, "no validation is available"):
            module.validate_archive_strict_proof(
                mode="receiving-validation",
                baseline_mining_info={},
                final_mining_info={},
                validation={"available": False},
                expected_provider="metal_rc_exact",
            )
        proof = module.validate_archive_strict_proof(
            mode="receiving-validation",
            baseline_mining_info={},
            final_mining_info={},
            validation={
                "available": True,
                "provider": "metal_rc_exact",
                "require_device": True,
                "fully_accelerated": True,
                "cpu_gemm_calls": 0,
                "cpu_gemm_fallbacks": 0,
            },
            expected_provider="metal_rc_exact",
        )
        self.assertEqual(proof["mode"], "receiving-validation")

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
