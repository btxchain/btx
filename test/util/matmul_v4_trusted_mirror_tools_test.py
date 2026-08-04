#!/usr/bin/env python3
"""Focused tests for MatMul lifecycle and trusted-mirror command-line tools."""

import importlib.util
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
            "MIRROR_BTXD",
            "MIRROR_CLI",
            "SIGNER_WIF_FILE",
            "SIGNER_PUB_FILE",
            "BTX_SOURCE_REVISION",
            "ARCHIVE_BTXD_SHA256",
            "ARCHIVE_CLI_SHA256",
            "MIRROR_BTXD_SHA256",
            "MIRROR_CLI_SHA256",
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

    def test_rehearsal_parses_explicit_deployment_arguments(self):
        module = load_rehearsal()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = {}
            for name in ("mirror-btxd", "mirror-cli", "signer-wif", "signer-pub"):
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
                        "--archive-host",
                        "gpu-archive.example.invalid",
                        "--archive-user",
                        "operator",
                        "--archive-btxd",
                        "/opt/btx/bin/btxd",
                        "--archive-cli",
                        "/opt/btx/bin/btx-cli",
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
                        "a" * 64,
                        "--archive-cli-sha256",
                        "b" * 64,
                        "--mirror-btxd-sha256",
                        binary_hash,
                        "--mirror-cli-sha256",
                        binary_hash,
                    ]
                ),
            )
        self.assertEqual(args.archive_host, "gpu-archive.example.invalid")
        self.assertEqual(args.archive_cli, "/opt/btx/bin/btx-cli")
        self.assertEqual(args.mirror_cli.name, "mirror-cli")
        self.assertEqual(args.source_revision, revision)

    def test_extracts_nested_strict_replay_evidence(self):
        module = load_rehearsal()
        rc = {
            "production_canary": {
                "passed": True,
                "device_macs": 1,
                "cpu_fallbacks": 0,
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
            "device_macs": 1,
            "cpu_fallbacks": 0,
            "build_source_revision": revision,
            "build_source_tree_fingerprint": fingerprint,
            "build_source_dirty": False,
            "build_provenance_matches": True,
        }
        rc = {
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

    def test_rejects_incomplete_validation_schema(self):
        module = load_rehearsal()
        with self.assertRaisesRegex(RuntimeError, "cpu_gemm_fallbacks"):
            module.extract_strict_replay_evidence(
                {
                    "backend_runtime": {
                        "rc_exact_replay": {
                            "production_canary": {
                                "passed": True,
                                "device_macs": 1,
                                "cpu_fallbacks": 0,
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
