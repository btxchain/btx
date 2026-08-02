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
                    ]
                ),
            )
        self.assertEqual(args.archive_host, "gpu-archive.example.invalid")
        self.assertEqual(args.archive_cli, "/opt/btx/bin/btx-cli")
        self.assertEqual(args.mirror_cli.name, "mirror-cli")

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


if __name__ == "__main__":
    unittest.main()
