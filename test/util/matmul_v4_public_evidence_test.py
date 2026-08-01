#!/usr/bin/env python3
"""Regression tests for the public MatMul evidence privacy gate."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "contrib/matmul-v4/check-public-evidence.py"
SPEC = importlib.util.spec_from_file_location("check_public_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicEvidencePrivacyTest(unittest.TestCase):
    def write(self, root: Path, name: str, value: object) -> Path:
        path = root / name
        if isinstance(value, str):
            path.write_text(value, encoding="utf-8")
        else:
            path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_sanitized_machine_class_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                Path(directory),
                "report.json",
                {
                    "hardware": "NVIDIA consumer Blackwell-class GPU",
                    "provider": "cuda_rc_exact_fused_extract",
                    "source_revision": "0123456789abcdef",
                },
            )
            self.assertEqual(MODULE.check_file(path), [])

    def test_creator_paths_and_identity_keys_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write(
                root,
                "report.json",
                {
                    "hostname": "validator-01",
                    "log": "/Users/operator/private-build/run.log",
                },
            )
            failures = MODULE.check_file(path)
            self.assertTrue(any("hostname" in failure for failure in failures))
            self.assertTrue(any("macOS user path" in failure for failure in failures))

    def test_secret_and_email_text_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                Path(directory),
                "README.md",
                "contact operator@example.invalid; token file github.key\n",
            )
            failures = MODULE.check_file(path)
            self.assertTrue(any("email address" in failure for failure in failures))
            self.assertTrue(any("private key filename" in failure for failure in failures))

    def test_mdns_hostname_hidden_inside_device_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                Path(directory),
                "report.json",
                {
                    "device_id": "metal-provider:validator-workstation.local",
                    "hardware": "Apple Silicon M4 Max-class Metal",
                },
            )
            failures = MODULE.check_file(path)
            self.assertTrue(any("mDNS hostname" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
