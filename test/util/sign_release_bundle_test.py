#!/usr/bin/env python3
"""Unit coverage for scripts/release/sign_release_bundle.py."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "release" / "sign_release_bundle.py"


def load_module():
    sys.path.insert(0, str(SCRIPT_PATH.parent))
    spec = importlib.util.spec_from_file_location("sign_release_bundle", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SignReleaseBundleTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def _build_bundle(self, root: pathlib.Path) -> pathlib.Path:
        bundle = root / "bundle"
        bundle.mkdir()
        manifest_path = bundle / "btx-release-manifest.json"
        manifest_path.write_text(json.dumps({
            "format_version": 1,
            "checksum_file": "SHA256SUMS",
            "signature_file": None,
            "release_tag": "v0.33.0",
        }) + "\n", encoding="utf-8")
        (bundle / "asset.bin").write_bytes(b"release asset")
        self.module.collector.write_checksum_file(bundle, "SHA256SUMS")
        return bundle

    def test_signs_rechecks_and_pins_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = self._build_bundle(pathlib.Path(tmpdir))
            signer = "11" * 20
            self.module.collector.sign_checksum_file = (
                lambda checksum, gpg, sign_with, gpg_passphrase_env=None:
                (bundle / "SHA256SUMS.asc").write_text("signature\n", encoding="utf-8")
            )
            self.module.publisher.verify_checksum_signature = lambda *args: {signer.upper()}
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = self.module.main([
                    "--bundle-dir", str(bundle),
                    "--sign-with", "release-key",
                    "--expected-signing-fingerprint", signer,
                ])

            self.assertEqual(exit_code, 0)
            manifest = json.loads((bundle / "btx-release-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["signature_file"], "SHA256SUMS.asc")
            self.assertTrue((bundle / "SHA256SUMS.asc").is_file())
            self.module.publisher.ensure_bundle(bundle)

    def test_signer_mismatch_restores_unsigned_bundle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = self._build_bundle(pathlib.Path(tmpdir))
            original_manifest = (bundle / "btx-release-manifest.json").read_bytes()
            original_checksums = (bundle / "SHA256SUMS").read_bytes()
            self.module.collector.sign_checksum_file = (
                lambda checksum, gpg, sign_with, gpg_passphrase_env=None:
                (bundle / "SHA256SUMS.asc").write_text("signature\n", encoding="utf-8")
            )
            self.module.publisher.verify_checksum_signature = lambda *args: {("22" * 20).upper()}

            with self.assertRaisesRegex(RuntimeError, "signer mismatch"):
                self.module.main([
                    "--bundle-dir", str(bundle),
                    "--sign-with", "wrong-key",
                    "--expected-signing-fingerprint", "11" * 20,
                ])

            self.assertEqual((bundle / "btx-release-manifest.json").read_bytes(), original_manifest)
            self.assertEqual((bundle / "SHA256SUMS").read_bytes(), original_checksums)
            self.assertFalse((bundle / "SHA256SUMS.asc").exists())


if __name__ == "__main__":
    unittest.main()
