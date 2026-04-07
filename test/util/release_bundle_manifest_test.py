#!/usr/bin/env python3
"""Unit coverage for scripts/release/collect_release_assets.py."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "release" / "collect_release_assets.py"


def load_module():
    spec = importlib.util.spec_from_file_location("collect_release_assets", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ReleaseBundleManifestTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_classify_primary_platform_asset_detects_supported_archives(self):
        info = self.module.classify_primary_platform_asset("btx-29.2-x86_64-linux-gnu.tar.gz")
        self.assertIsNotNone(info)
        self.assertEqual(info["platform_id"], "linux-x86_64")
        self.assertEqual(info["archive_format"], "tar.gz")

        self.assertIsNone(
            self.module.classify_primary_platform_asset(
                "btx-29.2-x86_64-linux-gnu-codesigning.tar.gz"
            )
        )

    def test_build_manifest_includes_platform_assets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = pathlib.Path(tmpdir)
            archive = bundle_dir / "btx-29.2-x86_64-linux-gnu.tar.gz"
            snapshot = bundle_dir / "snapshot.dat"
            archive.write_bytes(b"archive")
            snapshot.write_bytes(b"snapshot")

            args = self.module.parse_args(
                [
                    "--output-dir",
                    str(bundle_dir),
                    "--release-tag",
                    "v29.2",
                    "--release-name",
                    "BTX 29.2",
                ]
            )
            release_manifest_path = bundle_dir / "btx-release-manifest.json"
            manifest = self.module.build_manifest(
                args,
                [("archive", archive), ("snapshot", snapshot)],
                release_manifest_path,
                "SHA256SUMS",
            )

            self.assertIn("platform_assets", manifest)
            self.assertEqual(
                manifest["platform_assets"]["linux-x86_64"]["asset_name"],
                "btx-29.2-x86_64-linux-gnu.tar.gz",
            )

    def test_collect_platform_assets_rejects_duplicate_platform_archives(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = pathlib.Path(tmpdir)
            first = bundle_dir / "btx-29.2-x86_64-linux-gnu.tar.gz"
            second = bundle_dir / "btx-29.2-win64-x86_64-linux-gnu.zip"
            first.write_bytes(b"one")
            second.write_bytes(b"two")

            with self.assertRaises(ValueError):
                self.module.collect_platform_assets([("one", first), ("two", second)])

    def test_ensure_empty_dir_rejects_non_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = pathlib.Path(tmpdir)
            (bundle_dir / "existing.txt").write_text("occupied\n", encoding="utf-8")

            with self.assertRaisesRegex(FileExistsError, "Output directory is not empty"):
                self.module.ensure_empty_dir(bundle_dir)

    def test_collect_sources_rejects_duplicate_flattened_names(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_a = root / "a"
            source_b = root / "b"
            source_a.mkdir()
            source_b.mkdir()
            (source_a / "duplicate.txt").write_text("one\n", encoding="utf-8")
            (source_b / "duplicate.txt").write_text("two\n", encoding="utf-8")
            bundle_dir = root / "bundle"
            bundle_dir.mkdir()

            with self.assertRaisesRegex(FileExistsError, "Duplicate asset name after flattening"):
                self.module.collect_sources([str(source_a), str(source_b)], bundle_dir)

    def test_collect_sources_skips_checksum_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_dir = root / "source"
            source_dir.mkdir()
            (source_dir / "btx-29.2-x86_64-linux-gnu.tar.gz").write_bytes(b"archive")
            (source_dir / "SHA256SUMS").write_text("ignored\n", encoding="utf-8")
            (source_dir / "SHA256SUMS.part001").write_text("ignored\n", encoding="utf-8")
            bundle_dir = root / "bundle"
            bundle_dir.mkdir()

            staged = self.module.collect_sources([str(source_dir)], bundle_dir)

            self.assertEqual([path.name for _, path in staged], ["btx-29.2-x86_64-linux-gnu.tar.gz"])

    def test_main_requires_complete_platform_matrix_by_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_dir = root / "source"
            source_dir.mkdir()
            (source_dir / "btx-29.2-x86_64-linux-gnu.tar.gz").write_bytes(b"archive")

            with self.assertRaisesRegex(ValueError, "Missing required platform assets"):
                self.module.main(
                    [
                        "--output-dir",
                        str(root / "bundle"),
                        "--source",
                        str(source_dir),
                    ]
                )

    def test_main_stages_snapshot_and_signature_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_dir = root / "source"
            source_dir.mkdir()
            archive = source_dir / "btx-29.2-x86_64-linux-gnu.tar.gz"
            archive.write_bytes(b"archive")
            snapshot = root / "mainnet-utxo.dat"
            snapshot.write_bytes(b"snapshot")
            snapshot_manifest = root / "mainnet-utxo.json"
            snapshot_manifest.write_text("{\"chain\":\"main\"}\n", encoding="utf-8")
            checksum_signature = root / "external.asc"
            checksum_signature.write_text("signature\n", encoding="utf-8")
            bundle_dir = root / "bundle"

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = self.module.main(
                    [
                        "--output-dir",
                        str(bundle_dir),
                        "--source",
                        str(source_dir),
                        "--snapshot",
                        str(snapshot),
                        "--snapshot-manifest",
                        str(snapshot_manifest),
                        "--checksum-signature",
                        str(checksum_signature),
                        "--release-tag",
                        "v29.2",
                        "--required-platform",
                        "linux-x86_64",
                    ]
                )

            self.assertEqual(exit_code, 0)
            summary = json.loads(output.getvalue())
            self.assertEqual(summary["bundle_dir"], str(bundle_dir))
            self.assertTrue((bundle_dir / "snapshot.dat").is_file())
            self.assertTrue((bundle_dir / "snapshot.manifest.json").is_file())
            self.assertTrue((bundle_dir / "SHA256SUMS.asc").is_file())

            checksums = (bundle_dir / "SHA256SUMS").read_text(encoding="utf-8")
            self.assertIn("snapshot.dat", checksums)
            self.assertIn("snapshot.manifest.json", checksums)
            self.assertNotIn("SHA256SUMS  ", checksums)
            self.assertNotIn("SHA256SUMS.asc", checksums)

            manifest = json.loads((bundle_dir / "btx-release-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["snapshot_asset"], "snapshot.dat")
            self.assertEqual(manifest["snapshot_manifest"], "snapshot.manifest.json")
            self.assertEqual(manifest["signature_file"], "SHA256SUMS.asc")

    def test_validate_snapshot_inputs_rejects_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            snapshot = root / "snapshot.dat"
            snapshot.write_bytes(b"snapshot")
            snapshot_manifest = root / "snapshot.manifest.json"
            snapshot_manifest.write_text(
                json.dumps({"snapshot_sha256": "00" * 32}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "Snapshot manifest SHA256 mismatch"):
                self.module.validate_snapshot_inputs(snapshot, snapshot_manifest)

    def test_validate_snapshot_inputs_rejects_conflicting_manifest_digests(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            snapshot = root / "snapshot.dat"
            snapshot.write_bytes(b"snapshot")
            snapshot_manifest = root / "snapshot.manifest.json"
            snapshot_manifest.write_text(
                json.dumps(
                    {
                        "snapshot_sha256": "11" * 32,
                        "sha256": "22" * 32,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "conflicting SHA256"):
                self.module.validate_snapshot_inputs(snapshot, snapshot_manifest)

    def test_main_stages_guix_attestations_with_signer_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_dir = root / "source"
            source_dir.mkdir()
            archive = source_dir / "btx-29.2-x86_64-linux-gnu.tar.gz"
            archive.write_bytes(b"archive")
            attestations_dir = root / "guix.sigs" / "29.2"
            alice_dir = attestations_dir / "alice"
            bob_dir = attestations_dir / "bob"
            alice_dir.mkdir(parents=True)
            bob_dir.mkdir(parents=True)
            (alice_dir / "noncodesigned.SHA256SUMS").write_text("alice noncodesigned\n", encoding="utf-8")
            (alice_dir / "noncodesigned.SHA256SUMS.asc").write_text("alice signature\n", encoding="utf-8")
            (bob_dir / "all.SHA256SUMS").write_text("bob all\n", encoding="utf-8")

            bundle_dir = root / "bundle"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = self.module.main(
                    [
                        "--output-dir",
                        str(bundle_dir),
                        "--source",
                        str(source_dir),
                        "--attestations-dir",
                        str(attestations_dir),
                        "--required-platform",
                        "linux-x86_64",
                    ]
                )

            self.assertEqual(exit_code, 0)
            summary = json.loads(output.getvalue())
            self.assertIn("guix-attestations-alice-noncodesigned.SHA256SUMS", summary["attestation_assets"])
            self.assertIn("guix-attestations-alice-noncodesigned.SHA256SUMS.asc", summary["attestation_assets"])
            self.assertIn("guix-attestations-bob-all.SHA256SUMS", summary["attestation_assets"])
            self.assertTrue((bundle_dir / "guix-attestations-alice-noncodesigned.SHA256SUMS").is_file())
            self.assertTrue((bundle_dir / "guix-attestations-bob-all.SHA256SUMS").is_file())

            manifest = json.loads((bundle_dir / "btx-release-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(
                manifest["attestation_assets"],
                [
                    {
                        "signer": "alice",
                        "kind": "noncodesigned",
                        "signed": False,
                        "asset_name": "guix-attestations-alice-noncodesigned.SHA256SUMS",
                        "source_dir": str(alice_dir),
                    },
                    {
                        "signer": "alice",
                        "kind": "noncodesigned",
                        "signed": True,
                        "asset_name": "guix-attestations-alice-noncodesigned.SHA256SUMS.asc",
                        "source_dir": str(alice_dir),
                    },
                    {
                        "signer": "bob",
                        "kind": "all",
                        "signed": False,
                        "asset_name": "guix-attestations-bob-all.SHA256SUMS",
                        "source_dir": str(bob_dir),
                    },
                ],
            )

    def test_main_rejects_empty_attestations_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_dir = root / "source"
            source_dir.mkdir()
            (source_dir / "btx-29.2-x86_64-linux-gnu.tar.gz").write_bytes(b"archive")
            empty_attestations_dir = root / "guix.sigs" / "29.2"
            empty_attestations_dir.mkdir(parents=True)

            with self.assertRaisesRegex(FileNotFoundError, "No guix attestation files found"):
                self.module.main(
                    [
                        "--output-dir",
                        str(root / "bundle"),
                        "--source",
                        str(source_dir),
                        "--attestations-dir",
                        str(empty_attestations_dir),
                        "--required-platform",
                        "linux-x86_64",
                    ]
                )

    def test_main_rejects_mutually_exclusive_signature_modes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            bundle_dir = root / "bundle"
            checksum_signature = root / "external.asc"
            checksum_signature.write_text("signature\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                self.module.main(
                    [
                        "--output-dir",
                        str(bundle_dir),
                        "--checksum-signature",
                        str(checksum_signature),
                        "--sign-with",
                        "release-key",
                    ]
                )

    def test_main_sign_with_invokes_signer(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_dir = root / "source"
            source_dir.mkdir()
            archive = source_dir / "btx-29.2-x86_64-linux-gnu.tar.gz"
            archive.write_bytes(b"archive")
            bundle_dir = root / "bundle"
            signed: list[tuple[str, str, str]] = []

            original_sign = self.module.sign_checksum_file
            try:
                def fake_sign(checksum_path, gpg_bin, sign_with, gpg_passphrase_env=None):
                    signed.append((str(checksum_path), gpg_bin, sign_with, gpg_passphrase_env))
                    signature_path = pathlib.Path(str(checksum_path) + ".asc")
                    signature_path.write_text("signed\n", encoding="utf-8")
                    return signature_path

                self.module.sign_checksum_file = fake_sign
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    exit_code = self.module.main(
                        [
                            "--output-dir",
                            str(bundle_dir),
                        "--source",
                        str(source_dir),
                        "--sign-with",
                        "release-key",
                        "--gpg-passphrase-env",
                        "BTX_GPG_PASSPHRASE",
                        "--gpg",
                        "fake-gpg",
                        "--required-platform",
                        "linux-x86_64",
                    ]
                )
            finally:
                self.module.sign_checksum_file = original_sign

            self.assertEqual(exit_code, 0)
            self.assertEqual(
                signed,
                [(str(bundle_dir / "SHA256SUMS"), "fake-gpg", "release-key", "BTX_GPG_PASSPHRASE")],
            )
            self.assertTrue((bundle_dir / "SHA256SUMS.asc").is_file())

    def test_sign_checksum_file_uses_loopback_passphrase_when_requested(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            checksum_path = root / "SHA256SUMS"
            checksum_path.write_text("checksum\n", encoding="utf-8")
            recorded: list[tuple[list[str], dict[str, object]]] = []

            original_run = self.module.subprocess.run
            original_value = os.environ.get("BTX_GPG_PASSPHRASE")
            try:
                os.environ["BTX_GPG_PASSPHRASE"] = "secret-passphrase"

                def fake_run(command, **kwargs):
                    recorded.append((list(command), dict(kwargs)))
                    class Result:
                        returncode = 0
                    return Result()

                self.module.subprocess.run = fake_run
                self.module.sign_checksum_file(
                    checksum_path,
                    "gpg",
                    "release-key",
                    "BTX_GPG_PASSPHRASE",
                )
            finally:
                self.module.subprocess.run = original_run
                if original_value is None:
                    os.environ.pop("BTX_GPG_PASSPHRASE", None)
                else:
                    os.environ["BTX_GPG_PASSPHRASE"] = original_value

            self.assertEqual(len(recorded), 1)
            command, kwargs = recorded[0]
            self.assertIn("--pinentry-mode", command)
            self.assertIn("loopback", command)
            self.assertIn("--passphrase-fd", command)
            self.assertEqual(kwargs["input"], "secret-passphrase")
            self.assertTrue(kwargs["text"])

    def test_main_rejects_snapshot_name_collision(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_dir = root / "source"
            source_dir.mkdir()
            (source_dir / "btx-29.2-x86_64-linux-gnu.tar.gz").write_bytes(b"archive")
            (source_dir / "snapshot.dat").write_bytes(b"collision")
            snapshot = root / "real-snapshot.dat"
            snapshot.write_bytes(b"snapshot")

            with self.assertRaisesRegex(FileExistsError, "Duplicate bundle asset name"):
                self.module.main(
                    [
                        "--output-dir",
                        str(root / "bundle"),
                        "--source",
                        str(source_dir),
                        "--snapshot",
                        str(snapshot),
                        "--required-platform",
                        "linux-x86_64",
                    ]
                )


if __name__ == "__main__":
    unittest.main()
