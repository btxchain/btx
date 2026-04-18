#!/usr/bin/env python3
"""Unit coverage for scripts/release/publish_github_release.py."""

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
SCRIPT_PATH = ROOT / "scripts" / "release" / "publish_github_release.py"


def load_module():
    spec = importlib.util.spec_from_file_location("publish_github_release", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PublishGitHubReleaseTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def _build_bundle(
        self,
        root: pathlib.Path,
        *,
        include_signature: bool = False,
        manifest_overrides: dict[str, object] | None = None,
    ) -> pathlib.Path:
        bundle_dir = root / "bundle"
        bundle_dir.mkdir()
        manifest_path = bundle_dir / "btx-release-manifest.json"
        manifest = {"checksum_file": "SHA256SUMS", "signature_file": "SHA256SUMS.asc" if include_signature else None}
        if manifest_overrides:
            manifest.update(manifest_overrides)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        (bundle_dir / "SHA256SUMS").write_text(
            f"{self.module.sha256_file(manifest_path)}  {manifest_path.name}\n",
            encoding="utf-8",
        )
        if include_signature:
            (bundle_dir / "SHA256SUMS.asc").write_text("signed\n", encoding="utf-8")
        return bundle_dir

    def test_token_file_takes_precedence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            token_file = root / "github.token"
            token_file.write_text("file-token\n", encoding="utf-8")
            os.environ["BTX_GITHUB_TOKEN"] = "env-token"
            try:
                args = self.module.parse_args(
                    [
                        "--repo",
                        "btxchain/btx-node",
                        "--tag",
                        "v29.2",
                        "--bundle-dir",
                        str(self._build_bundle(root)),
                        "--token-file",
                        str(token_file),
                    ]
                )
                self.assertEqual(self.module.read_token(args), "file-token")
            finally:
                os.environ.pop("BTX_GITHUB_TOKEN", None)

    def test_main_dry_run_prints_release_plan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = self._build_bundle(pathlib.Path(tmpdir))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = self.module.main(
                    [
                        "--repo",
                        "btxchain/btx-node",
                        "--tag",
                        "v29.2",
                        "--bundle-dir",
                        str(bundle_dir),
                        "--dry-run",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["repo"], "btxchain/btx-node")
            self.assertEqual(payload["tag"], "v29.2")
            self.assertEqual(
                payload["assets"],
                ["SHA256SUMS", "btx-release-manifest.json"],
            )

    def test_main_updates_existing_release_and_reuploads_assets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = self._build_bundle(pathlib.Path(tmpdir))
            deleted_assets: list[int] = []
            uploaded_assets: list[str] = []

            self.module.read_token = lambda args: "test-token"
            self.module.get_release = lambda repo, tag, token: {
                "id": 41,
                "html_url": "https://github.example/releases/v29.2",
                "upload_url": "https://uploads.example/assets{?name,label}",
                "assets": [
                    {"id": 7, "name": "SHA256SUMS"},
                    {"id": 8, "name": "btx-release-manifest.json"},
                ],
            }
            self.module.update_release = lambda repo, release_id, token, payload: {
                "id": release_id,
                "html_url": "https://github.example/releases/v29.2",
                "upload_url": "https://uploads.example/assets{?name,label}",
                "assets": [
                    {"id": 7, "name": "SHA256SUMS"},
                    {"id": 8, "name": "btx-release-manifest.json"},
                ],
            }
            self.module.delete_asset = lambda repo, asset_id, token: deleted_assets.append(asset_id)
            self.module.upload_asset = lambda repo, release, asset, token: uploaded_assets.append(asset.name)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = self.module.main(
                    [
                        "--repo",
                        "btxchain/btx-node",
                        "--tag",
                        "v29.2",
                        "--bundle-dir",
                        str(bundle_dir),
                        "--publish",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(deleted_assets, [7, 8])
            self.assertEqual(
                uploaded_assets,
                ["SHA256SUMS", "btx-release-manifest.json"],
            )
            self.assertEqual(
                output.getvalue().strip(),
                "https://github.example/releases/v29.2",
            )

    def test_ensure_bundle_requires_checksum_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = pathlib.Path(tmpdir)
            bundle_dir.mkdir(exist_ok=True)
            (bundle_dir / "btx-release-manifest.json").write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(FileNotFoundError, "missing SHA256SUMS"):
                self.module.ensure_bundle(bundle_dir)

    def test_ensure_bundle_requires_release_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = pathlib.Path(tmpdir)
            bundle_dir.mkdir(exist_ok=True)
            checksum_path = bundle_dir / "SHA256SUMS"
            checksum_path.write_text("", encoding="utf-8")

            with self.assertRaisesRegex(FileNotFoundError, "missing btx-release-manifest.json"):
                self.module.ensure_bundle(bundle_dir)

    def test_ensure_bundle_rejects_unlisted_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = self._build_bundle(pathlib.Path(tmpdir))
            (bundle_dir / "extra.txt").write_text("extra\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "not listed in SHA256SUMS"):
                self.module.ensure_bundle(bundle_dir)

    def test_ensure_bundle_rejects_missing_manifest_asset_reference(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = self._build_bundle(
                pathlib.Path(tmpdir),
                manifest_overrides={"assets": [{"name": "missing-asset.tar.gz"}]},
            )

            with self.assertRaisesRegex(FileNotFoundError, "references asset not present"):
                self.module.ensure_bundle(bundle_dir)

    def test_ensure_bundle_rejects_missing_platform_asset_reference(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = self._build_bundle(
                pathlib.Path(tmpdir),
                manifest_overrides={
                    "platform_assets": {
                        "linux-x86_64": {"asset_name": "missing-archive.tar.gz"}
                    }
                },
            )

            with self.assertRaisesRegex(FileNotFoundError, "platform_assets\\['linux-x86_64'\\] points to missing asset"):
                self.module.ensure_bundle(bundle_dir)

    def test_ensure_bundle_rejects_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = self._build_bundle(pathlib.Path(tmpdir))
            (bundle_dir / "btx-release-manifest.json").write_text("{\"tampered\":true}\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "SHA256SUMS mismatch"):
                self.module.ensure_bundle(bundle_dir)

    def test_main_rejects_publish_and_draft_together(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = self._build_bundle(pathlib.Path(tmpdir))
            with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                self.module.main(
                    [
                        "--repo",
                        "btxchain/btx-node",
                        "--tag",
                        "v29.2",
                        "--bundle-dir",
                        str(bundle_dir),
                        "--publish",
                        "--draft",
                    ]
                )

    def test_main_requires_token_for_publish(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = self._build_bundle(pathlib.Path(tmpdir))
            original_read_token = self.module.read_token
            try:
                self.module.read_token = lambda args: None
                with self.assertRaisesRegex(RuntimeError, "No GitHub token found"):
                    self.module.main(
                        [
                            "--repo",
                            "btxchain/btx-node",
                            "--tag",
                            "v29.2",
                            "--bundle-dir",
                            str(bundle_dir),
                            "--publish",
                        ]
                    )
            finally:
                self.module.read_token = original_read_token

    def test_main_creates_release_and_propagates_payload_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            bundle_dir = self._build_bundle(root)
            body_file = root / "release-notes.md"
            body_file.write_text("# Release notes\n", encoding="utf-8")
            created_payloads: list[dict[str, object]] = []
            uploaded_assets: list[str] = []

            self.module.read_token = lambda args: "test-token"
            self.module.get_release = lambda repo, tag, token: None

            def fake_create(repo, tag, token, payload):
                created_payloads.append(payload)
                return {
                    "id": 52,
                    "html_url": "https://github.example/releases/v29.2",
                    "upload_url": "https://uploads.example/assets{?name,label}",
                    "assets": [],
                }

            self.module.create_release = fake_create
            self.module.upload_asset = lambda repo, release, asset, token: uploaded_assets.append(asset.name)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = self.module.main(
                    [
                        "--repo",
                        "btxchain/btx-node",
                        "--tag",
                        "v29.2",
                        "--bundle-dir",
                        str(bundle_dir),
                        "--body-file",
                        str(body_file),
                        "--target-branch",
                        "release/29.x",
                        "--prerelease",
                        "--publish",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(created_payloads), 1)
            self.assertEqual(created_payloads[0]["target_commitish"], "release/29.x")
            self.assertEqual(created_payloads[0]["prerelease"], True)
            self.assertEqual(created_payloads[0]["draft"], False)
            self.assertEqual(created_payloads[0]["body"], "# Release notes\n")
            self.assertEqual(uploaded_assets, ["SHA256SUMS", "btx-release-manifest.json"])

    def test_main_verifies_declared_checksum_signature_before_publish(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = self._build_bundle(pathlib.Path(tmpdir), include_signature=True)
            verified: list[tuple[str, str, str]] = []
            uploaded_assets: list[str] = []

            self.module.read_token = lambda args: "test-token"
            self.module.get_release = lambda repo, tag, token: None
            self.module.create_release = lambda repo, tag, token, payload: {
                "id": 52,
                "html_url": "https://github.example/releases/v29.2",
                "upload_url": "https://uploads.example/assets{?name,label}",
                "assets": [],
            }
            self.module.upload_asset = lambda repo, release, asset, token: uploaded_assets.append(asset.name)
            self.module.verify_checksum_signature = (
                lambda checksum_path, signature_path, gpg_bin: verified.append(
                    (checksum_path.name, signature_path.name, gpg_bin)
                )
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = self.module.main(
                    [
                        "--repo",
                        "btxchain/btx-node",
                        "--tag",
                        "v29.2",
                        "--bundle-dir",
                        str(bundle_dir),
                        "--gpg",
                        "fake-gpg",
                        "--publish",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(verified, [("SHA256SUMS", "SHA256SUMS.asc", "fake-gpg")])
            self.assertEqual(uploaded_assets, ["SHA256SUMS", "SHA256SUMS.asc", "btx-release-manifest.json"])
            self.assertEqual(output.getvalue().strip(), "https://github.example/releases/v29.2")

    def test_main_rejects_missing_declared_checksum_signature(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = self._build_bundle(pathlib.Path(tmpdir), include_signature=False, manifest_overrides={"signature_file": "SHA256SUMS.asc"})
            self.module.read_token = lambda args: "test-token"

            with self.assertRaisesRegex(FileNotFoundError, "missing declared signature file"):
                self.module.main(
                    [
                        "--repo",
                        "btxchain/btx-node",
                        "--tag",
                        "v29.2",
                        "--bundle-dir",
                        str(bundle_dir),
                        "--publish",
                    ]
                )

    def test_get_release_returns_none_for_404(self):
        original_run = self.module.subprocess.run
        try:
            def fake_run(cmd, capture_output, text):
                class Result:
                    returncode = 0
                    stdout = "{}\n404"
                    stderr = ""
                return Result()

            self.module.subprocess.run = fake_run
            self.assertIsNone(self.module.get_release("btxchain/btx-node", "v29.2", "token"))
        finally:
            self.module.subprocess.run = original_run

    def test_get_release_raises_on_unexpected_http_status(self):
        original_run = self.module.subprocess.run
        try:
            def fake_run(cmd, capture_output, text):
                class Result:
                    returncode = 0
                    stdout = "{\"message\":\"boom\"}\n500"
                    stderr = ""
                return Result()

            self.module.subprocess.run = fake_run
            with self.assertRaisesRegex(RuntimeError, "Unexpected HTTP 500"):
                self.module.get_release("btxchain/btx-node", "v29.2", "token")
        finally:
            self.module.subprocess.run = original_run

    def test_curl_json_raises_on_subprocess_failure(self):
        original_run = self.module.subprocess.run
        try:
            def fake_run(cmd, capture_output, text):
                class Result:
                    returncode = 1
                    stdout = ""
                    stderr = "curl failed"
                return Result()

            self.module.subprocess.run = fake_run
            with self.assertRaisesRegex(RuntimeError, "curl failed"):
                self.module.curl_json("POST", "https://api.github.com/example", token="token", payload={"x": 1})
        finally:
            self.module.subprocess.run = original_run

    def test_curl_binary_raises_on_subprocess_failure(self):
        original_run = self.module.subprocess.run
        try:
            def fake_run(cmd, capture_output, text):
                class Result:
                    returncode = 1
                    stdout = ""
                    stderr = "upload failed"
                return Result()

            self.module.subprocess.run = fake_run
            with tempfile.TemporaryDirectory() as tmpdir:
                payload = pathlib.Path(tmpdir) / "asset.bin"
                payload.write_bytes(b"asset")
                with self.assertRaisesRegex(RuntimeError, "upload failed"):
                    self.module.curl_binary(
                        "POST",
                        "https://uploads.example/assets?name=asset.bin",
                        payload,
                        token="token",
                        content_type="application/octet-stream",
                    )
        finally:
            self.module.subprocess.run = original_run

    def test_delete_asset_raises_on_subprocess_failure(self):
        original_run = self.module.subprocess.run
        try:
            def fake_run(cmd, capture_output, text):
                class Result:
                    returncode = 1
                    stdout = ""
                    stderr = "delete failed"
                return Result()

            self.module.subprocess.run = fake_run
            with self.assertRaisesRegex(RuntimeError, "delete failed"):
                self.module.delete_asset("btxchain/btx-node", 7, "token")
        finally:
            self.module.subprocess.run = original_run


if __name__ == "__main__":
    unittest.main()
