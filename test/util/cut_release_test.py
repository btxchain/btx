#!/usr/bin/env python3
"""Unit coverage for scripts/release/cut_release.py."""

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
SCRIPT_PATH = ROOT / "scripts" / "release" / "cut_release.py"


def load_module():
    spec = importlib.util.spec_from_file_location("cut_release", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CutReleaseTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def _create_primary_guix_outputs(
        self,
        repo_root: pathlib.Path,
        tag: str,
    ) -> tuple[pathlib.Path, dict[str, pathlib.Path]]:
        version = self.module.derive_version_from_tag(tag)
        output_dir = repo_root / f"guix-build-{self.module.derive_version_from_tag(tag)}" / "output"
        primary_assets: dict[str, pathlib.Path] = {}
        file_names = {
            "x86_64-linux-gnu": f"bitcoin-{version}-x86_64-linux-gnu.tar.gz",
            "aarch64-linux-gnu": f"bitcoin-{version}-aarch64-linux-gnu.tar.gz",
            "x86_64-w64-mingw32": f"bitcoin-{version}-win64-pgpverifiable.zip",
            "x86_64-apple-darwin": f"bitcoin-{version}-x86_64-apple-darwin-unsigned.tar.gz",
            "arm64-apple-darwin": f"bitcoin-{version}-arm64-apple-darwin-unsigned.tar.gz",
        }
        for host in self.module.PRIMARY_GUIX_HOSTS:
            host_dir = output_dir / host
            host_dir.mkdir(parents=True, exist_ok=True)
            asset_path = host_dir / file_names[host]
            asset_path.write_text(f"{host}\n", encoding="utf-8")
            primary_assets[host] = asset_path

        # Extra Guix artifacts should not become primary platform assets.
        (output_dir / "x86_64-linux-gnu" / f"bitcoin-{version}-x86_64-linux-gnu-debug.tar.gz").write_text(
            "debug\n",
            encoding="utf-8",
        )
        (output_dir / "x86_64-apple-darwin" / f"bitcoin-{version}-x86_64-apple-darwin-unsigned.zip").write_text(
            "zip\n",
            encoding="utf-8",
        )
        return output_dir, primary_assets

    def test_default_guix_output_dir_follows_release_tag(self):
        repo_root = pathlib.Path("/tmp/btx-node")
        output_dir = self.module.default_guix_output_dir(repo_root, "v29.2")
        self.assertEqual(output_dir, repo_root / "guix-build-29.2" / "output")

    def test_main_stages_existing_outputs_and_auto_discovers_attestations(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            repo_root = root / "btx-node"
            repo_root.mkdir()
            output_dir, primary_assets = self._create_primary_guix_outputs(repo_root, "v29.2")
            attestations_dir = root / "guix.sigs" / "29.2" / "alice"
            attestations_dir.mkdir(parents=True)
            (attestations_dir / "noncodesigned.SHA256SUMS").write_text("attest\n", encoding="utf-8")

            commands: list[list[str]] = []
            original_run_checked = self.module.run_checked
            try:
                self.module.run_checked = lambda command, **kwargs: commands.append(command)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    exit_code = self.module.main(
                        [
                            "--repo-root",
                            str(repo_root),
                            "--tag",
                            "v29.2",
                            "--bundle-dir",
                            str(root / "bundle"),
                        ]
                    )
            finally:
                self.module.run_checked = original_run_checked

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(commands), 2)
            collect_command = commands[0]
            self.assertEqual(collect_command[0], sys.executable)
            self.assertTrue(
                collect_command[1].endswith("/scripts/release/collect_release_assets.py")
            )
            self.assertEqual(collect_command[2], "--output-dir")
            for host in self.module.PRIMARY_GUIX_HOSTS:
                self.assertIn(str(primary_assets[host].resolve()), collect_command)
            self.assertNotIn(
                str((output_dir / "x86_64-linux-gnu" / "bitcoin-29.2-x86_64-linux-gnu-debug.tar.gz").resolve()),
                collect_command,
            )
            self.assertNotIn(
                str((output_dir / "x86_64-apple-darwin" / "bitcoin-29.2-x86_64-apple-darwin-unsigned.zip").resolve()),
                collect_command,
            )
            self.assertIn("--attestations-dir", collect_command)
            self.assertIn(str((root / "guix.sigs" / "29.2").resolve()), collect_command)
            self.assertIn("--dry-run", commands[1])

            summary = json.loads(output.getvalue())
            self.assertEqual(summary["guix_output_dir"], str(output_dir.resolve()))
            self.assertEqual(
                summary["primary_archives"],
                [str(primary_assets[host].resolve()) for host in self.module.PRIMARY_GUIX_HOSTS],
            )
            self.assertEqual(summary["attestations_dir"], [str((root / "guix.sigs" / "29.2").resolve())])
            self.assertEqual(summary["published"], False)

    def test_main_generates_snapshot_and_publishes_release(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            repo_root = root / "btx-node"
            repo_root.mkdir()
            _, primary_assets = self._create_primary_guix_outputs(repo_root, "v29.2")

            commands: list[list[str]] = []
            original_run_checked = self.module.run_checked
            try:
                self.module.run_checked = lambda command, **kwargs: commands.append(command)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    exit_code = self.module.main(
                        [
                            "--repo-root",
                            str(repo_root),
                            "--tag",
                            "v29.2",
                            "--bundle-dir",
                            str(root / "bundle"),
                            "--generate-snapshot",
                            "--rollback",
                            "60776",
                            "--btx-cli",
                            str(repo_root / "build-btx" / "bin" / "btx-cli"),
                            "--rpc-arg=-datadir=/srv/btx-main",
                            "--token-file",
                            str(root / "github.key"),
                            "--publish",
                        ]
                    )
            finally:
                self.module.run_checked = original_run_checked

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(commands), 4)
            self.assertIn("generate_assumeutxo.py", commands[0][1])
            self.assertIn("--rollback", commands[0])
            self.assertIn("collect_release_assets.py", commands[1][1])
            for host in self.module.PRIMARY_GUIX_HOSTS:
                self.assertIn(str(primary_assets[host].resolve()), commands[1])
            self.assertIn("--dry-run", commands[2])
            self.assertIn("--publish", commands[3])
            self.assertNotIn("--dry-run", commands[3])

            summary = json.loads(output.getvalue())
            self.assertTrue(summary["snapshot"].endswith("release-artifacts/29.2/snapshot/snapshot.dat"))
            self.assertTrue(summary["snapshot_manifest"].endswith("release-artifacts/29.2/snapshot/snapshot.manifest.json"))
            self.assertTrue(summary["snapshot_report"].endswith("release-artifacts/29.2/snapshot/snapshot.report.json"))
            self.assertEqual(summary["published"], True)

    def test_main_rejects_half_provided_snapshot_pair(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            repo_root = root / "btx-node"
            repo_root.mkdir()
            self._create_primary_guix_outputs(repo_root, "v29.2")

            with self.assertRaisesRegex(ValueError, "must be provided together"):
                self.module.main(
                    [
                        "--repo-root",
                        str(repo_root),
                        "--tag",
                        "v29.2",
                        "--bundle-dir",
                        str(root / "bundle"),
                        "--snapshot",
                        str(root / "snapshot.dat"),
                    ]
                )

    def test_main_runs_agent_setup_smoke_install_when_requested(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            repo_root = root / "btx-node"
            repo_root.mkdir()
            _, primary_assets = self._create_primary_guix_outputs(repo_root, "v29.2")

            commands: list[list[str]] = []
            original_run_checked = self.module.run_checked
            try:
                self.module.run_checked = lambda command, **kwargs: commands.append(command)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    exit_code = self.module.main(
                        [
                            "--repo-root",
                            str(repo_root),
                            "--tag",
                            "v29.2",
                            "--bundle-dir",
                            str(root / "bundle"),
                            "--smoke-platform",
                            "linux-x86_64",
                        ]
                    )
            finally:
                self.module.run_checked = original_run_checked

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(commands), 3)
            self.assertIn("collect_release_assets.py", commands[0][1])
            for host in self.module.PRIMARY_GUIX_HOSTS:
                self.assertIn(str(primary_assets[host].resolve()), commands[0])
            self.assertIn("--dry-run", commands[1])
            self.assertIn("btx-agent-setup.py", commands[2][1])
            self.assertIn("--platform", commands[2])
            self.assertIn("linux-x86_64", commands[2])
            self.assertIn("--force", commands[2])
            self.assertIn("--json", commands[2])

            summary = json.loads(output.getvalue())
            self.assertEqual(summary["smoke_platform"], "linux-x86_64")
            self.assertTrue(summary["smoke_install_dir"].endswith("bundle-smoke-linux-x86_64"))


if __name__ == "__main__":
    unittest.main()
