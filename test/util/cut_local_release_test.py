#!/usr/bin/env python3
"""Unit coverage for scripts/release/cut_local_release.py."""

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
SCRIPT_PATH = ROOT / "scripts" / "release" / "cut_local_release.py"


def load_module():
    spec = importlib.util.spec_from_file_location("cut_local_release", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CutLocalReleaseTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def _write_binary_pair(self, root: pathlib.Path, prefix: str) -> tuple[pathlib.Path, pathlib.Path]:
        btxd = root / f"{prefix}-btxd"
        btx_cli = root / f"{prefix}-btx-cli"
        btxd.write_text("daemon\n", encoding="utf-8")
        btx_cli.write_text("cli\n", encoding="utf-8")
        return btxd, btx_cli

    def test_parse_platform_spec_rejects_invalid_shape(self):
        with self.assertRaisesRegex(ValueError, "Invalid --platform-spec"):
            self.module.parse_platform_spec("linux-arm64:/tmp/btxd")

    def test_resolve_platform_specs_rejects_duplicate_platforms(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            btxd, btx_cli = self._write_binary_pair(root, "linux")
            raw = f"linux-arm64;{btxd};{btx_cli}"
            with self.assertRaisesRegex(ValueError, "Duplicate platform ids"):
                self.module.resolve_platform_specs([raw, raw])

    def test_main_packages_collects_smokes_and_publishes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            repo_root = root / "btx-node"
            repo_root.mkdir()
            mac_btxd, mac_btx_cli = self._write_binary_pair(root, "mac")
            linux_btxd, linux_btx_cli = self._write_binary_pair(root, "linux")

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
                            "v29.4.0-native-cli1",
                            "--bundle-dir",
                            str(root / "bundle"),
                            "--platform-spec",
                            f"macos-arm64;{mac_btxd};{mac_btx_cli}",
                            "--platform-spec",
                            f"linux-arm64;{linux_btxd};{linux_btx_cli}",
                            "--smoke-platform",
                            "macos-arm64",
                            "--publish",
                        ]
                    )
            finally:
                self.module.run_checked = original_run_checked

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(commands), 6)
            self.assertIn("package_release_archive.py", commands[0][1])
            self.assertIn("--platform-id", commands[0])
            self.assertIn("macos-arm64", commands[0])
            self.assertIn("package_release_archive.py", commands[1][1])
            self.assertIn("linux-arm64", commands[1])
            self.assertIn("collect_release_assets.py", commands[2][1])
            self.assertIn("--required-platform", commands[2])
            self.assertIn("macos-arm64", commands[2])
            self.assertIn("linux-arm64", commands[2])
            self.assertIn("--dry-run", commands[3])
            self.assertIn("btx-agent-setup.py", commands[4][1])
            self.assertIn("macos-arm64", commands[4])
            self.assertIn("--publish", commands[5])

            summary = json.loads(output.getvalue())
            self.assertEqual(summary["platform_ids"], ["macos-arm64", "linux-arm64"])
            self.assertEqual(summary["smoke_platform"], "macos-arm64")
            self.assertTrue(summary["smoke_install_dir"].endswith("bundle-smoke-macos-arm64"))
            self.assertTrue(summary["published"])


if __name__ == "__main__":
    unittest.main()
