#!/usr/bin/env python3
"""Unit coverage for scripts/release/package_release_archive.py."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import tarfile
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "release" / "package_release_archive.py"


def load_module():
    spec = importlib.util.spec_from_file_location("package_release_archive", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PackageReleaseArchiveTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def _build_source_root(self, root: pathlib.Path) -> pathlib.Path:
        source_root = root / "source-root"
        for relative_path in self.module.SUPPORT_FILES:
            path = source_root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{relative_path}\n", encoding="utf-8")
        return source_root

    def _write_binaries(self, root: pathlib.Path, *, windows: bool = False) -> tuple[pathlib.Path, pathlib.Path]:
        suffix = ".exe" if windows else ""
        btxd = root / f"btxd{suffix}"
        btx_cli = root / f"btx-cli{suffix}"
        btxd.write_text("daemon\n", encoding="utf-8")
        btx_cli.write_text("cli\n", encoding="utf-8")
        return btxd, btx_cli

    def test_linux_archive_includes_binaries_and_helpers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_root = self._build_source_root(root)
            btxd, btx_cli = self._write_binaries(root)
            output_dir = root / "out"

            exit_code = self.module.main(
                [
                    "--output-dir",
                    str(output_dir),
                    "--version",
                    "29.2",
                    "--platform-id",
                    "linux-x86_64",
                    "--btxd",
                    str(btxd),
                    "--btx-cli",
                    str(btx_cli),
                    "--source-root",
                    str(source_root),
                ]
            )

            self.assertEqual(exit_code, 0)
            archive_path = output_dir / "btx-29.2-x86_64-linux-gnu.tar.gz"
            self.assertTrue(archive_path.is_file())
            with tarfile.open(archive_path, "r:gz") as archive:
                names = set(archive.getnames())
                self.assertIn("btx-29.2/bin/btxd", names)
                self.assertIn("btx-29.2/bin/btx-cli", names)
                self.assertIn("btx-29.2/libexec/btxd.real", names)
                self.assertIn("btx-29.2/libexec/btx-cli.real", names)
                self.assertIn("btx-29.2/contrib/faststart/btx-faststart.py", names)
                self.assertIn("btx-29.2/contrib/mining/start-live-mining.sh", names)
                self.assertIn("btx-29.2/doc/btx-download-and-go.md", names)

                wrapper = archive.extractfile("btx-29.2/bin/btxd")
                assert wrapper is not None
                self.assertIn("missing runtime libraries", wrapper.read().decode("utf-8"))

    def test_windows_archive_uses_zip_and_exe_names(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_root = self._build_source_root(root)
            btxd, btx_cli = self._write_binaries(root, windows=True)
            output_dir = root / "out"

            exit_code = self.module.main(
                [
                    "--output-dir",
                    str(output_dir),
                    "--version",
                    "29.2",
                    "--platform-id",
                    "windows-x86_64",
                    "--btxd",
                    str(btxd),
                    "--btx-cli",
                    str(btx_cli),
                    "--source-root",
                    str(source_root),
                ]
            )

            self.assertEqual(exit_code, 0)
            archive_path = output_dir / "btx-29.2-x86_64-w64-mingw32.zip"
            self.assertTrue(archive_path.is_file())
            with zipfile.ZipFile(archive_path) as archive:
                names = set(archive.namelist())
            self.assertIn("btx-29.2/bin/btxd.exe", names)
            self.assertIn("btx-29.2/bin/btx-cli.exe", names)
            self.assertIn("btx-29.2/contrib/faststart/btx-agent-setup.py", names)

    def test_stage_release_tree_rejects_missing_support_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_root = root / "source-root"
            source_root.mkdir()
            btxd, btx_cli = self._write_binaries(root)

            with self.assertRaises(FileNotFoundError):
                self.module.stage_release_tree(
                    version="29.2",
                    platform_id="linux-x86_64",
                    btxd_path=btxd,
                    btx_cli_path=btx_cli,
                    source_root=source_root,
                    temp_root=root / "temp",
                )

    def test_tarball_is_reproducible_with_source_date_epoch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_root = self._build_source_root(root)
            btxd, btx_cli = self._write_binaries(root)
            output_a = root / "out-a"
            output_b = root / "out-b"

            original_epoch = os.environ.get("SOURCE_DATE_EPOCH")
            os.environ["SOURCE_DATE_EPOCH"] = "1712534400"
            try:
                self.module.main(
                    [
                        "--output-dir",
                        str(output_a),
                        "--version",
                        "29.2",
                        "--platform-id",
                        "linux-x86_64",
                        "--btxd",
                        str(btxd),
                        "--btx-cli",
                        str(btx_cli),
                        "--source-root",
                        str(source_root),
                    ]
                )
                self.module.main(
                    [
                        "--output-dir",
                        str(output_b),
                        "--version",
                        "29.2",
                        "--platform-id",
                        "linux-x86_64",
                        "--btxd",
                        str(btxd),
                        "--btx-cli",
                        str(btx_cli),
                        "--source-root",
                        str(source_root),
                    ]
                )
            finally:
                if original_epoch is None:
                    os.environ.pop("SOURCE_DATE_EPOCH", None)
                else:
                    os.environ["SOURCE_DATE_EPOCH"] = original_epoch

            archive_a = output_a / "btx-29.2-x86_64-linux-gnu.tar.gz"
            archive_b = output_b / "btx-29.2-x86_64-linux-gnu.tar.gz"
            self.assertEqual(archive_a.read_bytes(), archive_b.read_bytes())


if __name__ == "__main__":
    unittest.main()
