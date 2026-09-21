#!/usr/bin/env python3
"""Unit coverage for scripts/release/package_release_archive.py."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
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
        btx_util = root / f"btx-util{suffix}"
        btxd.write_text("daemon\n", encoding="utf-8")
        btx_cli.write_text("cli\n", encoding="utf-8")
        btx_util.write_text("util\n", encoding="utf-8")
        return btxd, btx_cli

    def _stub_ship_gate(self):
        self.module.verify_shipped_btxd = lambda path: None
        self.module.verify_shipped_cli = lambda path: None
        self.module.verify_shipped_macos_cli = lambda path: None
        self.module.verify_shipped_helper = lambda path: None

    def test_linux_archive_includes_binaries_and_helpers(self):
        self._stub_ship_gate()
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
                wrapper_text = wrapper.read().decode("utf-8")
                self.assertIn("missing runtime libraries", wrapper_text)
                self.assertIn("objdump -T", wrapper_text)
                self.assertIn("GLIBCXX", wrapper_text)
                self.assertIn("BTX_GLIBC_PREFIX", wrapper_text)

    def test_cuda_archive_names_match_release_platform_ids(self):
        self.assertEqual(
            self.module.archive_filename("0.33.0", "linux-x86_64-cuda12", None),
            "btx-0.33.0-x86_64-linux-gnu-cuda12.tar.gz",
        )
        self.assertEqual(
            self.module.archive_filename("0.33.0", "linux-x86_64-cuda13", None),
            "btx-0.33.0-x86_64-linux-gnu-cuda13.tar.gz",
        )

    def test_windows_archive_uses_zip_and_exe_names(self):
        self._stub_ship_gate()
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
        self._stub_ship_gate()
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
                    btx_util_path=None,
                    matmul_metallib_path=None,
                    oracle_metallib_path=None,
                    metal_lib_dir=None,
                    source_root=source_root,
                    temp_root=root / "temp",
                )

    def test_tarball_is_reproducible_with_source_date_epoch(self):
        self._stub_ship_gate()
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

    def test_ship_target_aliases_share_canonical_triples(self):
        self.assertEqual(
            self.module.archive_filename("0.34.5", "linux-x86_64-cpu", None),
            self.module.archive_filename("0.34.5", "linux-x86_64", None),
        )
        self.assertEqual(
            self.module.archive_filename("0.34.5", "macos-arm64-metal", None),
            self.module.archive_filename("0.34.5", "macos-arm64", None),
        )
        self.assertEqual(
            self.module.archive_filename("0.34.5", "linux-x86_64-cuda12", None),
            "btx-0.34.5-x86_64-linux-gnu-cuda12.tar.gz",
        )
        self.assertEqual(
            self.module.archive_filename("0.34.5", "linux-x86_64-cuda", None),
            self.module.archive_filename("0.34.5", "linux-x86_64-cuda12", None),
        )

    def test_macos_metal_archive_includes_modelnet_helpers_and_metallibs(self):
        self._stub_ship_gate()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_root = self._build_source_root(root)
            btxd, btx_cli = self._write_binaries(root)
            (root / "btx-modeld").write_text("modeld\n", encoding="utf-8")
            (root / "btx-modelcheck").write_text("modelcheck\n", encoding="utf-8")
            (root / "btx-open").write_text("open\n", encoding="utf-8")
            (root / "btx-matmul-backend-info").write_text("backend\n", encoding="utf-8")
            metal_dir = root / "metallibs"
            metal_dir.mkdir()
            (metal_dir / "matmul_accel_kernels.metallib").write_bytes(b"metal")
            (metal_dir / "matmul_v4_rc_rowleaf_gpu_kernels.metallib").write_bytes(b"rowleaf")
            output_dir = root / "out"

            exit_code = self.module.main(
                [
                    "--output-dir",
                    str(output_dir),
                    "--version",
                    "0.34.7",
                    "--platform-id",
                    "macos-arm64-metal",
                    "--btxd",
                    str(btxd),
                    "--btx-cli",
                    str(btx_cli),
                    "--metal-lib-dir",
                    str(metal_dir),
                    "--source-root",
                    str(source_root),
                ]
            )

            self.assertEqual(exit_code, 0)
            archive_path = output_dir / "btx-0.34.7-arm64-apple-darwin.tar.gz"
            self.assertTrue(archive_path.is_file())
            with tarfile.open(archive_path, "r:gz") as archive:
                names = set(archive.getnames())
            self.assertIn("btx-0.34.7/libexec/btx-modeld.real", names)
            self.assertIn("btx-0.34.7/bin/btx-modeld", names)
            self.assertIn("btx-0.34.7/libexec/btx-open.real", names)
            self.assertIn("btx-0.34.7/libexec/btx-matmul-backend-info.real", names)
            self.assertIn("btx-0.34.7/libexec/metal/matmul_accel_kernels.metallib", names)
            self.assertIn(
                "btx-0.34.7/libexec/metal/matmul_v4_rc_rowleaf_gpu_kernels.metallib", names
            )

    def test_verify_shipped_btxd_refuses_unrecognized_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            btxd = pathlib.Path(tmpdir) / "btxd"
            btxd.write_text("daemon\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unrecognized file"):
                self.module.verify_shipped_btxd(btxd)

    def test_verify_shipped_cli_refuses_unrecognized_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cli = pathlib.Path(tmpdir) / "btx-cli"
            cli.write_text("cli\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unrecognized file"):
                self.module.verify_shipped_cli(cli)

    def test_packaging_refuses_text_stub_btxd(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_root = self._build_source_root(root)
            btxd, btx_cli = self._write_binaries(root)
            with self.assertRaisesRegex(RuntimeError, "unrecognized file"):
                self.module.main(
                    [
                        "--output-dir",
                        str(root / "out"),
                        "--version",
                        "0.34.5",
                        "--platform-id",
                        "linux-x86_64-cpu",
                        "--btxd",
                        str(btxd),
                        "--btx-cli",
                        str(btx_cli),
                        "--source-root",
                        str(source_root),
                    ]
                )

    def test_packaging_refuses_btxd_built_without_zmq(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_root = self._build_source_root(root)
            btxd = root / "btxd"
            btx_cli = root / "btx-cli"
            btx_util = root / "btx-util"
            # ELF magic + hidden-arg string, no ENABLE_ZMQ help: 0.33.4.2 CPU shape.
            btxd.write_bytes(b"\x7fELF" + b"\x00" * 12 + b"-zmqpubhashblock\x00")
            btx_cli.write_bytes(b"\x7fELF" + b"\x00" * 16)
            btx_util.write_bytes(b"\x7fELF" + b"\x00" * 16)
            with self.assertRaisesRegex((RuntimeError, Exception), "ENABLE_ZMQ help text"):
                self.module.main(
                    [
                        "--output-dir",
                        str(root / "out"),
                        "--version",
                        "0.34.5",
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

    def _stage_linux_wrapper(self, root: pathlib.Path, *, glibc_sym: str = "GLIBC_2.99") -> pathlib.Path:
        bindir = root / "bin"
        libexec = root / "libexec"
        bindir.mkdir()
        libexec.mkdir()
        wrapper = bindir / "btxd"
        wrapper.write_text(self.module.wrapper_payload("btxd", "linux-x86_64"), encoding="utf-8")
        wrapper.chmod(0o755)
        real = libexec / "btxd.real"
        real.write_bytes(b"#!/bin/sh\necho should-not-run\n" + glibc_sym.encode() + b"\nGLIBCXX_3.4.99\n")
        real.chmod(0o755)
        tools = root / "tools"
        tools.mkdir()
        (tools / "ldd").write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' "
            "'\\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x0)' "
            "'\\tlibstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 (0x0)'\n",
            encoding="utf-8",
        )
        (tools / "getconf").write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = GNU_LIBC_VERSION ]; then echo 'glibc 2.35'; exit 0; fi\n"
            "exit 1\n",
            encoding="utf-8",
        )
        (tools / "ldd").chmod(0o755)
        (tools / "getconf").chmod(0o755)
        return wrapper

    def test_linux_wrapper_payload_checks_version_symbols(self):
        payload = self.module.wrapper_payload("btxd", "linux-x86_64")
        self.assertIsNotNone(payload)
        self.assertIn("objdump -T", payload)
        self.assertIn("GLIBC", payload)
        self.assertIn("GLIBCXX", payload)
        self.assertIn("GNU_LIBC_VERSION", payload)
        self.assertIn("BTX_GLIBC_PREFIX", payload)
        self.assertIn("ldd --version", payload)
        modeld = self.module.wrapper_payload("btx-modeld", "linux-x86_64")
        self.assertIn("objdump -T", modeld)
        self.assertNotIn("libsqlite3-0", modeld)

    def test_linux_wrapper_reports_glibc_version_mismatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            wrapper = self._stage_linux_wrapper(root)
            env = os.environ.copy()
            env["PATH"] = f"{root / 'tools'}:{env.get('PATH', '')}"
            env.pop("BTX_GLIBC_PREFIX", None)
            proc = subprocess.run(
                [str(wrapper), "--version"],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertEqual(proc.returncode, 127)
            self.assertIn("GLIBC_2.99", proc.stderr)
            self.assertIn("2.35", proc.stderr)
            self.assertIn("version nodes", proc.stderr)
            self.assertNotIn("should-not-run", proc.stdout)

    def test_linux_wrapper_honors_btx_glibc_prefix(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            wrapper = self._stage_linux_wrapper(root)
            libdir = root / "glibc" / "usr" / "lib" / "x86_64-linux-gnu"
            libdir.mkdir(parents=True)
            loader = libdir / "ld-linux-x86-64.so.2"
            loader.write_text("#!/bin/sh\nprintf 'loader-ok\\n'\n", encoding="utf-8")
            loader.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{root / 'tools'}:{env.get('PATH', '')}"
            env["BTX_GLIBC_PREFIX"] = str(root / "glibc")
            proc = subprocess.run(
                [str(wrapper), "--version"],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("loader-ok", proc.stdout)


if __name__ == "__main__":
    unittest.main()
