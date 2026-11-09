#!/usr/bin/env python3
"""Unit coverage for scripts/release/package_release_archive.py."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock


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
        # Text fixtures do not exercise ELF editing; native loader coverage below does.
        self.module.set_linux_guard_runpath = lambda path: None

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
                self.assertIn("btx-29.2/contrib/modelnet/btx-model", names)
                self.assertIn("btx-29.2/doc/modelnet/registry-independence.md", names)
                self.assertIn("btx-29.2/doc/release-notes/release-notes-0.34.9-dev.md", names)

                wrapper = archive.extractfile("btx-29.2/bin/btxd")
                assert wrapper is not None
                wrapper_text = wrapper.read().decode("utf-8")
                self.assertIn("missing runtime libraries", wrapper_text)
                self.assertIn("objdump -T", wrapper_text)
                self.assertIn("GLIBCXX", wrapper_text)
                self.assertIn("BTX_GLIBC_PREFIX", wrapper_text)
                self.assertIn("libgomp1", wrapper_text)
                self.assertIn("OPENSSL", wrapper_text)
                self.assertIn("LIB_DIR", wrapper_text)

    def test_require_gui_rejects_archive_without_btx_qt(self):
        self._stub_ship_gate()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_root = self._build_source_root(root)
            btxd, btx_cli = self._write_binaries(root)
            with self.assertRaises(FileNotFoundError):
                self.module.main(
                    [
                        "--output-dir",
                        str(root / "out"),
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
                        "--require-gui",
                    ]
                )

    def test_linux_guard_remains_a_regular_daemon_sibling_after_extraction(self):
        self._stub_ship_gate()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_root = self._build_source_root(root)
            btxd, btx_cli = self._write_binaries(root)
            guard_bytes = b"guard executable\n"
            (root / "btx-guardd").write_bytes(guard_bytes)
            original_epoch = os.environ.get("SOURCE_DATE_EPOCH")
            os.environ["SOURCE_DATE_EPOCH"] = "1712534400"
            try:
                for platform_id in ("linux-x86_64", "linux-arm64"):
                    archives = []
                    for attempt in ("first", "second"):
                        staged, included, _ = self.module.stage_release_tree(
                            version="29.2", platform_id=platform_id,
                            btxd_path=btxd, btx_cli_path=btx_cli, btx_util_path=None,
                            matmul_metallib_path=None, oracle_metallib_path=None,
                            metal_lib_dir=None, source_root=source_root,
                            temp_root=root / platform_id / attempt,
                        )
                        sibling = staged / "libexec/btx-guardd"
                        real_guard = staged / "libexec/btx-guardd.real"
                        self.assertTrue(sibling.is_file())
                        self.assertFalse(sibling.is_symlink())
                        self.assertTrue(sibling.samefile(real_guard))
                        self.assertIn("libexec/btx-guardd", included)
                        self.assertEqual(sibling.read_bytes(), guard_bytes)
                        self.assertEqual(sibling.stat().st_mode & 0o777, 0o755)
                        self.assertEqual(
                            (staged / "bin/btx-guardd").read_text(),
                            self.module.wrapper_payload("btx-guardd", platform_id),
                        )
                        archive_path = root / platform_id / (attempt + ".tar.gz")
                        self.module.write_tar_gz(archive_path, staged)
                        archives.append(archive_path.read_bytes())
                        extracted = root / platform_id / (attempt + "-extracted")
                        with tarfile.open(archive_path) as archive:
                            # This fixture generated every member above; retain
                            # support for Python versions before data_filter.
                            options = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
                            archive.extractall(extracted, **options)
                        for name in ("btx-guardd", "btx-guardd.real"):
                            actual = extracted / "btx-29.2/libexec" / name
                            self.assertTrue(actual.is_file())
                            self.assertFalse(actual.is_symlink())
                            self.assertEqual(actual.read_bytes(), guard_bytes)
                            self.assertEqual(actual.stat().st_mode & 0o777, 0o755)
                    self.assertEqual(archives[0], archives[1])
            finally:
                if original_epoch is None:
                    os.environ.pop("SOURCE_DATE_EPOCH", None)
                else:
                    os.environ["SOURCE_DATE_EPOCH"] = original_epoch

    def test_qt_only_wrapper_uses_private_libraries(self):
        qt = self.module.wrapper_payload("btx-qt", "linux-x86_64")
        self.assertIn('LD_LIBRARY_PATH="$SELF_DIR/../lib/qt-private:$LIB_DIR', qt)
        self.assertIn('PLUGIN_DIR="$SELF_DIR/../lib/qt-private/qt6/plugins"', qt)
        for name in ("btxd", "btx-atlas", "btx-guardd"):
            self.assertNotIn("qt-private", self.module.wrapper_payload(name, "linux-x86_64"))

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("cc") and shutil.which("patchelf"),
                         "native Linux ELF tools required")
    def test_direct_guard_and_qt_keep_shared_and_private_dependencies(self):
        setter = getattr(self.module, "set_linux_guard_runpath", None)
        self._stub_ship_gate()
        if setter is not None:
            self.module.set_linux_guard_runpath = setter
        bundle_path = SCRIPT_PATH.with_name("bundle_qt_gui.py")
        spec = importlib.util.spec_from_file_location("native_bundle_fixture", bundle_path)
        bundle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bundle)
        self.module._load_qt_bundle = lambda: bundle
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_root = self._build_source_root(root)
            btxd, cli = self._write_binaries(root)
            buildlib = root / "buildlib"; buildlib.mkdir()
            plugins = root / "plugins"; (plugins / "platforms").mkdir(parents=True)
            def library(name, code, deps=()):
                c = root / (name + ".c"); c.write_text(code)
                target = buildlib / name
                subprocess.run(["cc", "-shared", "-fPIC", str(c), "-L" + str(buildlib),
                                *["-l:" + d for d in deps], "-Wl,-soname," + name,
                                "-Wl,-rpath,$ORIGIN", "-o", str(target)], check=True)
                return target
            library("libbtxsharedchild.so.1", "int child(void) { return 17; }\n")
            library("libbtxshared.so.1", "extern int child(void); int shared(void) { return child(); }\n",
                    ["libbtxsharedchild.so.1"])
            library("libbtxprivate.so.1", "int private_value(void) { return 4; }\n")
            qt = library("libQt6Core.so.6", "extern int shared(void), private_value(void); int qt_value(void) { return shared()+private_value(); }\n",
                         ["libbtxshared.so.1", "libbtxprivate.so.1"])
            plugin = library("libqxcb.so", "extern int qt_value(void); int plugin(void) { return qt_value(); }\n", [qt.name])
            shutil.copy2(plugin, plugins / "platforms/libqxcb.so")
            subprocess.run(["patchelf", "--set-rpath", str(buildlib), str(plugins / "platforms/libqxcb.so")], check=True)
            bundle._qt_plugins_root = lambda: plugins
            for name, code, dep in (("btx-guardd", "extern int shared(void); int main(void) { return shared()==17 ? 0 : 2; }\n", "libbtxshared.so.1"),
                                    ("btx-qt", "extern int qt_value(void); int main(void) { return qt_value()==21 ? 0 : 3; }\n", qt.name)):
                c = root / (name + ".c");c.write_text(code)
                subprocess.run(["cc", str(c), "-L" + str(buildlib), "-l:" + dep,
                                "-Wl,-rpath," + (str(buildlib) if name == "btx-qt" else "$ORIGIN/buildlib"), "-Wl,-rpath-link," + str(buildlib),
                                "-o", str(root / name)], check=True)
            # Text daemon/CLI fixtures have no ELF dependencies. Do not fake the Qt/guard graphs.
            actual_ldd, actual_needed = bundle._ldd_map, getattr(bundle, "_needed", lambda path: set())
            text_fixtures = (btxd, cli, root / "btx-util")
            bundle._needed = lambda path: set() if path in text_fixtures else actual_needed(path)
            bundle._ldd_map = lambda path, *args: {} if path in text_fixtures else actual_ldd(path, *args)
            staged, _, _ = self.module.stage_release_tree(
                version="29.2", platform_id="linux-x86_64", btxd_path=btxd, btx_cli_path=cli,
                btx_util_path=None, matmul_metallib_path=None, oracle_metallib_path=None,
                metal_lib_dir=None, source_root=source_root, temp_root=root / "staged")
            guard = staged / "libexec/btx-guardd"
            self.assertTrue(guard.samefile(staged / "libexec/btx-guardd.real"))
            for name in ("libbtxshared.so.1", "libbtxsharedchild.so.1"):
                self.assertTrue((staged / "lib" / name).is_file())
            clean_env = {k: v for k, v in os.environ.items() if not k.startswith("LD_")}
            for binary in (guard, staged / "libexec/btx-qt.real"):
                result = subprocess.run([str(binary)], env=clean_env, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertTrue((staged / "lib/qt-private/libbtxprivate.so.1").is_file())
            self.assertFalse((staged / "lib/libbtxprivate.so.1").exists())
            archive = root / "guard.tar.gz"
            self.module.write_tar_gz(archive, staged)
            with tarfile.open(archive) as tar:
                options = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
                tar.extractall(root / "restored", **options)
            restored = root / "restored/btx-29.2/libexec/btx-guardd"
            self.assertFalse(restored.is_symlink())
            self.assertTrue(restored.samefile(restored.with_name("btx-guardd.real")))
            self.assertEqual(subprocess.run([str(restored)], env=clean_env, capture_output=True, timeout=5).returncode, 0)

    def test_require_model_helpers_rejects_archive_without_them(self):
        self._stub_ship_gate()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source_root = self._build_source_root(root)
            btxd, btx_cli = self._write_binaries(root)
            argv = ["--output-dir", str(root / "out"), "--version", "29.2",
                    "--platform-id", "linux-x86_64", "--btxd", str(btxd),
                    "--btx-cli", str(btx_cli), "--source-root", str(source_root),
                    "--require-model-helpers"]
            (root / "modelnet").mkdir()
            for name in self.module.MODEL_HELPER_BINARIES[:-1]:
                (root / "modelnet" / name).write_text("helper\n", encoding="utf-8")
            with self.assertRaises(FileNotFoundError) as caught:
                self.module.main(argv)
            self.assertIn("btx-matmul-backend-info", str(caught.exception))
            (root / "btx-matmul-backend-info").write_text("helper\n", encoding="utf-8")
            self.assertEqual(self.module.main(argv), 0)

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


def load_bundle_module():
    spec = importlib.util.spec_from_file_location("bundle_qt_gui", ROOT / "scripts/release/bundle_qt_gui.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class BundleQtGuiTest(unittest.TestCase):
    def setUp(self):
        self.module = load_bundle_module()

    def _mac_deploy_fixture(self, diagnostic=""):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        binary = root / "btx-qt"
        binary.write_bytes(b"fixture")
        calls = []
        def invoke(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, "", diagnostic)
        with mock.patch.object(self.module, "_macdeployqt", return_value=pathlib.Path("/qt/bin/macdeployqt")), \
             mock.patch.object(self.module.subprocess, "run", side_effect=invoke), \
             mock.patch.object(self.module.subprocess, "check_call", side_effect=lambda args: calls.append(args)), \
             mock.patch.object(self.module.shutil, "which", return_value=None):
            result = self.module.deploy_macos_qt_app(binary, root / "release", "test")
        return result, calls

    def test_macos_deployment_searches_install_prefix_lib(self):
        result, calls = self._mac_deploy_fixture()
        self.assertTrue(result.is_file())
        self.assertIn("-libpath=/qt/lib", calls[0])

    def test_macos_deployment_rejects_reported_errors_with_zero_exit(self):
        with self.assertRaisesRegex(RuntimeError, "incomplete deployment"):
            self._mac_deploy_fixture("ERROR: Cannot resolve rpath QtSvg.framework\n")

    def test_macos_deployment_allows_ordinary_diagnostics(self):
        result, _ = self._mac_deploy_fixture("WARNING: informational message\n")
        self.assertTrue(result.is_file())

    def _plugin_dependency_recovery_fixture(self, tool_removed_path=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            binary = root / "btx-qt"
            binary.write_bytes(b"fixture")
            calls = []
            def deploy(args, **kwargs):
                calls.append(args)
                if len(calls) == 1:
                    plugin = root / "release/btx-qt.app/Contents/PlugIns/iconengines/plugin.dylib"
                    plugin.parent.mkdir(parents=True)
                    plugin.write_bytes(b"fixture")
                    return subprocess.CompletedProcess(args, 0, "", "ERROR: Cannot resolve rpath QtSvg.framework")
                return subprocess.CompletedProcess(args, 0, "", "")
            with mock.patch.object(self.module, "_macdeployqt", return_value=pathlib.Path("/qt/bin/macdeployqt")), \
                 mock.patch.object(self.module.subprocess, "run", side_effect=deploy), \
                 mock.patch.object(self.module.subprocess, "check_output", side_effect=["", "" if tool_removed_path else "path /qt/lib (offset 12)"]), \
                 mock.patch.object(self.module.subprocess, "check_call") as edit, \
                 mock.patch.object(self.module.shutil, "which", return_value=None):
                self.module.deploy_macos_qt_app(binary, root / "release", "test")
            self.assertEqual(len(calls), 2)
            self.assertIn("-no-plugins", calls[1])
            self.assertTrue(any(arg.startswith("-executable=") for arg in calls[1]))
            self.assertIn("-add_rpath", edit.call_args_list[0].args[0])
            deletes = [c for c in edit.call_args_list if "-delete_rpath" in c.args[0]]
            self.assertEqual(len(deletes), 0 if tool_removed_path else 1)

    def test_macos_plugin_only_frameworks_are_additional_roots(self):
        self._plugin_dependency_recovery_fixture(False)

    def test_macos_deployer_may_remove_temporary_rpath(self):
        self._plugin_dependency_recovery_fixture(True)

    def test_direct_private_dependency_survives_host_branch_cut(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            names = ("btx-qt", "libQt6Core.so.6", "libglib-2.0.so.0", "libshared.so.1", "libhost_only.so.1")
            paths = {n: root / n for n in names}
            for p in paths.values(): p.write_bytes(b"fixture")
            needed = {"btx-qt": ["libQt6Core.so.6", "libshared.so.1"],
                      "libQt6Core.so.6": ["libglib-2.0.so.0", "libshared.so.1"],
                      "libshared.so.1": [], "libglib-2.0.so.0": ["libhost_only.so.1"],
                      "libhost_only.so.1": []}
            # Every ldd response is flattened, including a dependency owned only by host GLib.
            flat = "\n".join(f"{n} => {p} (0x1)" for n, p in paths.items() if n != "btx-qt")
            def print_needed(path): return set(needed[path.name])
            with mock.patch.object(self.module.shutil, "which", return_value="/tool/patchelf"), \
                 mock.patch.object(self.module, "_needed", side_effect=print_needed, create=True), \
                 mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, flat, "")):
                collected = self.module._collect_private_libs([paths["btx-qt"]])
            self.assertEqual(set(collected), {"libQt6Core.so.6", "libshared.so.1"})

    def test_missing_private_dependency_is_still_fatal(self):
        with mock.patch.object(self.module.shutil, "which", return_value="/tool/patchelf"), \
             mock.patch.object(self.module, "_needed", return_value={"libprivate.so.1"}, create=True), \
             mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "libprivate.so.1 => not found\n", "")):
            with self.assertRaisesRegex(RuntimeError, "missing libprivate.so.1"):
                self.module._ldd_map(pathlib.Path("fixture"))

    def test_static_root_does_not_require_dynamic_libraries(self):
        with mock.patch.object(self.module, "_needed", return_value=set(), create=True), \
             mock.patch.object(self.module.subprocess, "run") as ldd:
            self.assertEqual(self.module._ldd_map(pathlib.Path("static-fixture")), {})
        ldd.assert_not_called()

    def test_shared_query_does_not_acquire_unrelated_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            shared = pathlib.Path(tmp) / "libshared.so.1"
            shared.write_bytes(b"fixture")
            flat = f"libshared.so.1 => {shared} (0x1)\nlibunrelated.so.1 => not found\n"
            with mock.patch.object(self.module, "_needed", return_value={"libshared.so.1", "libunrelated.so.1"}, create=True), \
                 mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, flat, "unrelated dependency unavailable")):
                self.assertEqual(self.module._ldd_map(pathlib.Path("fixture"), {"libshared.so.1"}), {"libshared.so.1": shared})
                with self.assertRaises(RuntimeError):
                    self.module._ldd_map(pathlib.Path("fixture"))

    def test_host_desktop_services_are_not_copied(self):
        for name in ("libglib-2.0.so.0", "libgobject-2.0.so.0", "libgio-2.0.so.0", "libgmodule-2.0.so.0", "libgthread-2.0.so.0", "libdbus-1.so.3"):
            with self.subTest(name=name): self.assertTrue(self.module._host_soname(name))
        self.assertFalse(self.module._host_soname("libQt6Core.so.6"))

    def test_private_qt_paths_are_consistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            binary = root / "libexec/btx-qt.real";binary.parent.mkdir();binary.write_bytes(b"qt")
            plugins = root / "builder/plugins"; (plugins / "platforms").mkdir(parents=True)
            (plugins / "platforms/libqxcb.so").write_bytes(b"plugin")
            library = root / "builder/libQt6Core.so.6";library.write_bytes(b"lib")
            with mock.patch.object(self.module, "_ldd_map", return_value={library.name: library}), \
                 mock.patch.object(self.module, "_qt_plugins_root", return_value=plugins), \
                 mock.patch.object(self.module, "_collect_private_libs", return_value={library.name: library}), \
                 mock.patch.object(self.module.subprocess, "check_output", return_value=""), \
                 mock.patch.object(self.module, "_set_rpath") as rpath:
                self.module.bundle_linux_qt(binary, root / "lib/qt-private")
            rpath.assert_any_call(binary, "$ORIGIN/../lib/qt-private:$ORIGIN/../lib")
            config = (binary.parent / "qt.conf").read_text()
            self.assertIn("Plugins = lib/qt-private/qt6/plugins", config)
            self.assertIn("Libraries = lib/qt-private", config)
            self.assertTrue((root / "lib/qt-private/qt6/plugins/platforms/libqxcb.so").is_file())


if __name__ == "__main__":
    unittest.main()
