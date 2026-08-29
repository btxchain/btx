#!/usr/bin/env python3
"""Issue 122: the ZMQ release gate must actually fail, on every ship path.

Issues 111 and 122 shipped a Linux CPU tarball with ZMQ silently inert.
A gate nobody has seen fail is not a gate. This file:

  1. Compiles a real ELF named btxd, WITH the ENABLE_ZMQ help string, WITHOUT
     linking libzmq. Runs scripts/release/verify_release_btxd.py on it and
     requires a non-zero exit (ldd does not show libzmq).
  2. Requires the same non-zero failure for an unrecognized (non-ELF) file.
  3. Drops that no-ZMQ ELF into a shippable tarball for each 0.34.5 target
     name (linux-x86_64-cpu, linux-x86_64-cuda12 / the CUDA artifact,
     macos-arm64-metal) and actually invokes the packager, cut, collect,
     publish, and Guix pre-tarball invocation. A skip reads as a failure.

Do not weaken an assertion to make a case pass. A silent skip is how 111
and 122 shipped twice.
"""

from __future__ import annotations

import importlib.util
import io
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
VERIFY = ROOT / "scripts" / "release" / "verify_release_btxd.py"
PACKAGE = ROOT / "scripts" / "release" / "package_release_archive.py"
CUT = ROOT / "scripts" / "release" / "cut_release.py"
CUT_LOCAL = ROOT / "scripts" / "release" / "cut_local_release.py"
COLLECT = ROOT / "scripts" / "release" / "collect_release_assets.py"
PUBLISH = ROOT / "scripts" / "release" / "publish_github_release.py"
GUIX_BUILD = ROOT / "contrib" / "guix" / "libexec" / "build.sh"

# Operator-facing 0.34.5 ship targets. CUDA artifacts are named cuda12/cuda13
# (there is no packager id `linux-x86_64-cuda` without a toolkit version).
SHIP_ARCHIVES = (
    ("linux-x86_64-cpu", "btx-0.34.5-linux-x86_64-cpu.tar.gz"),
    ("linux-x86_64-cpu", "btx-0.34.5-x86_64-linux-gnu.tar.gz"),
    ("linux-x86_64-cuda", "btx-0.34.5-x86_64-linux-gnu-cuda12.tar.gz"),
    ("linux-x86_64-cuda", "btx-0.34.5-x86_64-linux-gnu-cuda13.tar.gz"),
    ("macos-arm64-metal", "btx-0.34.5-macos-arm64-metal.tar.gz"),
    ("macos-arm64-metal", "btx-0.34.5-arm64-apple-darwin.tar.gz"),
)

PACKAGE_PLATFORM_IDS = (
    "linux-x86_64-cpu",
    "linux-x86_64-cuda12",
    "macos-arm64-metal",
)

NOZMQ_SOURCE = r"""
/* Real btxd stand-in: ENABLE_ZMQ help text is present, libzmq is not linked.
   The 0.33.4.2 miss was missing help. This is the other 111/122 shape:
   help compiled in, WITH_ZMQ off / libzmq not on the NEEDED line. */
static const char k_enable_zmq_help[] = "Enable publish hash block";
int main(int argc, char **argv)
{
    (void)k_enable_zmq_help;
    (void)argc;
    (void)argv;
    return 0;
}
"""


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def compile_no_zmq_btxd(dest: pathlib.Path) -> pathlib.Path:
    src = dest.with_suffix(".c")
    src.write_text(NOZMQ_SOURCE, encoding="utf-8")
    proc = subprocess.run(
        ["gcc", "-O0", "-o", str(dest), str(src)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"gcc failed to build no-ZMQ btxd: {proc.stderr or proc.stdout}"
        )
    dest.chmod(0o755)
    return dest


def ldd_names(path: pathlib.Path) -> str:
    proc = subprocess.run(
        ["ldd", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout + proc.stderr


def write_archive_with_real(archive: pathlib.Path, btxd: pathlib.Path) -> None:
    payload = btxd.read_bytes()
    member = "btx-0.34.5/libexec/btxd.real"
    with tarfile.open(archive, "w:gz") as handle:
        info = tarfile.TarInfo(member)
        info.size = len(payload)
        info.mode = 0o755
        handle.addfile(info, io.BytesIO(payload))


class Issue122ZmqReleaseGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = tempfile.TemporaryDirectory(prefix="btx-issue122-nozmq-")
        root = pathlib.Path(cls._tmpdir.name)
        cls.nozmq_btxd = compile_no_zmq_btxd(root / "btxd")
        cls.ldd = ldd_names(cls.nozmq_btxd)
        if "libzmq" in cls.ldd:
            raise RuntimeError(
                f"test fixture is linked to libzmq; cannot prove the fail path: {cls.ldd}"
            )
        cls.cli_elf = root / "btx-cli"
        cls.cli_elf.write_bytes(b"\x7fELF" + b"\x00" * 32)
        cls.util_elf = root / "btx-util"
        cls.util_elf.write_bytes(b"\x7fELF" + b"\x00" * 32)
        cls.verify = load_module("verify_release_btxd_i122", VERIFY)
        cls.package = load_module("package_release_archive_i122", PACKAGE)
        cls.cut = load_module("cut_release_i122", CUT)
        cls.cut_local = load_module("cut_local_release_i122", CUT_LOCAL)
        cls.collect = load_module("collect_release_assets_i122", COLLECT)
        cls.publish = load_module("publish_github_release_i122", PUBLISH)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmpdir.cleanup()

    def test_compiled_no_zmq_btxd_is_elf_without_libzmq(self) -> None:
        self.assertEqual(self.verify.classify(self.nozmq_btxd), "elf")
        self.assertTrue(self.verify.has_enable_zmq_help(self.nozmq_btxd))
        self.assertNotIn("libzmq", self.ldd)
        self.assertIn("libc.so", self.ldd)

    def test_gate_exits_nonzero_on_compiled_btxd_without_zmq(self) -> None:
        """A gate nobody has seen fail is not a gate. This is the live fail."""
        proc = subprocess.run(
            [sys.executable, str(VERIFY), str(self.nozmq_btxd)],
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(
            proc.returncode,
            0,
            "verify_release_btxd.py exited 0 on a real ELF with no libzmq; "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r} ldd={self.ldd!r}",
        )
        self.assertIn(b"FAIL", proc.stderr)
        self.assertIn(b"libzmq", proc.stderr)
        with self.assertRaises(self.verify.VerifyError) as caught:
            self.verify.verify_path_for_ship(self.nozmq_btxd)
        self.assertIn("libzmq", str(caught.exception))
        self.assertEqual(self.verify.main([str(self.nozmq_btxd)]), 1)

    def test_unrecognized_file_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "btxd"
            path.write_text("this is not a binary\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(VERIFY), str(path)],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stderr.decode())
            self.assertIn(b"FAIL", proc.stderr)
            self.assertIn(b"not an ELF", proc.stderr)
            with self.assertRaises(self.verify.VerifyError):
                self.verify.verify_binary(path)
            with self.assertRaisesRegex(RuntimeError, "unrecognized file"):
                self.package.verify_shipped_btxd(path)

    def test_every_ship_archive_name_is_classified_and_gated(self) -> None:
        for target, filename in SHIP_ARCHIVES:
            with self.subTest(target=target, filename=filename):
                info = self.collect.classify_primary_platform_asset(filename)
                self.assertIsNotNone(
                    info,
                    f"FINDING: collect does not classify {filename}; "
                    "verify_staged_primary_archives would skip this artifact",
                )

    def test_cut_collect_publish_and_archive_cli_fail_on_no_zmq_tarball(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = pathlib.Path(tmpdir)
            for target, filename in SHIP_ARCHIVES:
                with self.subTest(target=target, filename=filename):
                    archive = tmp / filename
                    write_archive_with_real(archive, self.nozmq_btxd)

                    proc = subprocess.run(
                        [sys.executable, str(VERIFY), "--archive", str(archive)],
                        capture_output=True,
                        check=False,
                    )
                    self.assertNotEqual(
                        proc.returncode,
                        0,
                        f"--archive {filename} exited 0 on no-ZMQ btxd.real: "
                        f"{proc.stderr.decode()}",
                    )
                    self.assertIn(b"FAIL", proc.stderr)
                    self.assertIn(b"libzmq", proc.stderr)

                    command = self.cut.build_verify_archives_command(ROOT, [archive])
                    self.assertIn(str(VERIFY), command)
                    self.assertIn("--archive", command)
                    cut_proc = subprocess.run(command, capture_output=True, check=False)
                    self.assertNotEqual(
                        cut_proc.returncode,
                        0,
                        f"cut verify command exited 0 for {filename}: "
                        f"{cut_proc.stderr.decode()}",
                    )
                    self.assertIn(b"FAIL", cut_proc.stderr)

                    local_cmd = self.cut_local.build_verify_archives_command(
                        ROOT, [archive]
                    )
                    local_proc = subprocess.run(
                        local_cmd, capture_output=True, check=False
                    )
                    self.assertNotEqual(
                        local_proc.returncode,
                        0,
                        f"cut_local verify exited 0 for {filename}: "
                        f"{local_proc.stderr.decode()}",
                    )

                    with self.assertRaises(Exception) as caught:
                        self.collect.verify_staged_primary_archives(
                            [("staged", archive)]
                        )
                    self.assertIn("libzmq", str(caught.exception))

                    info = self.collect.classify_primary_platform_asset(filename)
                    self.assertIsNotNone(info, filename)
                    bundle = tmp / f"bundle-{filename}"
                    bundle.mkdir()
                    staged = bundle / filename
                    staged.write_bytes(archive.read_bytes())
                    manifest = {
                        "platform_assets": {
                            info["platform_id"]: {"asset_name": filename}
                        }
                    }
                    with self.assertRaisesRegex(RuntimeError, "ZMQ/release gate failed"):
                        self.publish.verify_bundle_btxd_archives(bundle, manifest)

    def test_native_packager_fails_closed_for_all_three_platform_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = pathlib.Path(tmpdir)
            for platform_id in PACKAGE_PLATFORM_IDS:
                with self.subTest(platform_id=platform_id):
                    with self.assertRaisesRegex(
                        (RuntimeError, Exception), "libzmq"
                    ):
                        self.package.main(
                            [
                                "--output-dir",
                                str(tmp / f"out-{platform_id}"),
                                "--version",
                                "0.34.5",
                                "--platform-id",
                                platform_id,
                                "--btxd",
                                str(self.nozmq_btxd),
                                "--btx-cli",
                                str(self.cli_elf),
                                "--btx-util",
                                str(self.util_elf),
                                "--source-root",
                                str(ROOT),
                            ]
                        )

    def test_guix_invokes_the_same_gate_before_every_host_tarball(self) -> None:
        text = GUIX_BUILD.read_text(encoding="utf-8")
        self.assertIn("assert_shipped_btxd_has_zmq()", text)
        self.assertIn("verify_release_btxd.py", text)
        # The call sits after support-file copy and before the HOST tarball
        # case (linux / darwin / mingw). It is not inside a CPU-only branch.
        call_at = text.find("\n        assert_shipped_btxd_has_zmq\n")
        self.assertGreater(call_at, 0, "Guix never calls assert_shipped_btxd_has_zmq")
        before = text[:call_at]
        after = text[call_at:]
        self.assertIn("assert_no_dynamic_cuda_runtime_dependencies", before)
        self.assertIn('case "$HOST" in', after)
        self.assertIn("*linux*)", after)
        self.assertIn("*darwin*)", after)
        self.assertIn("*mingw*)", after)
        tarball = after.find("tar --create")
        zipball = after.find("zip -X@")
        self.assertGreater(tarball, 0)
        self.assertGreater(zipball, 0)
        self.assertIn("GUIX_LINUX_FLAVOR", text)
        # Same function for cpu and cuda flavors; flavor is only printed.
        fn = re.search(
            r"assert_shipped_btxd_has_zmq\(\) \{.*?\n\}",
            text,
            flags=re.S,
        )
        self.assertIsNotNone(fn)
        body = fn.group(0)
        self.assertIn("verify_release_btxd.py", body)
        self.assertNotIn("if [ \"$GUIX_LINUX_FLAVOR\" = cpu ]", body)
        # Guix invokes the CLI the same way we just proved fails:
        proc = subprocess.run(
            [sys.executable, str(VERIFY), str(self.nozmq_btxd)],
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"FAIL", proc.stderr)

    def test_cut_refuses_an_empty_archive_set(self) -> None:
        with self.assertRaisesRegex(ValueError, "no primary archives"):
            self.cut.build_verify_archives_command(ROOT, [])
        with self.assertRaisesRegex(ValueError, "no primary archives"):
            self.cut_local.build_verify_archives_command(ROOT, [])

    def test_cut_primary_outputs_cover_cpu_cuda_and_metal(self) -> None:
        outputs = set(self.cut.PRIMARY_GUIX_OUTPUTS)
        self.assertIn("x86_64-linux-gnu", outputs)
        self.assertIn("x86_64-linux-gnu-cuda12", outputs)
        self.assertIn("x86_64-linux-gnu-cuda13", outputs)
        self.assertIn("arm64-apple-darwin", outputs)
        for host in (
            "x86_64-linux-gnu",
            "x86_64-linux-gnu-cuda12",
            "arm64-apple-darwin",
        ):
            self.assertIn(host, self.cut.PRIMARY_HOST_PATTERNS)


if __name__ == "__main__":
    unittest.main()
