#!/usr/bin/env python3
"""Fail-closed tests for scripts/release/verify_release_btxd.py."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import pathlib
import platform
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release" / "verify_release_btxd.py"
LEGACY_CPU = pathlib.Path.home() / ".cache" / "btx-legacy" / (
    "btx-0.33.4.2-linux-x86_64-cpu.tar.gz"
)


# The three published 0.35.0rc1 archives (#237). Optional: point
# BTX_RC1_ARCHIVE_DIR at a directory holding them to run the real-archive case.
RC1_DIR = pathlib.Path(os.environ.get("BTX_RC1_ARCHIVE_DIR", pathlib.Path.home() / ".cache" / "btx-rc1"))
RC1_SHA384 = {
    "btx-035-linux-x86_64.tar.xz": "8e60db66297146f0b061cab45747b9f01a3e1684a40b78cc2f3b5c4eaf70086cc43a3ef780b3cdb8a45fb7f07e1815c4",
    "btx-035-macos-arm64.tar.xz": "fede7a2cda3e4ca397ea562638944b98fda02385c3721ba0d390d558ab4119295a94a2b4c25e717dd8d630de357a5bb7",
    "btx-035-windows-x86_64.tar.xz": "096ea433e18124be142800e8c743c4676a6d1cef4dfa2a87195c0627246f5d6e638bd303d0333c093cdb5bf2a5f268f8",
}
# The official v0.34.15 macOS archive (sha256 = the release asset digest). Optional.
V0_34_15_DIR = pathlib.Path(os.environ.get("BTX_V0_34_15_ARCHIVE_DIR",
                                           pathlib.Path.home() / ".cache" / "btx-0.34.15"))
V0_34_15_MACOS_SHA256 = "6e1ec111fcfedb6da356e3897d3d224c07396c82b8897a83fdcfa558b781c4a8"
ZMQ_HELP = b"Enable publish hash block"


def load_module():
    spec = importlib.util.spec_from_file_location("verify_release_btxd", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_elf(needed=(), runpath=None, verneed=None, executable=True, extra=b""):
    """Minimal x86-64 ELF with PT_LOAD/PT_DYNAMIC (+PT_INTERP), as ld.so reads it."""
    strtab = bytearray(b"\0")

    def add(text):
        offset = len(strtab)
        strtab.extend(text.encode() + b"\0")
        return offset

    needed_offsets = [add(name) for name in needed]
    runpath_offset = add(runpath) if runpath is not None else None
    needs = [(add(so), [add(v) for v in versions]) for so, versions in (verneed or {}).items()]
    interp = b"/lib64/ld-linux-x86-64.so.2\0" if executable else b""
    phnum = 3 if executable else 2
    interp_off = 64 + 56 * phnum
    strtab_off = interp_off + len(interp)
    verneed_off = (strtab_off + len(strtab) + 7) & ~7
    vn = bytearray()
    for i, (file_off, versions) in enumerate(needs):
        vn += struct.pack("<HHIII", 1, len(versions), file_off, 16,
                          16 + 16 * len(versions) if i + 1 < len(needs) else 0)
        for j, name in enumerate(versions):
            vn += struct.pack("<IHHII", 0, 0, 0, name, 16 if j + 1 < len(versions) else 0)
    dyn_off = verneed_off + len(vn)
    tags = [(1, off) for off in needed_offsets]
    if runpath_offset is not None:
        tags.append((29, runpath_offset))
    tags += [(5, strtab_off), (10, len(strtab))]
    if needs:
        tags += [(0x6FFFFFFE, verneed_off), (0x6FFFFFFF, len(needs))]
    dyn = b"".join(struct.pack("<qQ", t, v) for t, v in tags + [(0, 0)])
    total = dyn_off + len(dyn) + len(extra)
    head = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, phnum, 64, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 0x1000)
    ph += struct.pack("<IIQQQQQQ", 2, 6, dyn_off, dyn_off, dyn_off, len(dyn), len(dyn), 8)
    if executable:
        ph += struct.pack("<IIQQQQQQ", 3, 4, interp_off, interp_off, interp_off, len(interp), len(interp), 1)
    body = head + ph + interp + bytes(strtab)
    body += bytes(verneed_off - len(body)) + bytes(vn) + dyn + extra
    assert len(body) == total
    return body


def make_pe(dlls):
    """PE32+ whose import directory names `dlls`."""
    rva, raw_ptr = 0x1000, 0x200
    table_size = 20 * (len(dlls) + 1)
    names, descriptors = b"", b""
    for dll in dlls:
        descriptors += struct.pack("<IIIII", 0, 0, 0, rva + table_size + len(names), rva)
        names += dll.encode() + b"\0"
    raw = descriptors + bytes(20) + names
    raw += bytes(-len(raw) % 0x200)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 108, 16)
    struct.pack_into("<II", opt, 120, rva, table_size)
    head = b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"PE\0\0"
    head += struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22) + bytes(opt)
    head += struct.pack("<8sIIIIIIHHI", b".idata", len(raw), rva, len(raw), raw_ptr, 0, 0, 0, 0, 0xC0000040)
    return head + bytes(raw_ptr - len(head)) + raw + ZMQ_HELP


def make_macho(defined=(), undefined=(), stabs=(), extra=b""):
    """Thin arm64 Mach-O with one LC_SYMTAB: defined (N_SECT|N_EXT), undefined and stab entries."""
    strtab = bytearray(b"\0")
    entries = b""
    for names, n_type, n_sect in ((defined, 0x0F, 1), (undefined, 0x01, 0), (stabs, 0x24, 1)):
        for name in names:
            entries += struct.pack("<IBBHQ", len(strtab), n_type, n_sect, 0, 0)
            strtab += name.encode() + b"\0"
    symoff = 32 + 24
    stroff = symoff + len(entries)
    count = len(defined) + len(undefined) + len(stabs)
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
    symtab = struct.pack("<IIIIII", 0x2, 24, symoff, count, stroff, len(strtab))
    return header + symtab + entries + bytes(strtab) + extra


def write_tar(archive, files, *, uid=0, uname="root", mode=0o755, dirs=(), links=(), hardlinks=()):
    with tarfile.open(archive, "w:gz") as handle:
        for name in dirs:
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.uid, info.gid, info.uname, info.gname = (
                tarfile.DIRTYPE, mode, uid, uid, uname, uname)
            handle.addfile(info)
        for kind, pairs in ((tarfile.SYMTYPE, links), (tarfile.LNKTYPE, hardlinks)):
            for name, target in pairs:
                info = tarfile.TarInfo(name)
                info.type, info.linkname = kind, target
                handle.addfile(info)
        for name, payload in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.uid, info.gid, info.uname, info.gname = (
                len(payload), mode, uid, uid, uname, uname)
            handle.addfile(info, io.BytesIO(payload))


class VerifyReleaseBtxdTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = load_module()

    def test_text_stub_is_other(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "btxd"
            path.write_text("daemon\n", encoding="utf-8")
            self.assertEqual(self.mod.classify(path), "other")

    def test_legacy_03342_cpu_fails_closed(self) -> None:
        if not LEGACY_CPU.is_file():
            self.skipTest("0.33.4.2 cpu tarball not on this host")
        import tarfile

        with tarfile.open(LEGACY_CPU) as archive, tempfile.TemporaryDirectory() as tmpdir:
            archive.extract("btxd", tmpdir)
            btxd = pathlib.Path(tmpdir) / "btxd"
            self.assertEqual(self.mod.classify(btxd), "elf")
            self.assertFalse(self.mod.has_enable_zmq_help(btxd))
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_btxd(btxd)
            self.assertIn("ENABLE_ZMQ help text", str(caught.exception))

    def test_macho_libzmq_dylib_is_rejected(self) -> None:
        name = b"/opt/homebrew/lib/libzmq.5.dylib\x00"
        name_off = 24
        cmdsize = (name_off + len(name) + 7) & ~7
        lc = struct.pack("<IIIIII", 0xC, cmdsize, name_off, 0, 0, 0) + name
        lc += b"\x00" * (cmdsize - len(lc))
        # 64-bit Mach-O header is 32 bytes (includes reserved).
        header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(lc), 0, 0)
        macho = header + lc
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "btxd"
            path.write_bytes(macho + b"Enable publish hash block")
            self.assertEqual(self.mod.classify(path), "macho")
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_macos(path, require_zmq=True)
            self.assertIn("libzmq", str(caught.exception))

    def test_macho_homebrew_libevent_is_rejected(self) -> None:
        name = b"/opt/homebrew/opt/libevent/lib/libevent_core-2.1.7.dylib\x00"
        name_off = 24
        cmdsize = (name_off + len(name) + 7) & ~7
        lc = struct.pack("<IIIIII", 0xC, cmdsize, name_off, 0, 0, 0) + name
        lc += b"\x00" * (cmdsize - len(lc))
        header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(lc), 0, 0)
        macho = header + lc
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "btxd"
            path.write_bytes(macho + b"Enable publish hash block")
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_macos(path, require_zmq=True)
            self.assertIn("Homebrew", str(caught.exception))
            self.assertIn("libevent", str(caught.exception))

    def test_cli_skips_zmq_help_but_rejects_homebrew(self) -> None:
        name = b"/opt/homebrew/opt/libomp/lib/libomp.dylib\x00"
        name_off = 24
        cmdsize = (name_off + len(name) + 7) & ~7
        lc = struct.pack("<IIIIII", 0xC, cmdsize, name_off, 0, 0, 0) + name
        lc += b"\x00" * (cmdsize - len(lc))
        header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(lc), 0, 0)
        macho = header + lc
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "btx-cli"
            path.write_bytes(macho)
            self.assertFalse(self.mod.requires_zmq(path))
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_binary(path)
            self.assertIn("Homebrew", str(caught.exception))

    def _write_03342_shaped_elf(self, path: pathlib.Path) -> None:
        # ELF magic so classify() is linux; hidden-arg string without the
        # ENABLE_ZMQ help text — the v0.33.3 / v0.33.4.2 CPU tarball shape.
        path.write_bytes(b"\x7fELF" + b"\x00" * 12 + b"-zmqpubhashblock\x00")

    def test_cli_exits_nonzero_on_03342_shaped_elf(self) -> None:
        """The gate is decorative if FAIL prints and the process still exits 0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            btxd = pathlib.Path(tmpdir) / "btxd"
            self._write_03342_shaped_elf(btxd)
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(btxd)],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(
                proc.returncode, 0,
                f"FAIL must be a non-zero exit; stdout={proc.stdout!r} stderr={proc.stderr!r}",
            )
            self.assertIn(b"FAIL", proc.stderr)
            self.assertIn(b"ENABLE_ZMQ help text", proc.stderr)
            self.assertEqual(self.mod.main([str(btxd)]), 1)

    def test_cli_mixed_btxd_fail_cli_pass_still_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            btxd = pathlib.Path(tmpdir) / "btxd"
            cli = pathlib.Path(tmpdir) / "btx-cli"
            self._write_03342_shaped_elf(btxd)
            # Linux btx-cli is portability-only: an ELF with no ZMQ help is OK.
            cli.write_bytes(b"\x7fELF" + b"\x00" * 16)
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(btxd), str(cli)],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stderr.decode())
            combined = proc.stdout + proc.stderr
            last = [ln for ln in combined.splitlines() if ln.strip()][-1]
            self.assertIn(b"FAIL", last)
            self.assertEqual(self.mod.main([str(btxd), str(cli)]), 1)

    def test_cli_legacy_03342_cpu_tarball_exits_nonzero(self) -> None:
        if not LEGACY_CPU.is_file():
            self.skipTest("0.33.4.2 cpu tarball not on this host")
        import tarfile

        with tarfile.open(LEGACY_CPU) as archive, tempfile.TemporaryDirectory() as tmpdir:
            archive.extract("btxd", tmpdir)
            btxd = pathlib.Path(tmpdir) / "btxd"
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(btxd)],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stderr.decode())
            self.assertIn(b"FAIL", proc.stderr)
            self.assertIn(b"ENABLE_ZMQ help text", proc.stderr)

    def test_launch_requires_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            failing = pathlib.Path(tmpdir) / "btxd"
            failing.write_text("#!/bin/sh\necho missing libcublasLt.so.13 >&2\nexit 127\n", encoding="utf-8")
            failing.chmod(0o755)
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_launch(failing)
            self.assertIn("exited 127", str(caught.exception))
            self.assertIn("libcublasLt", str(caught.exception))

            ok = pathlib.Path(tmpdir) / "btxd.ok"
            ok.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            ok.chmod(0o755)
            self.mod.verify_launch(ok)


    def test_shell_wrapper_without_real_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bindir = pathlib.Path(tmpdir) / "bin"
            bindir.mkdir()
            wrapper = bindir / "btxd"
            wrapper.write_text("#!/bin/sh\nexec ../libexec/btxd.real \"$@\"\n", encoding="utf-8")
            wrapper.chmod(0o755)
            self.assertTrue(self.mod.is_shell_wrapper(wrapper))
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.resolve_verify_target(wrapper)
            self.assertIn("libexec", str(caught.exception))
            self.assertIn("wrapper", str(caught.exception).lower())
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(wrapper)],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stderr.decode())
            self.assertIn(b"FAIL", proc.stderr)
            self.assertIn(b"wrapper", proc.stderr.lower())

    def test_shell_wrapper_resolves_to_libexec_real(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            bindir = root / "bin"
            libexec = root / "libexec"
            bindir.mkdir()
            libexec.mkdir()
            wrapper = bindir / "btxd"
            wrapper.write_text("#!/bin/sh\nexec ../libexec/btxd.real \"$@\"\n", encoding="utf-8")
            real = libexec / "btxd.real"
            real.write_bytes(b"\x7fELF" + b"\x00" * 16)
            self.assertEqual(self.mod.resolve_verify_target(wrapper), real)
            self.assertTrue(self.mod.is_daemon(real))
            self.assertTrue(self.mod.requires_zmq(real))

    def test_is_daemon_recognizes_btxd_real(self) -> None:
        self.assertTrue(self.mod.is_daemon(pathlib.Path("libexec/btxd.real")))
        self.assertFalse(self.mod.is_daemon(pathlib.Path("libexec/btx-cli.real")))
        self.assertFalse(self.mod.requires_zmq(pathlib.Path("libexec/btx-cli.real")))

    def test_cli_refuses_unrecognized_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "btxd"
            path.write_text("daemon\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(path)],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stderr.decode())
            self.assertIn(b"FAIL", proc.stderr)
            self.assertIn(b"not an ELF", proc.stderr)
            self.assertEqual(self.mod.main([str(path)]), 1)

    def test_gate_fails_when_handed_btxd_built_without_zmq(self) -> None:
        """A gate nobody has seen fail is not a gate. This is the 111/122 shape."""
        with tempfile.TemporaryDirectory() as tmpdir:
            btxd = pathlib.Path(tmpdir) / "btxd"
            self._write_03342_shaped_elf(btxd)
            self.assertEqual(self.mod.classify(btxd), "elf")
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_path_for_ship(btxd)
            self.assertIn("ENABLE_ZMQ help text", str(caught.exception))
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(btxd)],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stderr.decode())
            self.assertIn(b"FAIL", proc.stderr)
            self.assertEqual(self.mod.main([str(btxd)]), 1)

    def test_gate_fails_when_help_present_but_libzmq_not_linked(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            btxd = pathlib.Path(tmpdir) / "btxd"
            btxd.write_bytes(b"\x7fELF" + b"\x00" * 8 + b"Enable publish hash block")
            with mock.patch.object(self.mod, "elf_needed_ldd", return_value=["libc.so.6"]):
                with self.assertRaises(self.mod.VerifyError) as caught:
                    self.mod.verify_linux(btxd)
                self.assertIn("libzmq", str(caught.exception))
                self.assertEqual(self.mod.main([str(btxd)]), 1)

    def test_libzmq_check_reads_dt_needed_without_ldd(self) -> None:
        # A gate host without ldd (a Mac gating the Linux archive) reads DT_NEEDED.
        with tempfile.TemporaryDirectory() as tmpdir:
            btxd = pathlib.Path(tmpdir) / "btxd"
            with mock.patch.object(self.mod.subprocess, "run", side_effect=FileNotFoundError("ldd")):
                btxd.write_bytes(make_elf(["libzmq.so.5", "libc.so.6"], extra=ZMQ_HELP))
                self.assertEqual(self.mod.verify_binary(btxd), "linux-libzmq")
                btxd.write_bytes(make_elf(["libc.so.6"], extra=ZMQ_HELP))
                with self.assertRaises(self.mod.VerifyError) as caught:
                    self.mod.verify_binary(btxd)
            self.assertIn("NEEDED=['libc.so.6']", str(caught.exception))

    def test_pe_without_zmq_help_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            btxd = pathlib.Path(tmpdir) / "btxd.exe"
            btxd.write_bytes(b"MZ" + b"\x00" * 32 + b"-zmqpubhashblock\x00")
            self.assertEqual(self.mod.classify(btxd), "pe")
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_binary(btxd)
            self.assertIn("ENABLE_ZMQ help text", str(caught.exception))

    def test_macho_without_zmq_help_fails(self) -> None:
        header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "btxd"
            path.write_bytes(header)
            self.assertEqual(self.mod.classify(path), "macho")
            # codesign cannot parse a header-only Mach-O and would fail first on a
            # Mac; test_macos_signature_mismatch_is_rejected covers that step.
            with mock.patch.object(self.mod, "verify_macos_signature"), \
                    self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_macos(path, require_zmq=True)
            self.assertIn("ENABLE_ZMQ help text", str(caught.exception))

    def _write_tar_with_member(self, archive: pathlib.Path, member: str, payload: bytes) -> None:
        with tarfile.open(archive, "w:gz") as handle:
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            handle.addfile(info, io.BytesIO(payload))

    def test_archive_gate_fails_on_btxd_built_without_zmq(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = pathlib.Path(tmpdir) / "btx-0.34.5-x86_64-linux-gnu.tar.gz"
            payload = b"\x7fELF" + b"\x00" * 12 + b"-zmqpubhashblock\x00"
            self._write_tar_with_member(archive, "btx-0.34.5/libexec/btxd.real", payload)
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--archive", str(archive)],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stderr.decode())
            self.assertIn(b"FAIL", proc.stderr)
            self.assertIn(b"ENABLE_ZMQ help text", proc.stderr)
            with self.assertRaises(self.mod.VerifyError):
                self.mod.verify_archive(archive)
            self.assertEqual(self.mod.main(["--archive", str(archive)]), 1)

    def test_archive_gate_fails_on_unreadable_tarball(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = pathlib.Path(tmpdir) / "btx-0.34.5-linux-x86_64-cpu.tar.gz"
            archive.write_bytes(b"not a tarball")
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--archive", str(archive)],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stderr.decode())
            self.assertIn(b"FAIL", proc.stderr)

    def test_glibc_ceiling_rejects_newer_packaged_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            for rel in ("bin/btxd", "bin/btx-qt", "lib/libgnutls.so.30"):
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"x")
            floors = {
                "btxd": {"GLIBC": "2.38"},
                "btx-qt": {"GLIBC": "2.43"},
                "libgnutls.so.30": {"GLIBC": "2.43"},
            }
            with mock.patch.object(
                self.mod, "elf_required_versions", side_effect=lambda p: floors[p.name]
            ):
                with self.assertRaises(self.mod.VerifyError) as ctx:
                    self.mod.verify_glibc_ceiling(root)
                message = str(ctx.exception)
                self.assertIn("btx-qt needs GLIBC_2.43", message)
                self.assertIn("libgnutls.so.30 needs GLIBC_2.43", message)
                self.assertNotIn("btxd needs", message)
                # A ceiling at or above the highest requirement passes.
                self.mod.verify_glibc_ceiling(root, ceiling="2.43")

    def test_macos_signature_mismatch_is_rejected(self) -> None:
        bad = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="invalid signature (code or signature have been modified)"
        )
        with mock.patch.object(self.mod.shutil, "which", return_value="/usr/bin/codesign"), \
                mock.patch.object(self.mod.subprocess, "run", return_value=bad):
            with self.assertRaises(self.mod.VerifyError) as ctx:
                self.mod.verify_macos_signature(pathlib.Path("bin/btxd"))
        self.assertIn("modified after signing", str(ctx.exception))
        good = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with mock.patch.object(self.mod.shutil, "which", return_value="/usr/bin/codesign"), \
                mock.patch.object(self.mod.subprocess, "run", return_value=good):
            self.mod.verify_macos_signature(pathlib.Path("bin/btxd"))
        with mock.patch.object(self.mod.shutil, "which", return_value=None):
            self.mod.verify_macos_signature(pathlib.Path("bin/btxd"))

    def test_cli_requires_binary_or_archive(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"binary or --archive", proc.stderr)


class ArchiveContentGateTest(unittest.TestCase):
    """`--archive` gates the whole archive: the rc1 failure shapes (#237, #235)."""

    def setUp(self) -> None:
        self.mod = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        # ldd cannot trace a synthetic ELF and Darwin has none; DT_NEEDED is what it reports.
        patcher = mock.patch.object(self.mod, "elf_needed_ldd",
                                    side_effect=lambda path: self.mod.elf_dynamic_info(path).needed)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def _btxd(self, runpath=None, openssl="OPENSSL_3.2.0", glibc="GLIBC_2.38"):
        return make_elf(["libssl.so.3", "libzmq.so.5", "libc.so.6"], runpath=runpath,
                        verneed={"libssl.so.3": [openssl], "libc.so.6": [glibc]}, extra=ZMQ_HELP)

    def _libssl(self):
        return make_elf(["libc.so.6"], verneed={"libc.so.6": ["GLIBC_2.34"]}, executable=False)

    def _gate(self, files, **kwargs):
        archive = self.root / "btx-0.35.0-x86_64-linux-gnu.tar.gz"
        tar_kwargs = {k: kwargs.pop(k) for k in ("uid", "uname", "mode", "dirs", "links") if k in kwargs}
        write_tar(archive, files, **tar_kwargs)
        return self.mod.verify_archive(archive, launch=False, **kwargs)

    def _problems(self, files, **kwargs):
        with self.assertRaises(self.mod.VerifyError) as caught:
            self._gate(files, **kwargs)
        return str(caught.exception)

    def test_bundled_libssl_without_runpath_fails(self) -> None:
        text = self._problems({"btx-0.35.0/bin/btxd": self._btxd(),
                               "btx-0.35.0/lib/libssl.so.3": self._libssl()})
        self.assertIn("bin/btxd: no RUNPATH reaches btx-0.35.0/lib", text)
        self.assertIn("libssl.so.3 load instead of the copies this archive ships", text)
        self.assertIn("bin/btxd: needs OPENSSL_3.2.0 from the host's libssl.so.3 (floor OPENSSL_3.0.0)", text)

    def test_bundled_libssl_with_origin_runpath_passes(self) -> None:
        how = self._gate({"btx-0.35.0/bin/btxd": self._btxd(runpath="$ORIGIN/../lib"),
                          "btx-0.35.0/lib/libssl.so.3": self._libssl()})
        self.assertIn("+contents", how)

    def test_packaged_wrapper_reaches_lib_without_runpath(self) -> None:
        wrapper = b'#!/bin/sh\nexec "$SELF_DIR/../libexec/btxd.real" "$@"\n'
        self._gate({"btx-0.35.0/bin/btxd": wrapper,
                    "btx-0.35.0/libexec/btxd.real": self._btxd(),
                    "btx-0.35.0/lib/libssl.so.3": self._libssl()})

    def test_openssl_from_host_above_floor_fails_without_a_bundled_copy(self) -> None:
        text = self._problems({"btx-0.35.0/bin/btxd": self._btxd()})
        self.assertIn("needs OPENSSL_3.2.0 from the host's libssl.so.3", text)
        self._gate({"btx-0.35.0/bin/btxd": self._btxd(openssl="OPENSSL_3.0.0")})

    def test_openssl_floor_is_per_library(self) -> None:
        # Ubuntu 24.04's libssl.so.3 defines only OPENSSL_3.0.0; its libcrypto.so.3
        # defines up to OPENSSL_3.0.9. ld.so looks for a version node only in the
        # library the need names, so OPENSSL_3.0.3 from libssl does not load there
        # although libcrypto has it (bs1812, #247).
        def btxd(ssl, crypto):
            return make_elf(["libssl.so.3", "libcrypto.so.3", "libzmq.so.5"], extra=ZMQ_HELP,
                            verneed={"libssl.so.3": [ssl], "libcrypto.so.3": [crypto]})

        self._gate({"btx-0.35.0/bin/btxd": btxd("OPENSSL_3.0.0", "OPENSSL_3.0.9")})
        text = self._problems({"btx-0.35.0/bin/btxd": btxd("OPENSSL_3.0.3", "OPENSSL_3.0.9")})
        self.assertIn("bin/btxd: needs OPENSSL_3.0.3 from the host's libssl.so.3 (floor OPENSSL_3.0.0)", text)
        self.assertNotIn("libcrypto", text)
        text = self._problems({"btx-0.35.0/bin/btxd": btxd("OPENSSL_3.0.8", "OPENSSL_3.1.0")})
        self.assertIn("bin/btxd: needs OPENSSL_3.1.0 from the host's libcrypto.so.3 (floor OPENSSL_3.0.9), "
                      "OPENSSL_3.0.8 from the host's libssl.so.3 (floor OPENSSL_3.0.0)", text)
        # Any other library that defines OPENSSL_ nodes keeps the family floor.
        other = make_elf(["libother.so.1", "libzmq.so.5"], extra=ZMQ_HELP, verneed={"libother.so.1": ["OPENSSL_3.0.9"]})
        self._gate({"btx-0.35.0/bin/btxd": other})

    def test_floor_option_takes_a_library(self) -> None:
        archive = self.root / "btx-0.35.0-x86_64-linux-gnu.tar.gz"
        write_tar(archive, {"btx-0.35.0/bin/btxd": make_elf(
            ["libssl.so.3", "libzmq.so.5"], extra=ZMQ_HELP, verneed={"libssl.so.3": ["OPENSSL_3.0.3"]})})
        run = ["--no-launch", "--archive", str(archive)]
        with mock.patch("sys.stderr", new_callable=io.StringIO), mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(self.mod.main(run), 1)
            self.assertEqual(self.mod.main(["--floor", "libssl.so.3:OPENSSL=3.0.3"] + run), 0)
            self.assertEqual(self.mod.main(["--floor", "libcrypto.so.3:OPENSSL=3.0.3"] + run), 1)
            # A family value covers every library unless one is named too.
            self.assertEqual(self.mod.main(["--floor", "OPENSSL=3.2.0"] + run), 0)
            self.assertEqual(self.mod.main(["--floor", "OPENSSL=3.2.0", "--floor", "libssl.so.3:OPENSSL=3.0.0"] + run), 1)
            for bad in ("libssl.so.3:GLIBC=2.38", "OPENSSL=3.x", "libssl:OPENSSL=3.0.3", "openssl=3.0.3"):
                with self.assertRaises(SystemExit):
                    self.mod.main(["--floor", bad] + run)

    def test_runpath_must_be_a_literal_origin(self) -> None:
        # The loader expands only $ORIGIN and ${ORIGIN}. A RUNPATH escaped once
        # too often or not at all by the generator reaches nothing (#235 review).
        for good in ("$ORIGIN/../lib", "${ORIGIN}/../lib", "$ORIGIN:$ORIGIN/../lib"):
            self._gate({"btx-0.35.0/bin/btxd": self._btxd(runpath=good, openssl="OPENSSL_3.0.0"),
                        "btx-0.35.0/lib/libssl.so.3": self._libssl()})
        for bad in ("\\$ORIGIN/../lib", "$$ORIGIN/../lib", "ORIGIN/../lib", "/opt/openssl-3.5/lib"):
            text = self._problems({"btx-0.35.0/bin/btxd": self._btxd(runpath=bad, openssl="OPENSSL_3.0.0"),
                                   "btx-0.35.0/lib/libssl.so.3": self._libssl()})
            self.assertIn(f"bin/btxd: RUNPATH {bad} does not reach btx-0.35.0/lib", text)

    def test_host_library_floor_other_than_glibc(self) -> None:
        btxd = make_elf(["libzmq.so.5", "libstdc++.so.6"], extra=ZMQ_HELP,
                        verneed={"libstdc++.so.6": ["GLIBCXX_3.4.33", "CXXABI_1.3.15"]})
        files = {"btx-0.35.0/bin/btxd": btxd}
        text = self._problems(files)
        self.assertIn("bin/btxd: needs GLIBCXX_3.4.33 from the host's libstdc++.so.6 (floor GLIBCXX_3.4.32)", text)
        self.assertNotIn("CXXABI", text)
        self._gate(files, floor=dict(self.mod.DEFAULT_ABI_FLOOR, GLIBCXX="3.4.33"))
        # A copy the archive ships and RUNPATH reaches is gated as its own ELF instead.
        stdcxx = make_elf(["libc.so.6"], executable=False)
        reached = make_elf(["libzmq.so.5", "libstdc++.so.6"], runpath="$ORIGIN/../lib", extra=ZMQ_HELP,
                           verneed={"libstdc++.so.6": ["GLIBCXX_3.4.33"]})
        self._gate({"btx-0.35.0/bin/btxd": reached, "btx-0.35.0/lib/libstdc++.so.6": stdcxx})
        archive = self.root / "btx-0.35.0-x86_64-linux-gnu.tar.gz"
        write_tar(archive, files)
        self.assertEqual(self.mod.main(["--no-launch", "--archive", str(archive)]), 1)
        self.assertEqual(self.mod.main(["--no-launch", "--floor", "GLIBCXX=3.4.33", "--archive", str(archive)]), 0)

    def test_glibc_ceiling_is_reported_with_the_rest_and_blocks_launch(self) -> None:
        files = {"btx-0.35.0/bin/btxd": self._btxd(openssl="OPENSSL_3.0.0"),
                 "btx-0.35.0/lib/libgnutls.so.30": make_elf(["libc.so.6"], executable=False)}
        archive = self.root / "btx-0.35.0-x86_64-linux-gnu.tar.gz"
        write_tar(archive, files, uid=1000, uname="administrator")
        versions = {"btxd": {"GLIBC": "2.38"}, "libgnutls.so.30": {"GLIBC": "2.43"}}
        with mock.patch.object(self.mod, "elf_required_versions",
                               side_effect=lambda p: versions.get(p.name, {})), \
                mock.patch.object(self.mod, "verify_launch") as launch:
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_archive(archive)
        launch.assert_not_called()
        text = str(caught.exception)
        self.assertIn("2 problem(s)", text)
        self.assertIn("lib/libgnutls.so.30 needs GLIBC_2.43", text)
        self.assertIn("not owned by root:root", text)

    def test_glibc_ceiling_without_objdump_or_readelf(self) -> None:
        (self.root / "lib").mkdir()
        gnutls = self._write("lib/libgnutls.so.30",
                             make_elf(["libc.so.6"], verneed={"libc.so.6": ["GLIBC_2.43"]}, executable=False))
        real_run = subprocess.run

        def no_binutils(command, *args, **kwargs):
            if command[0] in ("objdump", "readelf"):
                raise FileNotFoundError(command[0])
            return real_run(command, *args, **kwargs)

        with mock.patch.object(self.mod.subprocess, "run", side_effect=no_binutils):
            self.assertEqual(self.mod.elf_required_versions(gnutls), {"GLIBC": "2.43"})
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_glibc_ceiling(self.root)
        self.assertIn("lib/libgnutls.so.30 needs GLIBC_2.43", str(caught.exception))

    def test_owner_mode_and_empty_directory(self) -> None:
        text = self._problems({"./bin/btxd": self._btxd(openssl="OPENSSL_3.0.0")},
                              uid=1000, uname="administrator", mode=0o775, dirs=("./", "./bin/", "./metal/"))
        self.assertIn("4 of 4 members are not owned by root:root (administrator:administrator)", text)
        self.assertIn("group/world-writable", text)
        self.assertIn("empty directories packed: metal", text)

    def test_unsafe_members_are_refused_before_extraction(self) -> None:
        for files, links, want in (({"../escape": b"x"}, (), "unsafe member name"),
                                   ({}, (("btx/lib", "../../etc"),), "leaves the archive"),
                                   ({}, (("btx/lib", "/etc"),), "leaves the archive"),
                                   ({"btx/lib/passwd": b"x"}, (("btx/lib", "sub"),), "symlinked directory"),
                                   ({}, (("btx/d/l1", ".."), ("btx/d/l2", "l1/../../x")), "after a symlink")):
            archive = self.root / "bad.tar.gz"
            write_tar(archive, files, links=links)
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_archive(archive, launch=False)
            self.assertIn(want, str(caught.exception))
        # Python < 3.12 extracts a hard link to a symlink as that symlink: btx/c -> ..
        # would put btx/c/evil outside. A repeated name replaces the checked copy.
        for links, hardlinks, files, want in (
                ((("btx/d/l1", ".."),), (("btx/c", "btx/d/l1"),), {"btx/c/evil": b"x"}, "does not name a regular file"),
                ((("btx/d/f", ".."),), (), {"btx/d/f": b"x"}, "appears twice")):
            write_tar(archive, files, links=links, hardlinks=hardlinks)
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_archive(archive, launch=False)
            self.assertIn(want, str(caught.exception))
        archive = self.root / "hardlink.tar.gz"  # GNU tar records a second name of one file this way
        with tarfile.open(archive, "w:gz") as handle:
            info = tarfile.TarInfo("btx/bin/btx-cli")
            info.size, info.mode = 1, 0o755
            handle.addfile(info, io.BytesIO(b"x"))
            link = tarfile.TarInfo("btx/bin/bitcoin-cli")
            link.type, link.linkname = tarfile.LNKTYPE, "btx/bin/btx-cli"
            handle.addfile(link)
        self.assertEqual(self.mod.archive_member_problems(archive), [])

    def test_hostile_elf_is_a_fail_not_a_crash(self) -> None:
        # Sizes or offsets past the end of the file, and a version-need table far
        # larger than any real one, are reported; they do not crash or hang the gate.
        lib = make_elf(["libc.so.6"], verneed={"libc.so.6": ["GLIBC_2.34"]}, executable=False)
        for offset, size in ((0x100, 1 << 62), (0x100, (1 << 64) - 1), ((1 << 64) - 16, 16)):
            data = bytearray(lib)
            struct.pack_into("<QQQQ", data, 64 + 56 + 8, offset, offset, offset, size)  # PT_DYNAMIC
            with self.assertRaises(self.mod.VerifyError):
                self.mod.elf_dynamic_info(self._write("lib.so", bytes(data)))
        huge = make_elf(["libc.so.6"], verneed={"libc.so.6": ["GLIBC_2.34"] * 5000}, executable=False)
        text = self._problems({"btx-0.35.0/bin/btxd": self._btxd(openssl="OPENSSL_3.0.0"),
                               "btx-0.35.0/lib/libx.so": huge})
        self.assertIn("lib/libx.so: unreadable ELF: more than 4096 version needs", text)

    def test_require_model_helpers(self) -> None:
        files = {"btx-0.35.0/bin/btxd": self._btxd(openssl="OPENSSL_3.0.0")}
        self._gate(files)
        text = self._problems(files, require_model_helpers=True)
        self.assertIn("model helpers missing: btx-modeld", text)
        helper = make_elf(["libc.so.6"])
        files.update({f"btx-0.35.0/bin/{name}": helper for name in self.mod.MODEL_HELPER_BINARIES})
        self._gate(files, require_model_helpers=True)

    def test_model_helper_list_matches_packager(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "package_release_archive", ROOT / "scripts" / "release" / "package_release_archive.py")
        packager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packager)
        self.assertEqual(tuple(packager.MODEL_HELPER_BINARIES), self.mod.MODEL_HELPER_BINARIES)

    def test_pe_import_must_sit_next_to_the_exe(self) -> None:
        exe = make_pe(["KERNEL32.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "libgomp-1.dll"])
        self.assertEqual(self.mod.pe_imports(self._write("btxd.exe", exe)),
                         ["KERNEL32.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "libgomp-1.dll"])
        text = self._problems({"btx-0.35.0/bin/btxd.exe": exe})
        self.assertIn("bin/btxd.exe: imports libgomp-1.dll, which is neither next to it", text)
        self._gate({"btx-0.35.0/bin/btxd.exe": exe, "btx-0.35.0/bin/libgomp-1.dll": make_pe(["KERNEL32.dll"])})

    def _write(self, name, payload):
        path = self.root / name
        path.write_bytes(payload)
        return path

    def test_macho_mldsa_keygen_must_use_btx_randombytes(self) -> None:
        # 17c2da89: ML-DSA keygen calls btx_mldsa_randombytes. Without it ld kept
        # libsodium's randombytes in the v0.34.15 macOS btxd (#253).
        bad = make_macho(["_main", "_ml_dsa_44_keygen", "_randombytes", "_randombytes_buf"],
                         undefined=["_btx_mldsa_randombytes"], stabs=["_btx_mldsa_randombytes"], extra=ZMQ_HELP)
        btxd = self._write("btxd", bad)
        self.assertEqual(self.mod.macho_defined_symbols(btxd),
                         {"_main", "_ml_dsa_44_keygen", "_randombytes", "_randombytes_buf"})
        with mock.patch.object(self.mod, "verify_macos_signature"):
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_macos(btxd, require_zmq=True)
            self.assertIn("btxd: has ML-DSA keygen but no _btx_mldsa_randombytes", str(caught.exception))
            for ok in (["_ml_dsa_44_keygen", "_btx_mldsa_randombytes", "_randombytes"],  # rc1 btxd
                       ["_randombytes"],  # no ML-DSA keygen (btx-cli)
                       []):  # stripped: nothing to read, the wallet check is the backstop
                self.mod.verify_macos(self._write("btxd", make_macho(ok, extra=ZMQ_HELP)), require_zmq=True)
        no_symtab = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
        self.assertEqual(self.mod.macho_defined_symbols(self._write("btxd", no_symtab)), set())
        with self.assertRaises(self.mod.VerifyError):  # a zero-size load command is refused, not looped on
            self.mod.macho_defined_symbols(self._write("btxd", make_macho()[:32] + bytes(24)))

    def test_archive_checks_every_macho_for_the_randombytes_rename(self) -> None:
        good = make_macho(["_ml_dsa_44_keygen", "_btx_mldsa_randombytes"], extra=ZMQ_HELP)
        bad = make_macho(["_ml_dsa_44_keygen", "_randombytes"], extra=ZMQ_HELP)
        qt = "btx-0.35.0/btx-qt.app/Contents/MacOS/btx-qt"
        archive = self.root / "btx-0.35.0-arm64-apple-darwin.tar.gz"
        with mock.patch.object(self.mod, "verify_macos_signature"):
            write_tar(archive, {"btx-0.35.0/bin/btxd": good, qt: good})
            self.mod.verify_archive(archive, launch=False)
            write_tar(archive, {"btx-0.35.0/bin/btxd": bad, qt: bad})
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_archive(archive, launch=False)
        text = str(caught.exception)
        self.assertIn("2 problem(s)", text)  # btxd's line is not repeated by the btxd pass
        self.assertEqual(text.count("bin/btxd: has ML-DSA keygen but no _btx_mldsa_randombytes"), 1)
        self.assertIn(f"{qt}: has ML-DSA keygen but no _btx_mldsa_randombytes", text)
        truncated = good[:40] + struct.pack("<I", 1 << 30) + good[44:]  # nsyms past the end
        write_tar(archive, {"btx-0.35.0/btx-qt": truncated, "btx-0.35.0/bin/btx-cli": make_macho()})
        with self.assertRaises(self.mod.VerifyError) as caught:
            self.mod.verify_archive(archive, launch=False)
        self.assertIn("btx-qt: unreadable Mach-O: symbol table past the end of the file", str(caught.exception))

    def test_v0_34_15_macos_archive_fails_the_randombytes_checks(self) -> None:
        archive = V0_34_15_DIR / "btx-0.34.15-arm64-apple-darwin.tar.gz"
        if not archive.is_file():
            self.skipTest(f"v0.34.15 macOS archive not in {V0_34_15_DIR} (set BTX_V0_34_15_ARCHIVE_DIR)")
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), V0_34_15_MACOS_SHA256)
        native = sys.platform == "darwin" and platform.machine() == "arm64"
        with self.assertRaises(self.mod.VerifyError) as caught:
            self.mod.verify_archive(archive, launch=False, wallet_check=native)
        text = str(caught.exception)
        for name in ("libexec/btxd.real", "btx-qt.app/Contents/MacOS/btx-qt", "libexec/btx-util.real",
                     "libexec/btx-modeld.real", "libexec/btx-hosted.real", "libexec/btx-hcpd.real"):
            self.assertIn(f"btx-0.34.15/{name}: has ML-DSA keygen but no _btx_mldsa_randombytes", text)
        self.assertEqual(text.count("has ML-DSA keygen"), 6)
        if native:  # the archive's own btxd, run on regtest (MendeMatthias, #247)
            self.assertIn("btx-0.34.15/libexec/btxd.real: index 0 of the new wallet's own private receive "
                          "descriptor derived", text)
        if sys.platform == "darwin" and shutil.which("nm"):
            with tarfile.open(archive) as handle:
                handle.extract("btx-0.34.15/libexec/btxd.real", self.root, **(
                    {"filter": "data"} if sys.version_info >= (3, 12) else {}))
            real = self.root / "btx-0.34.15" / "libexec" / "btxd.real"
            listed = subprocess.run(["nm", "-m", str(real)], capture_output=True, text=True, check=True).stdout
            self.assertEqual(self.mod.macho_defined_symbols(real),
                             {line.split()[-1] for line in listed.splitlines() if " (__" in line})

    def test_bin_layout_launch_gets_no_lib_dir_and_no_host_loader_env(self) -> None:
        for sub in ("bin", "libexec", "lib"):
            (self.root / sub).mkdir()
        (self.root / "lib" / "libssl.so.3").write_bytes(b"x")
        self.assertIsNone(self.mod.packaged_openssl_libdir(self.root / "bin" / "btxd"))
        self.assertEqual(self.mod.packaged_openssl_libdir(self.root / "libexec" / "btxd.real"), self.root / "lib")
        probe = self._write("bin/btxd", b'#!/bin/sh\n[ -z "${LD_LIBRARY_PATH:-}" ]\n')
        probe.chmod(0o755)
        with mock.patch.dict(os.environ, {"LD_LIBRARY_PATH": "/opt/openssl-3.5/lib"}):
            with self.assertRaises(self.mod.VerifyError):
                self.mod.verify_launch(probe)
            self.mod.verify_launch(probe, clean_env=True)

    def test_rc1_archives_fail_for_the_reported_reasons(self) -> None:
        paths = {name: RC1_DIR / name for name in RC1_SHA384}
        if not all(path.is_file() for path in paths.values()):
            self.skipTest(f"0.35.0rc1 archives not in {RC1_DIR} (set BTX_RC1_ARCHIVE_DIR)")
        for name, path in paths.items():
            self.assertEqual(hashlib.sha384(path.read_bytes()).hexdigest(), RC1_SHA384[name], name)
        texts = {}
        for name, path in paths.items():
            with self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_archive(path, launch=False, require_model_helpers=True)
            texts[name] = str(caught.exception)
        linux, macos, windows = (texts[n] for n in RC1_SHA384)
        for want in ("bin/btxd: no RUNPATH reaches lib", "bin/btxd: needs OPENSSL_3.2.0 from the host's libssl.so.3",
                     "not owned by root:root (administrator:administrator)",
                     "empty directories packed: metal", "model helpers missing",
                     "bin/btx-qt needs GLIBC_2.43", "lib/libgnutls.so.30 needs GLIBC_2.43"):
            self.assertIn(want, linux)
        for text in (macos, windows):
            self.assertIn("not owned by root:root", text)
            self.assertIn("model helpers missing", text)
        self.assertNotIn("imports", windows)  # rc1 ships the three MinGW DLLs beside btxd.exe
        self.assertNotIn("has ML-DSA keygen", macos)  # rc1 is built with 17c2da89
        if shutil.which("codesign"):  # verify_macos_signature runs only where codesign exists
            self.assertIn("bin/btxd: codesign --verify --strict failed", macos)
            self.assertEqual(macos.count("codesign --verify --strict failed"), 1)


# A stand-in btxd for --run-wallet-check: regtest-style cookie and JSON-RPC on
# -rpcport. FAKE_BTXD_MODE picks the behaviour; FAKE_BTXD_LOG records argv.
FAKE_BTXD = r'''#!{python}
import base64, http.server, json, os, sys, threading, time
args = sys.argv[1:]
mode = os.environ.get("FAKE_BTXD_MODE", "stable")
with open(os.environ["FAKE_BTXD_LOG"], "a") as fh:
    fh.write(json.dumps({"pid": os.getpid(), "args": args}) + "\n")
opts = dict(a[1:].split("=", 1) for a in args if a.startswith("-") and "=" in a)
if mode == "no-modelnet" and "modelnet" in opts:
    sys.stderr.write("Error: Error parsing command line arguments: Invalid parameter -modelnet=" + opts["modelnet"] + "\n")
    sys.exit(1)
if mode == "exit":
    sys.stderr.write("Error: Unable to start HTTP server.\n")
    sys.exit(1)
if mode == "hang":
    time.sleep(600)
cookie_path = os.path.join(opts["datadir"], "regtest", ".cookie")
os.makedirs(os.path.dirname(cookie_path))
cookie = "__cookie__:" + os.urandom(16).hex()
calls = [0]

def address():
    calls[0] += 1
    return "bcrt1q" + (str(calls[0]) if mode == "random" else "stable")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.headers.get("Authorization") != "Basic " + base64.b64encode(cookie.encode()).decode():
            self.send_response(401); self.end_headers(); return
        method, params, result, error = request["method"], request["params"], None, None
        if method == "getblockcount":
            result = 0
        elif method == "createwallet" and mode != "no-wallet":
            result = {"name": params[0]}
        elif method == "listdescriptors":
            result = {"descriptors": [
                {"desc": "mr(pqhd(tprv/0/*))#recv", "active": True, "internal": False},
                {"desc": "mr(pqhd(tprv/1/*))#change", "active": True, "internal": True}]}
        elif method == "deriveaddresses":
            result = [address()]
        elif method == "getnewaddress":
            result = "bcrt1qother" if mode == "mismatch" else address()
        elif method == "stop":
            result = "BTX node stopping"
            if mode != "no-stop":
                threading.Thread(target=server.shutdown).start()
        else:
            error = {"code": -32601, "message": "Method not found"}
        body = json.dumps({"result": result, "error": error, "id": request["id"]}).encode()
        self.send_response(500 if error else 200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", int(opts["rpcport"])), Handler)
with open(cookie_path, "w") as fh:
    fh.write(cookie)
server.serve_forever()
os.remove(cookie_path)
'''


class WalletDerivationCheckTest(unittest.TestCase):
    """--run-wallet-check: the shipped btxd's own wallet must derive its first address."""

    def setUp(self) -> None:
        self.mod = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.btxd = self.root / "btxd"
        self.btxd.write_text(FAKE_BTXD.replace("{python}", sys.executable), encoding="utf-8")
        self.btxd.chmod(0o755)
        self.log = self.root / "argv.log"

    def _check(self, mode, **kwargs):
        with mock.patch.dict(os.environ, {"FAKE_BTXD_MODE": mode, "FAKE_BTXD_LOG": str(self.log)}):
            return self.mod.verify_wallet_derivation(self.btxd, **kwargs)

    def _fails(self, mode, **kwargs):
        with self.assertRaises(self.mod.VerifyError) as caught:
            self._check(mode, **kwargs)
        return str(caught.exception)

    def _starts(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def _assert_gone(self):
        for start in self._starts():
            with self.assertRaises(ProcessLookupError):
                os.kill(start["pid"], 0)
            datadir = [a.split("=", 1)[1] for a in start["args"] if a.startswith("-datadir=")][0]
            self.assertFalse(pathlib.Path(datadir).exists(), datadir)

    def test_reproducible_wallet_passes_and_cleans_up(self) -> None:
        self.assertEqual(self._check("stable"), "wallet-derivation")
        (start,) = self._starts()
        for arg in ("-regtest", "-listen=0", "-modelnet=0", "-matmulvalidation=economic"):
            self.assertIn(arg, start["args"])
        self._assert_gone()

    def test_random_keygen_fails(self) -> None:
        # The v0.34.15 macOS shape: every derivation of index 0 is a new address.
        text = self._fails("random")
        self.assertIn("derived bcrt1q1, then bcrt1q2; the wallet's first address is bcrt1q3", text)
        self.assertIn("a seed backup would not restore it", text)
        self.assertNotIn("tprv", text)  # never print the private descriptor
        self._assert_gone()

    def test_stable_derivation_must_still_match_the_wallet(self) -> None:
        text = self._fails("mismatch")
        self.assertIn("derives bcrt1qstable, but the wallet's first address is bcrt1qother", text)

    def test_build_without_modelnet_is_started_again_without_that_flag(self) -> None:
        self.assertEqual(self._check("no-modelnet"), "wallet-derivation")
        first, second = self._starts()
        self.assertIn("-modelnet=0", first["args"])
        self.assertNotIn("-modelnet=0", second["args"])
        self.assertIn("-matmulvalidation=economic", second["args"])
        self._assert_gone()

    def test_startup_failure_timeout_and_unclean_stop_fail(self) -> None:
        self.assertIn("exited 1 before its RPC answered: Error: Unable to start HTTP server.", self._fails("exit"))
        self.assertIn("did not answer RPC within 2s", self._fails("hang", timeout=2))
        self.assertIn("did not exit 0 within 2s of the stop RPC", self._fails("no-stop", timeout=2))
        self.assertIn("wallet RPC on regtest failed: Method not found", self._fails("no-wallet"))
        self._assert_gone()

    def test_archive_and_cli_plumbing(self) -> None:
        archive = self.root / "btx-0.35.0-x86_64-linux-gnu.tar.gz"
        write_tar(archive, {"btx-0.35.0/bin/btxd": make_elf(["libzmq.so.5"], extra=ZMQ_HELP)})
        with mock.patch.object(self.mod, "elf_needed_ldd", side_effect=lambda p: self.mod.elf_dynamic_info(p).needed):
            self.mod.verify_archive(archive, launch=False)
            with mock.patch.object(self.mod, "native_launch_possible", return_value=False):
                with self.assertRaises(self.mod.VerifyError) as caught:
                    self.mod.verify_archive(archive, launch=False, wallet_check=True)
            self.assertIn("bin/btxd: --run-wallet-check needs a gate host that can run this btxd", str(caught.exception))
            with mock.patch.object(self.mod, "native_launch_possible", return_value=True), \
                    mock.patch.object(self.mod, "verify_wallet_derivation", return_value="wallet-derivation") as check:
                self.assertIn("+wallet-derivation", self.mod.verify_archive(archive, launch=False, wallet_check=True))
            check.assert_called_once()
            self.assertEqual(check.call_args.kwargs, {"clean_env": True})
            # When something else fails, the FAIL still says the wallet check passed.
            write_tar(archive, {"btx-0.35.0/bin/btxd": make_elf(["libzmq.so.5"], extra=ZMQ_HELP)},
                      uid=1000, uname="builder")
            with mock.patch.object(self.mod, "native_launch_possible", return_value=True), \
                    mock.patch.object(self.mod, "verify_wallet_derivation", return_value="wallet-derivation"), \
                    mock.patch("sys.stderr", new_callable=io.StringIO) as err, \
                    self.assertRaises(self.mod.VerifyError) as caught:
                self.mod.verify_archive(archive, launch=False, wallet_check=True)
            self.assertIn("not owned by root:root", str(caught.exception))
            self.assertIn(f"note {archive.name}: btx-0.35.0/bin/btxd: wallet check passed", err.getvalue())
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            self.mod.main(["--run-wallet-check", "--no-launch", "--archive", str(archive)])
        self.assertIn("--run-wallet-check runs btxd; drop --no-launch", err.getvalue())


if __name__ == "__main__":
    unittest.main()
