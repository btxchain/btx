#!/usr/bin/env python3
"""Fail-closed tests for scripts/release/verify_release_btxd.py."""

from __future__ import annotations

import importlib.util
import pathlib
import struct
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release" / "verify_release_btxd.py"
LEGACY_CPU = pathlib.Path(
    "/home/administrator/Documents/btxchain/.03342-binaries/"
    "btx-0.33.4.2-linux-x86_64-cpu.tar.gz"
)


def load_module():
    spec = importlib.util.spec_from_file_location("verify_release_btxd", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


if __name__ == "__main__":
    unittest.main()
