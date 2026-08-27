#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/licenses/mit-license.php.
"""Fail-closed ZMQ and macOS-portability check for shipped binaries.

0.33.4.2 advertised -zmqpubhashblock (hidden-arg strings) with no libzmq
linked. Pool operators got silence. This gate requires the ENABLE_ZMQ help
text (not just the flag name) and a real ZeroMQ link:

- Linux ELF: DT_NEEDED / ldd must name libzmq.
- macOS Mach-O: libzmq must be static — no libzmq dylib.

macOS release binaries must also launch on a Mac without Homebrew. Any
LC_LOAD_DYLIB under /opt/homebrew or /usr/local/opt (libevent, libomp,
libzmq, sqlite from the keg, ...) is a ship-blocker. System
(/usr/lib, /System/Library) load commands are expected.

Pass btxd (ZMQ + portability) and btx-cli (portability only) as separate
arguments. Do not stage a tarball that fails either.
"""

from __future__ import annotations

import argparse
import re
import struct
import subprocess
import sys
from pathlib import Path


ENABLE_ZMQ_HELP = b"Enable publish hash block"
ELF_MAGIC = b"\x7fELF"
MACHO_MAGIC_64LE = 0xFEEDFACF
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x18
LC_REQ_DYLD = 0x80000000
HOMEBREW_PREFIXES = ("/opt/homebrew", "/usr/local/opt")


class VerifyError(RuntimeError):
    pass


def read_prefix(path: Path, n: int = 5) -> bytes:
    with path.open("rb") as handle:
        return handle.read(n)


def has_enable_zmq_help(path: Path) -> bool:
    # mmap-sized files are fine; btxd is hundreds of MB at worst.
    return ENABLE_ZMQ_HELP in path.read_bytes()


def macho_dylibs(path: Path) -> list[str]:
    data = path.read_bytes()
    if len(data) < 32:
        raise VerifyError(f"{path}: too small to be Mach-O")
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != MACHO_MAGIC_64LE:
        raise VerifyError(f"{path}: not a little-endian 64-bit Mach-O (magic {magic:#x})")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    names: list[str] = []
    for _ in range(ncmds):
        if off + 8 > len(data):
            raise VerifyError(f"{path}: truncated Mach-O load commands")
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        load = cmd & ~LC_REQ_DYLD
        if load in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
            name_off = struct.unpack_from("<I", data, off + 8)[0]
            raw = data[off + name_off : off + cmdsize]
            names.append(raw.split(b"\x00", 1)[0].decode("ascii", "replace"))
        off += cmdsize
    return names


def homebrew_loads(dylibs: list[str]) -> list[str]:
    return [
        name
        for name in dylibs
        if any(name.startswith(prefix) or f"{prefix}/" in name for prefix in HOMEBREW_PREFIXES)
    ]


def elf_needed_ldd(path: Path) -> list[str]:
    try:
        result = subprocess.run(
            ["ldd", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise VerifyError("ldd is required to verify a Linux btxd") from exc
    if result.returncode != 0:
        raise VerifyError(f"ldd failed on {path}: {result.stderr.strip()}")
    needed: list[str] = []
    for line in result.stdout.splitlines():
        match = re.match(r"\s*(\S+)\s+=>", line)
        if match:
            needed.append(match.group(1))
            continue
        match = re.match(r"\s*(\S+)\s+\(", line)
        if match:
            needed.append(match.group(1))
    return needed


def verify_linux(path: Path) -> None:
    if not has_enable_zmq_help(path):
        raise VerifyError(
            f"{path}: missing ENABLE_ZMQ help text — this binary advertises "
            "-zmqpubhashblock without compiling bitcoin_zmq (0.33.4.2 failure shape)"
        )
    needed = elf_needed_ldd(path)
    if not any("libzmq" in name for name in needed):
        raise VerifyError(
            f"{path}: ldd does not show libzmq; WITH_ZMQ was OFF or libzmq was not linked. "
            f"NEEDED={needed}"
        )


def verify_macos_portable(path: Path, dylibs: list[str] | None = None) -> None:
    if dylibs is None:
        dylibs = macho_dylibs(path)
    forbidden = homebrew_loads(dylibs)
    if forbidden:
        raise VerifyError(
            f"{path}: macOS release binary must not load Homebrew dylibs "
            f"(clean Mac without brew will not launch). Found: {forbidden}"
        )


def verify_macos(path: Path, *, require_zmq: bool) -> None:
    dylibs = macho_dylibs(path)
    verify_macos_portable(path, dylibs)
    zmq_loads = [
        name
        for name in dylibs
        if "libzmq" in name or "zeromq" in name.lower()
    ]
    if zmq_loads:
        raise VerifyError(
            f"{path}: macOS btxd must statically link libzmq.a; found dylib load(s): "
            f"{zmq_loads}"
        )
    if require_zmq and not has_enable_zmq_help(path):
        raise VerifyError(
            f"{path}: missing ENABLE_ZMQ help text — ZMQ was not compiled in. "
            "otool showing no libzmq dylib is necessary but not sufficient; "
            "static libzmq.a plus bitcoin_zmq must actually be in the image."
        )


def classify(path: Path) -> str:
    prefix = read_prefix(path, 4)
    if prefix == ELF_MAGIC:
        return "elf"
    if len(prefix) == 4:
        magic = struct.unpack_from("<I", prefix, 0)[0]
        if magic == MACHO_MAGIC_64LE:
            return "macho"
    return "other"


def requires_zmq(path: Path) -> bool:
    name = path.name.lower()
    return not name.startswith("btx-cli")


def verify_binary(path: Path) -> str:
    kind = classify(path)
    if kind == "elf":
        if requires_zmq(path):
            verify_linux(path)
            return "linux-libzmq"
        return "linux-cli"
    if kind == "macho":
        want_zmq = requires_zmq(path)
        verify_macos(path, require_zmq=want_zmq)
        return "macos-static-zmq" if want_zmq else "macos-portable-cli"
    raise VerifyError(f"{path}: not an ELF or Mach-O binary (refusing to ship an untyped file)")


def verify_btxd(path: Path) -> str:
    """Back-compat for package_release_archive and unit tests."""
    return verify_binary(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "binaries",
        nargs="+",
        type=Path,
        help="Paths to btxd and/or btx-cli (or btxd.real) to verify.",
    )
    parser.add_argument(
        "--allow-non-binary",
        action="store_true",
        help="Exit 0 on non-ELF/Mach-O inputs (unit-test stubs only).",
    )
    args = parser.parse_args(argv)
    status = 0
    for raw in args.binaries:
        path = raw.expanduser().resolve()
        if not path.is_file():
            print(f"verify_release_btxd: FAIL missing {path}", file=sys.stderr)
            status = 1
            continue
        kind = classify(path)
        if kind == "other":
            if args.allow_non_binary:
                print(f"verify_release_btxd: SKIP non-binary {path}")
                continue
            print(f"verify_release_btxd: FAIL {path}: not an ELF or Mach-O binary", file=sys.stderr)
            status = 1
            continue
        try:
            how = verify_binary(path)
        except VerifyError as exc:
            print(f"verify_release_btxd: FAIL {exc}", file=sys.stderr)
            status = 1
            continue
        print(f"verify_release_btxd: PASS {path} ({how})")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
