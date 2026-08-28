#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/licenses/mit-license.php.
"""Fail-closed ZMQ, portability, and launch check for shipped binaries.

0.33.4.2 advertised -zmqpubhashblock (hidden-arg strings) with no libzmq
linked. Pool operators got silence. This gate requires the ENABLE_ZMQ help
text (not just the flag name) and a real ZeroMQ link:

- Linux ELF: DT_NEEDED / ldd must name libzmq.
- macOS Mach-O: libzmq must be static — no libzmq dylib.

macOS release binaries must also launch on a Mac without Homebrew. Any
LC_LOAD_DYLIB under /opt/homebrew or /usr/local/opt (libevent, libomp,
libzmq, sqlite from the keg, ...) is a ship-blocker. System
(/usr/lib, /System/Library) load commands are expected.

The 0.34 CUDA tarball shipped a btxd that would not start:
`libcublasLt.so.13: cannot open shared object file`. ldd/ZMQ checks do
not catch that. After the static checks, this gate runs `btxd -version`
and requires exit 0. Bundle CUDA runtime libs with `$ORIGIN` rpath
(see `bundle_cuda_runtime_libs.py`) so that launch succeeds without a
toolkit install.

Since 0.34.1 the published `bin/btxd` is a `#!/bin/sh` wrapper. `ldd`
and `otool -L` on that path return nothing and look like a clean pass
while meaning nothing at all (MendeMatthias). The real binary is
`libexec/btxd.real` on Linux and macOS. This script follows the wrapper
to that file; passing the wrapper without a sibling `.real` is FAIL.

Pass btxd (ZMQ + portability + launch) and btx-cli (portability only)
as separate arguments. `--archive` unpacks a shippable tarball/zip and
gates `libexec/btxd.real` (or `bin/btxd`). Guix, cut, collect, and
publish all invoke this script; an unrecognized file is FAIL, not a
skip. A skipped gate is how issues 111 and 122 shipped twice.
"""

from __future__ import annotations

import argparse
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
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


def verify_windows(path: Path) -> None:
    """PE has no ldd. The 111/122 miss is still visible as missing ENABLE_ZMQ help."""
    if requires_zmq(path) and not has_enable_zmq_help(path):
        raise VerifyError(
            f"{path}: missing ENABLE_ZMQ help text — this Windows btxd was built without ZMQ"
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
    if prefix[:2] == b"MZ":
        return "pe"
    if len(prefix) == 4:
        magic = struct.unpack_from("<I", prefix, 0)[0]
        if magic == MACHO_MAGIC_64LE:
            return "macho"
    return "other"


def native_launch_possible(kind: str) -> bool:
    """True when this host can actually exec the classified binary.

    linux-x86_64-cpu / linux-x86_64-cuda must launch on Linux. macos-arm64-metal
    must launch on Darwin. Cross-compile (Mach-O on Linux Guix) still runs the
    static ZMQ checks; launch is skipped only when exec format cannot succeed.
    """
    if kind == "elf":
        return sys.platform.startswith("linux")
    if kind == "macho":
        return sys.platform == "darwin"
    if kind == "pe":
        return sys.platform.startswith("win")
    return False


def requires_zmq(path: Path) -> bool:
    name = path.name.lower()
    if name.endswith(".exe"):
        name = name[:-4]
    if name.endswith(".real"):
        name = name[:-5]
    return not name.startswith("btx-cli")


def is_daemon(path: Path) -> bool:
    name = path.name.lower()
    if name.endswith(".exe"):
        name = name[:-4]
    if name.endswith(".real"):
        name = name[:-5]
    return name == "btxd"


def is_shell_wrapper(path: Path) -> bool:
    """True for the 0.34.1+ bin/btxd #!/bin/sh launcher, not the ELF/Mach-O."""
    try:
        prefix = path.read_bytes()[:80]
    except OSError:
        return False
    if not prefix.startswith(b"#!"):
        return False
    return b"/bin/sh" in prefix or b"/usr/bin/env" in prefix


def packaged_real_binary(wrapper: Path) -> Path:
    """bin/btxd wrapper -> libexec/btxd.real. Raises if the real binary is missing."""
    name = wrapper.name
    if name.endswith(".exe"):
        name = name[:-4]
    expected = wrapper.parent.parent / "libexec" / f"{name}.real"
    if not expected.is_file():
        raise VerifyError(
            f"{wrapper}: this is a #!/bin/sh wrapper (bin/btxd and bin/btx-cli "
            f"since 0.34.1). ldd/otool on the wrapper is a vacuous pass — it "
            f"is not an ELF or Mach-O. The real binary is {expected}. "
            "MendeMatthias: otool -L bin/btxd on the 0.34.1 tarball returned "
            "nothing and looked clean while meaning nothing at all."
        )
    return expected


def resolve_verify_target(path: Path) -> Path:
    """Follow packaged wrappers to libexec/*.real; leave build-tree binaries alone."""
    if is_shell_wrapper(path):
        return packaged_real_binary(path)
    return path


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
    if kind == "pe":
        verify_windows(path)
        return "windows-zmq-help" if requires_zmq(path) else "windows-cli"
    raise VerifyError(
        f"{path}: not an ELF, Mach-O, or PE binary (refusing to ship an untyped file)"
    )


def verify_launch(path: Path, timeout: float = 30.0) -> None:
    """Refuse a binary that cannot even print its version.

    The CUDA 0.34 packaging miss (`libcublasLt.so.13` missing) failed here
    and was invisible to the ZMQ/ldd checks.
    """
    try:
        result = subprocess.run(
            [str(path), "-version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise VerifyError(f"{path}: `{path.name} -version` timed out after {timeout}s") from exc
    except OSError as exc:
        raise VerifyError(f"{path}: cannot execute: {exc}") from exc
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        raise VerifyError(
            f"{path}: `{path.name} -version` exited {result.returncode} (need 0)"
            + (f": {err}" if err else "")
        )


def verify_btxd(path: Path) -> str:
    """Back-compat for package_release_archive and unit tests."""
    return verify_binary(path)


def verify_path_for_ship(path: Path) -> str:
    """Resolve wrappers, refuse untyped files, check ZMQ, and launch when native."""
    path = resolve_verify_target(path)
    kind = classify(path)
    if kind == "other":
        raise VerifyError(
            f"{path}: not an ELF, Mach-O, or PE binary (refusing to ship an untyped file)"
        )
    how = verify_binary(path)
    if is_daemon(path):
        if native_launch_possible(kind):
            verify_launch(path)
            how = f"{how}+launch"
        else:
            how = f"{how}+launch-skipped-cross"
            print(
                f"verify_release_btxd: note skip launch for {path} "
                f"({kind} is not executable on {sys.platform}); static checks passed",
                file=sys.stderr,
            )
    return how


def extract_release_archive(archive: Path, dest: Path) -> None:
    name = archive.name.lower()
    try:
        if name.endswith(".zip"):
            with zipfile.ZipFile(archive) as handle:
                handle.extractall(dest)
            return
        if name.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar")):
            with tarfile.open(archive, "r:*") as handle:
                kwargs: dict[str, object] = {}
                if sys.version_info >= (3, 12):
                    kwargs["filter"] = "data"
                handle.extractall(dest, **kwargs)
            return
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
        raise VerifyError(f"{archive}: not a readable shippable archive: {exc}") from exc
    raise VerifyError(f"{archive}: not a recognized archive (.tar.gz/.zip)")


def _prefer_bin_then_any(paths: list[Path]) -> Path:
    preferred = [path for path in paths if path.parent.name == "bin"]
    chosen = preferred or paths
    if len(chosen) != 1:
        names = ", ".join(str(path) for path in chosen)
        raise VerifyError(f"archive contains multiple candidate binaries: {names}")
    return chosen[0]


def find_packaged_btxd(root: Path) -> Path:
    reals = sorted(path for path in root.rglob("btxd.real") if path.is_file())
    if reals:
        if len(reals) != 1:
            raise VerifyError(
                "archive contains multiple libexec/btxd.real files: "
                + ", ".join(str(path) for path in reals)
            )
        return reals[0]
    found = [path for path in root.rglob("btxd") if path.is_file()]
    found.extend(path for path in root.rglob("btxd.exe") if path.is_file())
    if not found:
        raise VerifyError(f"{root}: archive contains no btxd (looked for libexec/btxd.real, bin/btxd)")
    return _prefer_bin_then_any(found)


def find_packaged_cli(root: Path) -> Path | None:
    reals = sorted(path for path in root.rglob("btx-cli.real") if path.is_file())
    if len(reals) == 1:
        return reals[0]
    if len(reals) > 1:
        raise VerifyError(
            "archive contains multiple libexec/btx-cli.real files: "
            + ", ".join(str(path) for path in reals)
        )
    found = [path for path in root.rglob("btx-cli") if path.is_file()]
    found.extend(path for path in root.rglob("btx-cli.exe") if path.is_file())
    if not found:
        return None
    return _prefer_bin_then_any(found)


def verify_archive(archive: Path) -> str:
    """Unpack a shippable tarball/zip and gate the real btxd (and btx-cli if present)."""
    if not archive.is_file():
        raise VerifyError(f"{archive}: missing archive")
    with tempfile.TemporaryDirectory(prefix="btx-verify-archive-") as tmpdir:
        dest = Path(tmpdir)
        extract_release_archive(archive, dest)
        btxd = find_packaged_btxd(dest)
        how = verify_path_for_ship(btxd)
        cli = find_packaged_cli(dest)
        if cli is not None:
            cli = resolve_verify_target(cli)
            kind = classify(cli)
            if kind == "other":
                raise VerifyError(
                    f"{cli}: not an ELF, Mach-O, or PE binary (refusing to ship an untyped file)"
                )
            verify_binary(cli)
            how = f"{how}+cli"
        return how


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "binaries",
        nargs="*",
        type=Path,
        help="Paths to btxd, btx-cli, or libexec/btxd.real. A packaged "
        "bin/btxd #!/bin/sh wrapper is followed to libexec/btxd.real; "
        "ldd/otool on the wrapper itself is refused.",
    )
    parser.add_argument(
        "--archive",
        action="append",
        default=[],
        type=Path,
        dest="archives",
        help="Shippable .tar.gz/.zip to unpack and gate (libexec/btxd.real or bin/btxd). "
        "Required on the Guix/cut/publish path that produces the user download.",
    )
    parser.add_argument(
        "--allow-non-binary",
        action="store_true",
        help="Exit 0 on non-ELF/Mach-O/PE inputs (unit-test stubs only; never for release).",
    )
    args = parser.parse_args(argv)
    if not args.binaries and not args.archives:
        parser.error("pass at least one binary or --archive")
    failures = 0
    for raw in args.archives:
        path = raw.expanduser().resolve()
        try:
            how = verify_archive(path)
        except VerifyError as exc:
            print(f"verify_release_btxd: FAIL {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"verify_release_btxd: PASS archive {path} ({how})")
    for raw in args.binaries:
        path = raw.expanduser().resolve()
        if not path.is_file():
            print(f"verify_release_btxd: FAIL missing {path}", file=sys.stderr)
            failures += 1
            continue
        try:
            path = resolve_verify_target(path)
        except VerifyError as exc:
            print(f"verify_release_btxd: FAIL {exc}", file=sys.stderr)
            failures += 1
            continue
        kind = classify(path)
        if kind == "other":
            if args.allow_non_binary:
                print(f"verify_release_btxd: SKIP non-binary {path}")
                continue
            print(
                f"verify_release_btxd: FAIL {path}: not an ELF, Mach-O, or PE binary",
                file=sys.stderr,
            )
            failures += 1
            continue
        try:
            how = verify_path_for_ship(path)
        except VerifyError as exc:
            print(f"verify_release_btxd: FAIL {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"verify_release_btxd: PASS {path} ({how})")
    if failures:
        # Last line must be FAIL. A mixed btxd-FAIL + btx-cli-PASS used to
        # end on PASS, which a wrapper that inspects the last line (or a
        # pipeline without pipefail) treats as green — the 111/122 miss.
        print(f"verify_release_btxd: FAIL {failures} binary(ies)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
