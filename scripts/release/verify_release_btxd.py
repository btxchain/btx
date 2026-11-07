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

`ldd` returning no "not found" sonames is not the whole runtime story.
The v0.34.8-rc1 CPU archive is linked against GLIBC_2.38 / GLIBCXX_3.4.32;
Ubuntu 22.04 (glibc 2.35) and Debian 12 (2.36) have libc.so.6 and
libstdc++.so.6 installed, so `ldd` looks clean and the loader then fails
on a version node (issue 169). Before launching a Linux daemon this gate
reads the required GLIBC/GLIBCXX/CXXABI version nodes from `objdump -T`
(or `readelf -V`) and prints them, so a baseline-host FAIL names the
archive's floor instead of only the host's missing symbol.

`--archive` also gates the whole archive, not only btxd (0.35.0rc1, #237).
On top of the GLIBC ceiling and the Mach-O codesign check: an executable
that NEEDs a library the archive ships must reach it through RUNPATH/RPATH
or the packaged wrapper; no ELF may need a GLIBCXX, CXXABI, GCC or OPENSSL
version above the floor from a host library (OPENSSL per library: libssl
and libcrypto define different nodes); a Windows .exe/.dll may import
only system DLLs or DLLs beside it; a Mach-O with ML-DSA keygen must define
_btx_mldsa_randombytes (17c2da89); tar members must be root-owned and not
group/world-writable, no directory may be empty, and no name or link may
leave the archive. These checks read the files and run nothing, so a Mac
can gate a Linux archive.

`--run-wallet-check` (off by default) also runs btxd (with `--archive`, the
archive's own) on regtest in a temporary datadir: a new wallet's private
receive descriptor must derive the wallet's first address, twice. The
v0.34.15 macOS btxd linked libsodium's randombytes into ML-DSA keygen and
failed this (#253); `test_btx` is a separate link and cannot show it. It
needs a gate host that can run the binary.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import platform
import posixpath
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
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


LC_SYMTAB = 0x2
N_STAB = 0xE0
N_TYPE = 0x0E
N_SECT = 0x0E
# 17c2da89 compiles the ML-DSA sources with randombytes=btx_mldsa_randombytes.
# A Mach-O that has ML-DSA keygen but not that symbol calls whichever
# randombytes ld kept: libsodium's in the official v0.34.15 macOS btxd (#253).
MLDSA_KEYGEN_SYMBOL = "_ml_dsa_44_keygen"
MLDSA_RANDOMBYTES_SYMBOL = "_btx_mldsa_randombytes"


def macho_defined_symbols(path: Path) -> set[str]:
    """Names a thin 64-bit Mach-O defines in a section, from LC_SYMTAB.

    The same names `nm -m` lists with a (__SEGMENT,__section), external or
    not. Read in Python so a Linux host gating the macOS archive gets the
    same answer. A fully stripped image gives an empty set.
    """
    data = path.read_bytes()
    if len(data) < 32 or struct.unpack_from("<I", data, 0)[0] != MACHO_MAGIC_64LE:
        raise VerifyError(f"{path}: not a little-endian 64-bit Mach-O")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    for _ in range(ncmds):
        if off + 8 > len(data):
            raise VerifyError(f"{path}: truncated Mach-O load commands")
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SYMTAB:
            if off + 24 > len(data):
                raise VerifyError(f"{path}: truncated LC_SYMTAB")
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, off + 8)
            if symoff + 16 * nsyms > len(data) or stroff + strsize > len(data):
                raise VerifyError(f"{path}: symbol table past the end of the file")
            strings = data[stroff:stroff + strsize]
            names = set()
            for n_strx, n_type in struct.iter_unpack("<IB11x", data[symoff:symoff + 16 * nsyms]):
                if n_type & N_STAB or (n_type & N_TYPE) != N_SECT or n_strx >= len(strings):
                    continue
                end = strings.find(b"\0", n_strx)
                names.add(strings[n_strx:end if end >= 0 else len(strings)].decode("utf-8", "replace"))
            return names
        if cmdsize < 8:
            raise VerifyError(f"{path}: Mach-O load command of size {cmdsize}")
        off += cmdsize
    return set()


def macho_randombytes_problem(path: Path, label: str) -> str:
    """'' unless the Mach-O links ML-DSA keygen without btx_mldsa_randombytes."""
    symbols = macho_defined_symbols(path)
    if MLDSA_KEYGEN_SYMBOL in symbols and MLDSA_RANDOMBYTES_SYMBOL not in symbols:
        return (f"{label}: has ML-DSA keygen but no {MLDSA_RANDOMBYTES_SYMBOL}, so keygen calls "
                "whichever randombytes the linker kept (libsodium's in the v0.34.15 macOS btxd: keys "
                "did not follow from the seed, #253); build with the 17c2da89 rename in "
                "src/libbitcoinpqc/CMakeLists.txt")
    return ""


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
    except FileNotFoundError:
        # A non-Linux gate host has no ldd. DT_NEEDED is where libzmq must be.
        return elf_dynamic_info(path).needed
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


ELF_VERSION_PREFIXES = ("GLIBC", "GLIBCXX", "CXXABI")


def version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split(".") if part.isdigit())


def host_glibc_version() -> str:
    try:
        name, version = platform.libc_ver()
    except Exception:  # pragma: no cover - platform probe must never gate
        return ""
    return version if name == "glibc" else ""


def elf_required_versions(path: Path) -> dict[str, str]:
    """Highest GLIBC/GLIBCXX/CXXABI version node the ELF names (objdump -T).

    `ldd` only reports missing sonames. Debian 12 and Ubuntu 22.04 ship
    libc.so.6 and libstdc++.so.6, so that preflight passes and the loader
    then fails on a version node. Reading the floor from the binary itself
    is what makes a 22.04 gate FAIL explicit (issue 169).
    """
    if not path.is_file() or classify(path) != "elf":
        return {}
    text = ""
    for command in (["objdump", "-T", str(path)], ["readelf", "-V", str(path)]):
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            continue
        text = result.stdout or ""
        if text.strip():
            break
    if not text.strip():
        # No objdump/readelf (a slim CI image, a Mac without the command line
        # tools): read the version needs directly, so verify_glibc_ceiling does
        # not pass an archive only because binutils is missing.
        try:
            text = " ".join(v for versions in elf_dynamic_info(path).verneed.values() for v in versions)
        except (VerifyError, struct.error):
            return {}
    required: dict[str, str] = {}
    for prefix in ELF_VERSION_PREFIXES:
        found = re.findall(rf"\b{prefix}_([0-9]+(?:\.[0-9]+)+)", text)
        if found:
            required[prefix] = max(found, key=version_key)
    return required


def required_versions_summary(path: Path) -> str:
    return ", ".join(
        f"{prefix}_{value}" for prefix, value in elf_required_versions(path).items()
    )


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
    verify_macos_signature(path)
    if dylibs is None:
        dylibs = macho_dylibs(path)
    forbidden = homebrew_loads(dylibs)
    if forbidden:
        raise VerifyError(
            f"{path}: macOS release binary must not load Homebrew dylibs "
            f"(clean Mac without brew will not launch). Found: {forbidden}"
        )


def verify_macos_signature(path: Path) -> None:
    """Fail a Mach-O whose code signature no longer matches its bytes.

    rc1's bin/btxd had compiled-in Metal kernel paths rewritten after linking
    and was not re-signed, so Apple Silicon killed it at launch (SIGKILL, exit
    137) while the dylib checks passed. Only a host with `codesign` can check;
    elsewhere this is a no-op and the release checklist must record a native run.
    """
    codesign = shutil.which("codesign")
    if codesign is None:
        return
    result = subprocess.run(
        [codesign, "--verify", "--strict", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if "not signed at all" in detail:
            return  # never signed is a distribution choice; a broken seal is the bug
        raise VerifyError(
            f"{path}: codesign --verify --strict failed (the binary was modified "
            f"after signing; re-sign it or set the paths at configure time): {detail}"
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
    problem = macho_randombytes_problem(path, str(path))
    if problem:
        raise VerifyError(problem)


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


def packaged_openssl_libdir(path: Path) -> Path | None:
    """<prefix>/lib when the packaged bin/ wrapper puts it on LD_LIBRARY_PATH.

    Only libexec/<tool>.real is launched through that wrapper, and the
    wrapper adds lib/ only when lib/libssl.so.3 exists. An ELF directly in
    bin/ (the rc1 layout) gets nothing from the user's shell: it must find
    lib/ through its own RUNPATH. Adding lib/ here hid rc1's missing RUNPATH.
    """
    if path.parent.name != "libexec" or not path.name.endswith(".real"):
        return None
    libdir = path.parent.parent / "lib"
    if (libdir / "libssl.so.3").is_file():
        return libdir
    return None


LOADER_ENV_VARS = ("LD_LIBRARY_PATH", "LD_PRELOAD", "DYLD_LIBRARY_PATH",
                   "DYLD_FALLBACK_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES")


def launch_env(path: Path, *, clean_env: bool = False) -> dict[str, str]:
    """The environment a packaged binary gets: clean_env drops the gate host's
    loader variables; the libexec/*.real layout gets the wrapper's lib/."""
    env = os.environ.copy()
    if clean_env:
        for name in LOADER_ENV_VARS:
            env.pop(name, None)
    libdir = packaged_openssl_libdir(path)
    if libdir is not None:
        env["LD_LIBRARY_PATH"] = str(libdir) + (
            f":{env['LD_LIBRARY_PATH']}" if env.get("LD_LIBRARY_PATH") else ""
        )
    return env


def verify_launch(path: Path, timeout: float = 30.0, *, clean_env: bool = False) -> None:
    """Refuse a binary that cannot even print its version.

    The CUDA 0.34 packaging miss (`libcublasLt.so.13` missing) failed here
    and was invisible to the ZMQ/ldd checks. clean_env drops the gate
    host's loader variables, so an archive is launched as a user gets it.
    """
    env = launch_env(path, clean_env=clean_env)
    try:
        result = subprocess.run(
            [str(path), "-version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise VerifyError(f"{path}: `{path.name} -version` timed out after {timeout}s") from exc
    except OSError as exc:
        raise VerifyError(f"{path}: cannot execute: {exc}") from exc
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        required = required_versions_summary(path)
        hint = ""
        if required:
            hint = (
                f" Required version nodes (objdump -T): {required}. "
                "If that floor is above the host (Debian 12 / Ubuntu 22.04 "
                "provide glibc 2.36 / 2.35), ldd still looks clean; build from "
                "source there or raise the documented baseline (issue 169)."
            )
        raise VerifyError(
            f"{path}: `{path.name} -version` exited {result.returncode} (need 0)"
            + (f": {err}" if err else "")
            + hint
        )


def verify_btxd(path: Path) -> str:
    """Back-compat for package_release_archive and unit tests."""
    return verify_binary(path)


def verify_path_for_ship(path: Path, *, launch: bool = True, clean_env: bool = False) -> str:
    """Resolve wrappers, refuse untyped files, check ZMQ, and launch when native."""
    path = resolve_verify_target(path)
    kind = classify(path)
    if kind == "other":
        raise VerifyError(
            f"{path}: not an ELF, Mach-O, or PE binary (refusing to ship an untyped file)"
        )
    how = verify_binary(path)
    if is_daemon(path):
        if not launch:
            how = f"{how}+launch-not-run"
        elif native_launch_possible(kind):
            required = required_versions_summary(path)
            if required:
                host = host_glibc_version()
                print(
                    f"verify_release_btxd: note {path.name} requires {required} "
                    f"(objdump -T; host GLIBC {host or 'unknown'})",
                    file=sys.stderr,
                )
            verify_launch(path, clean_env=clean_env)
            how = f"{how}+launch"
        else:
            how = f"{how}+launch-skipped-cross"
            print(
                f"verify_release_btxd: note skip launch for {path} "
                f"({kind} is not executable on {sys.platform}); static checks passed",
                file=sys.stderr,
            )
    return how


# ---------------------------------------------------------------------------
# Seeded wallet keys, checked on the shipped btxd itself (--run-wallet-check).
# The official v0.34.15 macOS btxd linked libsodium's randombytes into ML-DSA
# keygen (fixed by 17c2da89, #253). A new wallet's own private receive
# descriptor then derived a different address on every call, none of them the
# address the wallet gave out, so its seed could not restore it. test_btx is a
# separate link from the archive's btxd, and nothing else here runs a wallet.
# MendeMatthias proposed this check in the #247 review.

WALLET_CHECK_ARGS = ("-regtest", "-server=1", "-listen=0", "-connect=0", "-dnsseed=0",
                     "-printtoconsole=0")
# Tried first. If btxd rejects one ("Invalid parameter -modelnet=0" from a
# -DWITH_MODELNET=OFF build), it is started again without that one.
WALLET_CHECK_OPTIONAL_ARGS = ("-modelnet=0", "-matmulvalidation=economic")
WALLET_CHECK_WALLET = "release-gate"


class RpcError(Exception):
    def __init__(self, code: object, message: str) -> None:
        super().__init__(f"{message} (code {code})")
        self.code = code


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _rpc(port: int, cookie: str, method: str, params: list, *, wallet: str | None = None,
         timeout: float = 60.0) -> object:
    # http.client, not urllib: a gate host's http_proxy must never see the cookie.
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("POST", f"/wallet/{wallet}" if wallet else "/",
                     json.dumps({"jsonrpc": "1.0", "id": method, "method": method, "params": params}),
                     {"Authorization": "Basic " + base64.b64encode(cookie.encode()).decode(),
                      "Content-Type": "application/json"})
        response = conn.getresponse()
        raw = response.read()
    finally:
        conn.close()
    try:
        reply = json.loads(raw)
    except ValueError:
        raise RpcError(response.status, raw[:200].decode("utf-8", "replace").strip() or response.reason)
    if not isinstance(reply, dict):
        raise RpcError(response.status, "reply is not a JSON-RPC object")
    if reply.get("error"):
        error = reply["error"] if isinstance(reply["error"], dict) else {"message": str(reply["error"])}
        raise RpcError(error.get("code"), str(error.get("message")))
    return reply.get("result")


def _output_tail(path: Path, limit: int = 600) -> str:
    try:
        text = path.read_bytes()[-limit:].decode("utf-8", "replace")
    except OSError:
        return ""
    return " ".join(text.split())


def _stop_regtest_btxd(proc: subprocess.Popen, port: int, cookie: str | None, timeout: float) -> bool:
    """Stop through the stop RPC. True when btxd then exited 0 in time.

    A btxd that ignores the RPC gets SIGTERM, its own clean shutdown signal;
    one that ignores that too is killed, since its datadir is a throwaway
    regtest one that is deleted next.
    """
    if proc.poll() is None and cookie is not None:
        try:
            _rpc(port, cookie, "stop", [], timeout=min(timeout, 30.0))
        except (OSError, RpcError, http.client.HTTPException):
            pass
    try:
        return proc.wait(timeout=timeout) == 0
    except subprocess.TimeoutExpired:
        pass
    proc.terminate()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    return False


def _start_regtest_btxd(path: Path, workdir: Path, env: dict[str, str],
                        timeout: float) -> tuple[subprocess.Popen, int, str]:
    """Start btxd on regtest under workdir and wait until its RPC answers."""
    optional = list(WALLET_CHECK_OPTIONAL_ARGS)
    for attempt in range(len(WALLET_CHECK_OPTIONAL_ARGS) + 1):
        datadir = workdir / f"datadir{attempt}"
        datadir.mkdir()
        output = workdir / f"output{attempt}.log"
        port = _free_local_port()
        command = [str(path), f"-datadir={datadir}", f"-rpcport={port}",
                   *WALLET_CHECK_ARGS, *optional]
        with output.open("wb") as log:
            try:
                proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                        stderr=subprocess.STDOUT, env=env)
            except OSError as exc:
                raise VerifyError(f"{path}: cannot execute: {exc}") from exc
        cookie_path = datadir / "regtest" / ".cookie"
        deadline = time.monotonic() + timeout
        while proc.poll() is None:
            if time.monotonic() > deadline:
                _stop_regtest_btxd(proc, port, None, 0)
                raise VerifyError(f"{path}: regtest btxd did not answer RPC within {timeout:.0f}s: "
                                  f"{_output_tail(output)}")
            try:
                cookie = cookie_path.read_text(encoding="utf-8").strip()
                _rpc(port, cookie, "getblockcount", [], timeout=10)
                return proc, port, cookie
            except (OSError, RpcError, http.client.HTTPException):
                time.sleep(0.2)  # no cookie yet, not listening yet, or warming up (-28)
        text = _output_tail(output)
        rejected = re.search(r"Invalid parameter (-[A-Za-z0-9_]+)", text)
        dropped = [arg for arg in optional if rejected and arg.split("=")[0] == rejected.group(1)]
        if not dropped:
            how = (f"was killed by signal {-proc.returncode}" if proc.returncode < 0
                   else f"exited {proc.returncode}")
            raise VerifyError(f"{path}: regtest btxd {how} before its RPC answered"
                              + (f": {text}" if text else ""))
        optional.remove(dropped[0])
    raise VerifyError(f"{path}: regtest btxd rejected every start")  # pragma: no cover


def verify_wallet_derivation(path: Path, *, timeout: float = 120.0, clean_env: bool = True) -> str:
    """A new wallet's own private receive descriptor must derive its first address.

    Start btxd -regtest in a temporary datadir; createwallet; listdescriptors
    true; deriveaddresses on each active receive descriptor for index 0,
    twice; then getnewaddress. Both derivations must agree, and the address
    must be one of them. Stop through RPC; the datadir is removed.
    """
    env = launch_env(path, clean_env=clean_env)
    with tempfile.TemporaryDirectory(prefix="btx-wallet-check-") as tmpdir:
        proc, port, cookie = _start_regtest_btxd(path, Path(tmpdir), env, timeout)

        def call(method: str, *params: object, wallet: str | None = None) -> object:
            return _rpc(port, cookie, method, list(params), wallet=wallet, timeout=timeout)

        problem = ""
        try:
            try:
                call("createwallet", WALLET_CHECK_WALLET)
                listed = call("listdescriptors", True, wallet=WALLET_CHECK_WALLET)
                receive = [entry["desc"] for entry in (listed or {}).get("descriptors", [])
                           if entry.get("active") and not entry.get("internal")]
                derived = [(call("deriveaddresses", desc, [0, 0]), call("deriveaddresses", desc, [0, 0]))
                           for desc in receive]
                first = call("getnewaddress", wallet=WALLET_CHECK_WALLET)
            except (RpcError, KeyError, TypeError, AttributeError) as exc:
                raise VerifyError(f"{path}: wallet RPC on regtest failed: {exc}") from exc
            except (OSError, http.client.HTTPException) as exc:
                raise VerifyError(f"{path}: lost the regtest btxd RPC connection: {exc}") from exc
            for once, again in derived:
                if once != again or len(once) != 1:
                    problem = (f"{path}: index 0 of the new wallet's own private receive descriptor "
                               f"derived {', '.join(once)}, then {', '.join(again)}; the wallet's first "
                               f"address is {first}")
                    break
            if receive and not problem and first not in {once[0] for once, _ in derived}:
                problem = (f"{path}: index 0 of the new wallet's own private receive descriptor derives "
                           f"{', '.join(once[0] for once, _ in derived)}, but the wallet's first address "
                           f"is {first}")
            if problem:
                problem += (". Its ML-DSA keys do not follow from its seed, so a seed backup would not "
                            "restore it (libsodium's randombytes in ML-DSA keygen: v0.34.15 macOS, 17c2da89)")
            elif not receive:
                problem = f"{path}: listdescriptors true shows no active receive descriptor"
        finally:
            stopped = _stop_regtest_btxd(proc, port, cookie, timeout)
        if problem:
            raise VerifyError(problem)
        if not stopped:
            raise VerifyError(f"{path}: regtest btxd did not exit 0 within {timeout:.0f}s of the stop RPC")
    return "wallet-derivation"


def run_wallet_check(path: Path, *, clean_env: bool = True) -> str:
    """verify_wallet_derivation on the real binary, where this host can run it."""
    target = resolve_verify_target(path)
    kind = classify(target)
    if not native_launch_possible(kind):
        raise VerifyError(f"{target}: --run-wallet-check needs a gate host that can run this btxd "
                          f"({kind} on {sys.platform})")
    return verify_wallet_derivation(target, clean_env=clean_env)


# ---------------------------------------------------------------------------
# Whole-archive gate. 0.35.0rc1 passed the btxd-only gate above and still
# shipped a Linux btxd that needs OPENSSL_3.2.0 with no RUNPATH to the
# bundled lib/libssl.so.3, administrator-owned and group-writable members,
# an empty metal/ and no model helpers (#237, #235). verify_glibc_ceiling and
# verify_macos_signature cover the GLIBC_2.43 files and the re-signed btxd.

# The host libraries other than libc. GLIBCXX/CXXABI: the floor recorded in
# doc/release/0.35.0-rc1-checklist.md, as GLIBC_CEILING is. GCC: the highest
# version node Ubuntu 24.04's libgcc_s defines. "<soname>:<family>" sets the
# floor for the version nodes needed from that one library: OPENSSL nodes
# are per library, and 24.04's libssl.so.3 defines only OPENSSL_3.0.0 while
# its libcrypto.so.3 goes to OPENSSL_3.0.9 (readelf -V, libssl3t64 3.0.13).
# A need for OPENSSL_3.0.3 from the host libssl.so.3 does not load there
# (bs1812, #247). The family entry covers any other library.
ABI_FAMILIES = ("GLIBCXX", "CXXABI", "GCC", "OPENSSL")
DEFAULT_ABI_FLOOR = {
    "GLIBCXX": "3.4.32",
    "CXXABI": "1.3.15",
    "GCC": "14.0.0",
    "OPENSSL": "3.0.9",
    "libssl.so.3:OPENSSL": "3.0.0",
    "libcrypto.so.3:OPENSSL": "3.0.9",
}
ABI_NODE_RE = re.compile(r"^(GLIBCXX|CXXABI|GCC|OPENSSL)_([0-9]+(?:\.[0-9]+)*)$")
FLOOR_NAME_RE = re.compile(r"^(?:([A-Za-z0-9_.+-]+\.so(?:\.[0-9]+)*):)?(" + "|".join(ABI_FAMILIES) + r")$")
# Same names as package_release_archive.MODEL_HELPER_BINARIES (a test pins it).
MODEL_HELPER_BINARIES = (
    "btx-modeld", "btx-hcpd", "btx-hosted", "btx-open",
    "btx-capability", "btx-capabilityd", "btx-modelcheck", "btx-matmul-backend-info",
)
WINDOWS_SYSTEM_DLLS = frozenset({
    "advapi32.dll", "authz.dll", "bcrypt.dll", "cfgmgr32.dll", "comctl32.dll",
    "comdlg32.dll", "crypt32.dll", "d2d1.dll", "d3d11.dll", "d3d12.dll", "d3d9.dll",
    "dbghelp.dll", "dnsapi.dll", "dwmapi.dll", "dwrite.dll", "dxgi.dll", "gdi32.dll",
    "imm32.dll", "iphlpapi.dll", "kernel32.dll", "mpr.dll", "msvcrt.dll", "mswsock.dll",
    "ncrypt.dll", "netapi32.dll", "normaliz.dll", "ntdll.dll", "nvcuda.dll", "ole32.dll",
    "oleaut32.dll", "opengl32.dll", "powrprof.dll", "psapi.dll", "rpcrt4.dll",
    "secur32.dll", "setupapi.dll", "shcore.dll", "shell32.dll", "shlwapi.dll",
    "ucrtbase.dll", "user32.dll", "userenv.dll", "uxtheme.dll", "version.dll",
    "winhttp.dll", "wininet.dll", "winmm.dll", "winspool.drv", "wldap32.dll",
    "ws2_32.dll", "wtsapi32.dll",
})


class ElfDynamic:
    # Not a dataclass: release scripts load this module by path, without
    # sys.modules, and 3.9 dataclasses need it there to read annotations.
    def __init__(self, executable: bool) -> None:
        self.executable = executable
        self.needed: list[str] = []
        self.search: list[str] = []  # DT_RUNPATH, else DT_RPATH
        self.search_tag = ""
        self.verneed: dict[str, list[str]] = {}


def elf_dynamic_info(path: Path) -> ElfDynamic:
    """DT_NEEDED, RUNPATH/RPATH and version needs, read the way ld.so reads them."""
    with path.open("rb") as fh:
        file_size = os.fstat(fh.fileno()).st_size

        def read_at(offset: int, size: int) -> bytes:
            # Check against the file first: a crafted 2^62 size is otherwise a
            # MemoryError, and a 2^64 offset an OverflowError, not a FAIL.
            if offset + size > file_size:
                raise VerifyError(f"{path}: truncated ELF")
            fh.seek(offset)
            data = fh.read(size)
            if len(data) != size:
                raise VerifyError(f"{path}: truncated ELF")
            return data

        head = read_at(0, 64)
        if head[:4] != ELF_MAGIC or head[4] != 2 or head[5] != 1:
            raise VerifyError(f"{path}: only little-endian 64-bit ELF is gated")
        e_type = struct.unpack_from("<H", head, 16)[0]
        phoff = struct.unpack_from("<Q", head, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", head, 54)
        loads: list[tuple[int, int, int]] = []
        dynamic = None
        interp = False
        for i in range(phnum):
            p_type, _, p_off, p_vaddr, _, p_filesz = struct.unpack_from(
                "<IIQQQQ", read_at(phoff + i * phentsize, 40))
            if p_type == 1:
                loads.append((p_vaddr, p_off, p_filesz))
            elif p_type == 2:
                dynamic = (p_off, p_filesz)
            elif p_type == 3:
                interp = True
        info = ElfDynamic(executable=e_type == 2 or interp)
        if dynamic is None:
            return info

        def file_offset(vaddr: int) -> int:
            for start, offset, size in loads:
                if start <= vaddr < start + size:
                    return vaddr - start + offset
            raise VerifyError(f"{path}: dynamic address {vaddr:#x} is outside every PT_LOAD")

        raw = read_at(*dynamic)
        tags: list[tuple[int, int]] = []
        for pos in range(0, len(raw) - 15, 16):
            tag, value = struct.unpack_from("<qQ", raw, pos)
            if tag == 0:
                break
            tags.append((tag, value))
        first = {tag: value for tag, value in reversed(tags)}
        if 5 not in first:
            raise VerifyError(f"{path}: PT_DYNAMIC without DT_STRTAB")
        strings = read_at(file_offset(first[5]), first.get(10, 0))

        def string(offset: int) -> str:
            end = strings.find(b"\0", offset)
            if offset >= len(strings) or end < 0:
                raise VerifyError(f"{path}: dynamic string offset {offset} out of range")
            return strings[offset:end].decode("utf-8", "replace")

        info.needed = [string(value) for tag, value in tags if tag == 1]
        for tag, name in ((29, "RUNPATH"), (15, "RPATH")):
            if tag in first:  # ld.so ignores DT_RPATH when DT_RUNPATH is present
                info.search = [entry for entry in string(first[tag]).split(":") if entry]
                info.search_tag = name
                break
        if 0x6FFFFFFE in first:
            offset = file_offset(first[0x6FFFFFFE])
            records = 0
            for _ in range(first.get(0x6FFFFFFF, 0)):
                _, count, file_name, aux, next_need = struct.unpack("<HHIII", read_at(offset, 16))
                records += 1 + count
                if records > 4096:  # real files need a few dozen; overlapping records repeat for hours
                    raise VerifyError(f"{path}: more than 4096 version needs")
                versions = info.verneed.setdefault(string(file_name), [])
                aux_offset = offset + aux
                for _ in range(count):
                    _, _, _, name, next_aux = struct.unpack("<IHHII", read_at(aux_offset, 16))
                    versions.append(string(name))
                    if not next_aux:
                        break
                    aux_offset += next_aux
                if not next_need:
                    break
                offset += next_need
        return info


def _search_dirs(path: Path, info: ElfDynamic) -> list[Path]:
    dirs = []
    for entry in info.search:
        entry = entry.replace("${ORIGIN}", "$ORIGIN")
        if entry.startswith("$ORIGIN"):
            dirs.append(Path(os.path.normpath(str(path.parent) + entry[len("$ORIGIN"):])))
    if info.executable:
        wrapper_lib = packaged_openssl_libdir(path)
        if wrapper_lib is not None and is_shell_wrapper(path.parent.parent / "bin" / path.name[:-5]):
            dirs.insert(0, wrapper_lib)
    return dirs


def linux_elf_problems(root: Path, files: list[Path], floor: dict[str, str]) -> list[str]:
    """Floor and reachability checks for every ELF in the unpacked archive."""
    shipped: dict[str, list[Path]] = {}
    for path in root.rglob("*"):
        if path.is_file():
            shipped.setdefault(path.name, []).append(path)
    problems = []
    for path in files:
        rel = path.relative_to(root)
        try:
            info = elf_dynamic_info(path)
        except (VerifyError, struct.error) as exc:
            problems.append(f"{rel}: unreadable ELF: {str(exc).replace(f'{path}: ', '')}")
            continue
        dirs = [d for d in _search_dirs(path, info) if d == root or root in d.parents]

        def reaches(soname: str) -> bool:
            if not info.executable:  # libraries: optimistic, a shipped copy wins
                return soname in shipped
            return any((d / soname).is_file() for d in dirs)

        if info.executable:
            stranded = [name for name in info.needed if name in shipped and not reaches(name)]
            if stranded:
                where = sorted({str(p.parent.relative_to(root)) for n in stranded for p in shipped[n]})
                how = (f"{info.search_tag} {':'.join(info.search)} does not reach {', '.join(where)}"
                       if info.search else f"no RUNPATH reaches {', '.join(where)}")
                problems.append(f"{rel}: {how}, so the host's {', '.join(stranded)} load "
                                "instead of the copies this archive ships")
        over: dict[tuple[str, str], tuple[str, str]] = {}  # (family, soname) -> (need, floor)
        for soname, versions in info.verneed.items():
            for version in versions:
                match = ABI_NODE_RE.match(version)
                if not match:
                    continue
                family, number = match.groups()
                if reaches(soname):
                    continue  # resolved to the archive's own copy, gated as its own ELF
                # A version node belongs to the library that defines it: the
                # loader looks for it in that soname only.
                limit = floor.get(f"{soname}:{family}", floor.get(family))
                if limit and version_key(number) > version_key(limit):
                    key = (family, soname)
                    if key not in over or version_key(number) > version_key(over[key][0]):
                        over[key] = (number, limit)
        if over:
            needs = ", ".join(f"{fam}_{num} from the host's {so} (floor {fam}_{limit})"
                              for (fam, so), (num, limit) in sorted(over.items()))
            problems.append(f"{rel}: needs {needs}")
    return problems


def pe_imports(path: Path) -> list[str]:
    """Names in the PE import directory (what the loader must find at start)."""
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise VerifyError(f"{path}: MZ file without a PE header")
    sections, opt_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    wide = struct.unpack_from("<H", data, opt)[0] == 0x20B
    if struct.unpack_from("<I", data, opt + (108 if wide else 92))[0] < 2:
        return []
    import_rva = struct.unpack_from("<I", data, opt + (112 if wide else 96) + 8)[0]
    table = [struct.unpack_from("<8sIIII", data, opt + opt_size + 40 * i)[1:] for i in range(sections)]

    def offset(rva: int) -> int:
        for vsize, vaddr, rawsize, rawptr in table:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                return rva - vaddr + rawptr
        raise VerifyError(f"{path}: import RVA {rva:#x} is outside every section")

    names: list[str] = []
    if not import_rva:
        return names
    entry = offset(import_rva)
    while len(names) < 4096:
        first_thunk, _, _, name_rva, thunk = struct.unpack_from("<IIIII", data, entry)
        if not (first_thunk or name_rva or thunk):
            break
        start = offset(name_rva)
        names.append(data[start:data.index(b"\0", start)].decode("ascii", "replace"))
        entry += 20
    return names


def pe_problems(root: Path, files: list[Path]) -> list[str]:
    problems = []
    for path in files:
        beside = {p.name.lower() for p in path.parent.iterdir() if p.is_file()}
        try:
            imports = pe_imports(path)
        except (VerifyError, struct.error, ValueError) as exc:
            problems.append(f"{path.relative_to(root)}: unreadable PE: {exc}")
            continue
        missing = [name for name in imports
                   if name.lower() not in beside
                   and name.lower() not in WINDOWS_SYSTEM_DLLS
                   and not name.lower().startswith(("api-ms-win-", "ext-ms-"))]
        if missing:
            problems.append(f"{path.relative_to(root)}: imports {', '.join(missing)}, which is neither "
                            "next to it in the archive nor a Windows system DLL; it will not start")
    return problems


def archive_member_problems(archive: Path) -> list[str]:
    """Owners, modes, link targets and empty directories, read from the member list.

    Unsafe names (absolute, .., through a symlink, links leaving the archive,
    a link target with .. after a symlink) raise before anything is
    extracted. Python < 3.12 has no extraction filter.
    """
    entries: list[tuple[str, str, int, int | None, int | None, str]] = []  # name, kind, mode, uid, gid, owner
    if archive.name.lower().endswith(".zip"):
        try:
            with zipfile.ZipFile(archive) as handle:
                for info in handle.infolist():
                    mode = (info.external_attr >> 16) if info.create_system == 3 else 0
                    kind = "dir" if info.is_dir() else ("link" if (mode & 0o170000) == 0o120000 else "file")
                    entries.append((info.filename, kind, mode & 0o7777, None, None, "", ))
        except (zipfile.BadZipFile, OSError) as exc:
            raise VerifyError(f"{archive}: not a readable shippable archive: {exc}") from exc
    else:
        try:
            with tarfile.open(archive, "r:*") as handle:
                members = handle.getmembers()
        except (tarfile.TarError, OSError) as exc:
            raise VerifyError(f"{archive}: not a readable shippable archive: {exc}") from exc
        links = set()
        regular = set()
        seen = set()
        link_paths = []
        for member in members:
            name = posixpath.normpath(member.name)
            if name in seen:
                raise VerifyError(f"{archive}: {member.name} appears twice; the second copy replaces the first")
            seen.add(name)
            if member.isfile():
                regular.add(name)
            if member.issym() or member.islnk():
                # A symlink target is relative to its directory; a hard link names a member.
                base = posixpath.dirname(name) if member.issym() else ""
                target = posixpath.normpath(posixpath.join(base, member.linkname))
                if member.linkname.startswith("/") or target == ".." or target.startswith("../"):
                    raise VerifyError(f"{archive}: link {member.name} -> {member.linkname} leaves the archive")
                if member.islnk() and target not in regular:
                    # Python < 3.12 extracts a hard link to a symlink as that symlink,
                    # at the link's own path, where its target can point outside.
                    raise VerifyError(f"{archive}: hard link {member.name} -> {member.linkname} "
                                      "does not name a regular file before it")
                link_paths.append((member, posixpath.join(base, member.linkname)))
                if member.issym():
                    links.add(name)
            elif not (member.isfile() or member.isdir()):
                raise VerifyError(f"{archive}: {member.name} is a device, fifo or other special file")
            kind = "dir" if member.isdir() else ("link" if member.issym() else "file")
            entries.append((member.name, kind, member.mode, member.uid, member.gid,
                            f"{member.uname or member.uid}:{member.gname or member.gid}"))
        for name, *_ in entries:
            parts = posixpath.normpath(name).split("/")
            if any(posixpath.join(*parts[:i]) in links for i in range(1, len(parts))):
                raise VerifyError(f"{archive}: {name} is inside a symlinked directory")
        for member, path in link_paths:
            # normpath reads a symlink as a directory. A .. after one climbs from
            # where it points: d/l1 -> .. and d/l2 -> l1/../../x leave the archive.
            walked: list[str] = []
            through_link = False
            for part in path.split("/"):
                if part == ".." and through_link:
                    raise VerifyError(f"{archive}: link {member.name} -> {member.linkname} "
                                      "uses .. after a symlink, which can leave the archive")
                if part == "..":
                    walked = walked[:-1]
                elif part not in ("", "."):
                    walked.append(part)
                    through_link = through_link or "/".join(walked) in links
    for name, *_ in entries:
        if name.startswith("/") or ".." in name.split("/"):
            raise VerifyError(f"{archive}: unsafe member name {name}")

    problems = []
    owners = sorted({owner for _, _, _, uid, gid, owner in entries if (uid, gid) not in ((0, 0), (None, None))})
    if owners:
        count = sum(1 for e in entries if (e[3], e[4]) not in ((0, 0), (None, None)))
        problems.append(f"{count} of {len(entries)} members are not owned by root:root ({', '.join(owners)}); "
                        "tar run as root keeps that owner")
    writable = [f"{name} {mode:04o}" for name, kind, mode, *_ in entries if kind != "link" and mode & 0o7022]
    if writable:
        problems.append(f"{len(writable)} members are group/world-writable or setuid/setgid "
                        f"(e.g. {', '.join(writable[:3])})")
    names = [posixpath.normpath(name) for name, *_ in entries]
    holders = set()  # every directory some member sits in, at any depth
    for name in names:
        parent = posixpath.dirname(name)
        while parent and parent not in holders:
            holders.add(parent)
            parent = posixpath.dirname(parent)
    empty = [name for name, (_, kind, *_) in zip(names, entries)
             if kind == "dir" and name != "." and name not in holders]
    if empty:
        problems.append(f"empty directories packed: {', '.join(empty)}")
    return problems


def archive_content_problems(root: Path, *, floor: dict[str, str],
                             require_model_helpers: bool = False) -> list[str]:
    elves, pes, machos, problems = [], [], [], []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        prefix = read_prefix(path, 8)
        if prefix[:4] == ELF_MAGIC:
            elves.append(path)
        elif prefix[:2] == b"MZ":
            pes.append(path)
        elif len(prefix) >= 4 and struct.unpack_from("<I", prefix, 0)[0] == MACHO_MAGIC_64LE:
            machos.append(path)
    problems += linux_elf_problems(root, elves, floor)
    problems += pe_problems(root, pes)
    for path in machos:  # btx-qt, btx-util and the helpers link the PQ code too
        try:
            problem = macho_randombytes_problem(path, str(path.relative_to(root)))
        except (VerifyError, struct.error) as exc:
            problem = f"{path.relative_to(root)}: unreadable Mach-O: {str(exc).replace(f'{path}: ', '')}"
        if problem:
            problems.append(problem)
    if require_model_helpers:
        present = {p.name for p in root.rglob("*") if p.is_file()}
        missing = [name for name in MODEL_HELPER_BINARIES
                   if not {name, f"{name}.real", f"{name}.exe"} & present]
        if missing:
            problems.append(f"model helpers missing: {', '.join(missing)}")
    return problems


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


GLIBC_CEILING = "2.38"


def verify_glibc_ceiling(root: Path, ceiling: str | None = None) -> None:
    """Fail when any packaged ELF needs a newer GLIBC than the documented floor.

    verify_launch only runs btxd. rc1 shipped btx-qt and a bundled libgnutls
    that needed GLIBC_2.43 against a documented 2.38 (issue 237), so the GUI
    could not start on Ubuntu 24.04 and the bundled lib/ broke host tools
    when put on LD_LIBRARY_PATH. Read every ELF under bin/, libexec/ and lib/.
    """
    ceiling = ceiling or os.environ.get("BTX_RELEASE_GLIBC_CEILING", GLIBC_CEILING)
    limit = version_key(ceiling)
    offenders: list[str] = []
    for sub in ("bin", "libexec", "lib"):
        for directory in sorted(root.rglob(sub)):
            if not directory.is_dir():
                continue
            for path in sorted(directory.rglob("*")):
                if path.is_symlink() or not path.is_file():
                    continue
                glibc = elf_required_versions(path).get("GLIBC")
                if glibc and version_key(glibc) > limit:
                    offenders.append(f"{path.relative_to(root)} needs GLIBC_{glibc}")
    if offenders:
        raise VerifyError(
            f"packaged files need a GLIBC newer than the documented {ceiling}: "
            + "; ".join(offenders[:8])
            + (f" (+{len(offenders) - 8} more)" if len(offenders) > 8 else "")
            + ". Build on the baseline image, or drop or re-bundle those files."
        )


def verify_archive(archive: Path, *, floor: dict[str, str] | None = None,
                   require_model_helpers: bool = False, launch: bool = True,
                   wallet_check: bool = False) -> str:
    """Gate a shippable tarball/zip: its members, every binary in it, then btxd.

    All problems are collected and reported together. btxd is launched only
    when nothing else failed, with the gate host's loader variables removed.
    wallet_check (opt-in) runs verify_wallet_derivation on the archive's btxd
    whatever else failed, so one run reports both.
    """
    if not archive.is_file():
        raise VerifyError(f"{archive}: missing archive")
    problems = archive_member_problems(archive)
    with tempfile.TemporaryDirectory(prefix="btx-verify-archive-") as tmpdir:
        dest = Path(tmpdir)
        extract_release_archive(archive, dest)
        problems += archive_content_problems(
            dest, floor=dict(DEFAULT_ABI_FLOOR if floor is None else floor),
            require_model_helpers=require_model_helpers)
        try:
            verify_glibc_ceiling(dest)
        except VerifyError as exc:
            problems.append(str(exc).replace(f"{dest}{os.sep}", ""))
        how = ""
        btxd = None
        try:
            btxd = find_packaged_btxd(dest)
            how = verify_path_for_ship(btxd, launch=launch and not problems, clean_env=True)
            cli = find_packaged_cli(dest)
            if cli is not None:
                cli = resolve_verify_target(cli)
                if classify(cli) == "other":
                    raise VerifyError(
                        f"{cli}: not an ELF, Mach-O, or PE binary (refusing to ship an untyped file)"
                    )
                verify_binary(cli)
                how = f"{how}+cli"
        except VerifyError as exc:
            problems.append(str(exc).replace(f"{dest}{os.sep}", ""))
        if wallet_check and btxd is not None:
            try:
                how = f"{how}+{run_wallet_check(btxd, clean_env=True)}"
                if problems:  # the FAIL lists only problems: say that this part passed
                    print(f"verify_release_btxd: note {archive.name}: "
                          f"{resolve_verify_target(btxd).relative_to(dest)}: wallet check passed",
                          file=sys.stderr)
            except VerifyError as exc:
                problems.append(str(exc).replace(f"{dest}{os.sep}", ""))
        problems = list(dict.fromkeys(problems))  # one binary can fail two passes the same way
        if problems:
            raise VerifyError(f"{archive.name}: {len(problems)} problem(s)\n  - " + "\n  - ".join(problems))
        return f"{how}+contents"


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
        "--floor",
        action="append",
        default=[],
        metavar="[SONAME:]NAME=VERSION",
        help="Override one floor entry: " + ", ".join(f"{k}={v}" for k, v in DEFAULT_ABI_FLOOR.items())
        + ". NAME alone also replaces that NAME's per-library entries. GLIBC is the separate "
        "ceiling (BTX_RELEASE_GLIBC_CEILING).",
    )
    parser.add_argument(
        "--require-model-helpers",
        action="store_true",
        help="--archive: FAIL when any model helper (" + ", ".join(MODEL_HELPER_BINARIES) + ") is missing.",
    )
    parser.add_argument(
        "--no-launch",
        action="store_true",
        help="--archive: run every static check but never execute btxd (inspecting a third-party "
        "archive). A release cut must launch.",
    )
    parser.add_argument(
        "--run-wallet-check",
        action="store_true",
        help="Also start btxd -regtest in a temporary datadir and require index 0 of a new wallet's "
        "own private receive descriptor to derive the wallet's first address, twice (ML-DSA keys "
        "must follow from the seed). Takes a few seconds. FAIL on a host that cannot run the btxd.",
    )
    parser.add_argument(
        "--allow-non-binary",
        action="store_true",
        help="Exit 0 on non-ELF/Mach-O/PE inputs (unit-test stubs only; never for release).",
    )
    args = parser.parse_args(argv)
    if not args.binaries and not args.archives:
        parser.error("pass at least one binary or --archive")
    if args.run_wallet_check and args.no_launch:
        parser.error("--run-wallet-check runs btxd; drop --no-launch")
    floor = dict(DEFAULT_ABI_FLOOR)
    overrides: dict[str, str] = {}
    for item in args.floor:
        name, _, version = item.partition("=")
        if not FLOOR_NAME_RE.match(name) or not re.fullmatch(r"[0-9]+(\.[0-9]+)*", version):
            parser.error(f"bad floor {item!r}; expected [<soname>:]{{{','.join(ABI_FAMILIES)}}}=<version>, "
                         f"e.g. OPENSSL=3.2.0 or libssl.so.3:OPENSSL=3.0.0")
        overrides[name] = version
    for name in overrides:
        if ":" not in name:  # OPENSSL=3.2.0 means every library's OPENSSL floor
            for key in [k for k in floor if k.endswith(f":{name}")]:
                del floor[key]
    floor.update(overrides)
    failures = 0
    for raw in args.archives:
        path = raw.expanduser().resolve()
        try:
            how = verify_archive(path, floor=floor, require_model_helpers=args.require_model_helpers,
                                 launch=not args.no_launch, wallet_check=args.run_wallet_check)
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
        failed = False
        try:
            how = verify_path_for_ship(path)
        except VerifyError as exc:
            print(f"verify_release_btxd: FAIL {exc}", file=sys.stderr)
            failed = True
        if args.run_wallet_check and is_daemon(path):
            # Run even after a static FAIL, so one run reports both.
            try:
                check = run_wallet_check(path, clean_env=False)
                if failed:
                    print(f"verify_release_btxd: note {path}: wallet check passed", file=sys.stderr)
                else:
                    how = f"{how}+{check}"
            except VerifyError as exc:
                print(f"verify_release_btxd: FAIL {exc}", file=sys.stderr)
                failed = True
        if failed:
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
