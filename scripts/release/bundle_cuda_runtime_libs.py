#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/licenses/mit-license.php.
"""Copy CUDA toolkit shared libraries next to a CUDA btxd and set RPATH $ORIGIN.

libcublasLt is not provided by the NVIDIA driver. A CUDA release tarball
that ships only btxd fails at launch with:

    libcublasLt.so.13: cannot open shared object file

This script copies the CUDA-toolkit DT_NEEDED libs (cublasLt and siblings)
next to the binary and runs patchelf --set-rpath '$ORIGIN'. libcuda.so.* is
left to the driver and is not bundled.

Intended for native CUDA tarballs. Guix builds remain rpath-free; they must
not call this.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


CUDA_LIB_RE = re.compile(
    r"^lib(cublasLt|cublas|cudart|nvJitLink|nvrtc|culibos)(\.so(\.\d+)*)$"
)
SKIP_RE = re.compile(r"^libcuda\.so")


class BundleError(RuntimeError):
    pass


def parse_ldd(path: Path) -> list[tuple[str, Path | None]]:
    result = subprocess.run(
        ["ldd", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise BundleError(f"ldd failed on {path}: {result.stderr.strip()}")
    entries: list[tuple[str, Path | None]] = []
    for line in result.stdout.splitlines():
        # "libfoo.so.1 => /lib/libfoo.so.1 (0x...)" or "libfoo.so.1 => not found"
        match = re.match(r"\s*(\S+)\s+=>\s+(\S+)", line)
        if not match:
            continue
        soname, rest = match.group(1), match.group(2)
        if rest == "not":
            entries.append((soname, None))
            continue
        entries.append((soname, Path(rest)))
    return entries


def is_cuda_toolkit_lib(soname: str) -> bool:
    if SKIP_RE.match(soname):
        return False
    return CUDA_LIB_RE.match(soname) is not None


def patchelf_origin(path: Path) -> None:
    result = subprocess.run(
        ["patchelf", "--force-rpath", "--set-rpath", "$ORIGIN", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise BundleError(f"patchelf failed on {path}: {result.stderr.strip()}")


def bundle(btxd: Path) -> list[Path]:
    btxd = btxd.resolve()
    dest_dir = btxd.parent
    copied: dict[str, Path] = {}
    pending = [btxd]
    seen: set[Path] = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        for soname, resolved in parse_ldd(current):
            if not is_cuda_toolkit_lib(soname):
                if resolved is None and soname.startswith("libcublas"):
                    raise BundleError(
                        f"{current} needs {soname} but ldd reports not found; "
                        "install the CUDA toolkit matching this binary"
                    )
                continue
            if soname in copied:
                continue
            if resolved is None:
                raise BundleError(
                    f"{current} needs {soname} but it is not on the loader path"
                )
            dest = dest_dir / resolved.name
            if dest.resolve() != resolved.resolve():
                shutil.copy2(resolved, dest)
            dest.chmod(dest.stat().st_mode | 0o111)
            copied[soname] = dest
            pending.append(dest)
    if not copied:
        raise BundleError(
            f"{btxd} has no libcublasLt/CUDA-toolkit DT_NEEDED entries; "
            "this is not a CUDA btxd, or cublasLt was statically linked"
        )
    patchelf_origin(btxd)
    for lib in copied.values():
        patchelf_origin(lib)
    return [btxd, *copied.values()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("btxd", type=Path, help="Path to a CUDA btxd (or btxd.real)")
    args = parser.parse_args(argv)
    if not args.btxd.is_file():
        print(f"bundle_cuda_runtime_libs: FAIL missing {args.btxd}", file=sys.stderr)
        return 1
    try:
        bundled = bundle(args.btxd)
    except BundleError as exc:
        print(f"bundle_cuda_runtime_libs: FAIL {exc}", file=sys.stderr)
        return 1
    print("bundle_cuda_runtime_libs: PASS")
    for path in bundled:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
