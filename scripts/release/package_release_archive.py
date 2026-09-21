#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Create a canonical BTX binary archive for one release platform.

The generated archive contains the release binaries plus the fast-start and
mining helper scripts needed for a download-and-go operator flow.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path
import zipfile
import importlib.util


ROOT = Path(__file__).resolve().parents[2]
SUPPORT_FILES_MANIFEST = Path(__file__).with_name("support_files.txt")


def load_support_files(manifest_path: Path = SUPPORT_FILES_MANIFEST) -> list[str]:
    support_files: list[str] = []
    for raw_line in manifest_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        support_files.append(line)
    return support_files


PLATFORM_CONFIGS = {
    "linux-x86_64": {
        "triple": "x86_64-linux-gnu",
        "archive_format": "tar.gz",
        "exe_suffix": "",
    },
    "linux-x86_64-cuda12": {
        "triple": "x86_64-linux-gnu-cuda12",
        "archive_format": "tar.gz",
        "exe_suffix": "",
    },
    "linux-x86_64-cuda13": {
        "triple": "x86_64-linux-gnu-cuda13",
        "archive_format": "tar.gz",
        "exe_suffix": "",
    },
    "linux-arm64": {
        "triple": "aarch64-linux-gnu",
        "archive_format": "tar.gz",
        "exe_suffix": "",
    },
    "windows-x86_64": {
        "triple": "x86_64-w64-mingw32",
        "archive_format": "zip",
        "exe_suffix": ".exe",
    },
    "macos-x86_64": {
        "triple": "x86_64-apple-darwin",
        "archive_format": "tar.gz",
        "exe_suffix": "",
    },
    "macos-arm64": {
        "triple": "arm64-apple-darwin",
        "archive_format": "tar.gz",
        "exe_suffix": "",
    },
}
# Operator-facing aliases for the three 0.34.5 ship targets. Same bytes as the
# canonical ids; extra keys so a cut that says linux-x86_64-cpu /
# linux-x86_64-cuda / macos-arm64-metal cannot bypass the gate by using a
# name the packager does not recognize. Bare cuda is the published 0.34 name
# (no 12/13 suffix); it packs the same tree as cuda12.
PLATFORM_CONFIGS["linux-x86_64-cpu"] = dict(PLATFORM_CONFIGS["linux-x86_64"])
PLATFORM_CONFIGS["linux-x86_64-cuda"] = dict(PLATFORM_CONFIGS["linux-x86_64-cuda12"])
PLATFORM_CONFIGS["macos-arm64-metal"] = dict(PLATFORM_CONFIGS["macos-arm64"])
SUPPORT_FILES = load_support_files()
# Packaged next to btxd when present (0.34.7 Native Model Network + 0.34.8
# first-run / hosted HCP / CRL planes + Metal probe).
OPTIONAL_SIBLING_BINARIES = (
    "btx-modeld",
    "btx-modelcheck",
    "btx-open",
    "btx-matmul-backend-info",
    "btx-hcpd",
    "btx-hosted",
    "btx-capability",
    "btx-capabilityd",
)

LINUX_WRAPPER = r"""#!/bin/sh
set -eu
SELF_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REAL="$SELF_DIR/../libexec/@BINARY@.real"
if [ ! -x "$REAL" ]; then
  echo "BTX packaged binary is missing: $REAL" >&2
  exit 127
fi

# Unprivileged newer-userspace prefix (dpkg-deb -x libc6 libstdc++6 libgcc-s1).
# When set, skip the host glibc check: the prefix loader is what will run.
if [ -n "${BTX_GLIBC_PREFIX:-}" ]; then
  BTX_GLIBC_LOADER="${BTX_GLIBC_PREFIX}/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
  BTX_GLIBC_LIBDIR="${BTX_GLIBC_PREFIX}/usr/lib/x86_64-linux-gnu"
  if [ ! -x "$BTX_GLIBC_LOADER" ]; then
    echo "BTX_GLIBC_PREFIX is set but the loader is missing: $BTX_GLIBC_LOADER" >&2
    echo "Expected a dpkg-deb -x of libc6 (and libstdc++6, libgcc-s1) into $BTX_GLIBC_PREFIX" >&2
    exit 127
  fi
  exec "$BTX_GLIBC_LOADER" --library-path "$BTX_GLIBC_LIBDIR" "$REAL" "$@"
fi

btx_max_ver_sym() {
  _file=$1
  _pfx=$2
  _pat="${_pfx}_[0-9]+(\.[0-9]+)+"
  _out=""
  if command -v objdump >/dev/null 2>&1; then
    _out=$(objdump -T "$_file" 2>/dev/null | grep -oE "$_pat" || true)
  fi
  if [ -z "$_out" ] && command -v readelf >/dev/null 2>&1; then
    _out=$(readelf -V "$_file" 2>/dev/null | grep -oE "$_pat" || true)
  fi
  if [ -z "$_out" ]; then
    _out=$(grep -aoE "$_pat" "$_file" 2>/dev/null || true)
  fi
  printf '%s\n' "$_out" | sort -Vu | tail -1
}

btx_ver_lt() {
  [ "$1" = "$2" ] && return 1
  printf '%s\n%s\n' "$1" "$2" | sort -C -V
}

if command -v ldd >/dev/null 2>&1; then
  missing="$(ldd "$REAL" 2>/dev/null | awk '/=> not found/ {print $1}' | tr '\n' ' ')"
  if [ -n "$missing" ]; then
    echo "BTX @BINARY@ is missing runtime libraries: $missing" >&2
    echo "Ubuntu/Debian hint: sudo apt-get install libevent-2.1-7t64 libevent-core-2.1-7t64 libevent-extra-2.1-7t64 libevent-pthreads-2.1-7t64@EXTRA_HINT@" >&2
    echo "  Ubuntu 24.04 / Debian 13 use the t64 spellings above; Ubuntu 22.04 / Debian 12 use libevent-2.1-7 libevent-core-2.1-7 libevent-extra-2.1-7 libevent-pthreads-2.1-7." >&2
    echo "General hint: install the equivalent libevent, sqlite3, and zeromq runtime packages for your distribution." >&2
    echo "A missing soname is not the GLIBC_2.38 / GLIBCXX_3.4.32 case: there the .so is present and only the version node is absent." >&2
    echo "The packaged binary is located at: $REAL" >&2
    exit 127
  fi

  need_glibc=$(btx_max_ver_sym "$REAL" GLIBC)
  host_glibc=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
  if [ -z "$host_glibc" ]; then
    host_glibc=$(ldd --version 2>/dev/null | awk 'NR==1 {
      for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\.[0-9]+/) { print $i; exit }
    }')
  fi
  if [ -n "$need_glibc" ] && [ -n "$host_glibc" ]; then
    need_glibc_v=${need_glibc#GLIBC_}
    if btx_ver_lt "$host_glibc" "$need_glibc_v"; then
      echo "BTX @BINARY@ requires $need_glibc (this host provides GLIBC_${host_glibc})." >&2
      echo "Debian 12 (glibc 2.36) and Ubuntu 22.04 (2.35) cannot load this archive; Ubuntu 24.04 / Debian 13 can." >&2
      echo "ldd reported no missing .so files because libc is present; the version nodes are not." >&2
      echo "Build from source on this host, or unpack Debian 13 libc6/libstdc++6/libgcc-s1 into a private prefix and set BTX_GLIBC_PREFIX. See doc/btx-download-and-go.md." >&2
      echo "The packaged binary is located at: $REAL" >&2
      exit 127
    fi
  fi

  need_cxx=$(btx_max_ver_sym "$REAL" GLIBCXX)
  stdcpp=$(ldd "$REAL" 2>/dev/null | awk '/libstdc\+\+\.so/ {print $3; exit}')
  have_cxx=""
  if [ -n "$stdcpp" ] && [ -e "$stdcpp" ]; then
    have_cxx=$(btx_max_ver_sym "$stdcpp" GLIBCXX)
  fi
  if [ -n "$need_cxx" ] && [ -n "$have_cxx" ]; then
    need_cxx_v=${need_cxx#GLIBCXX_}
    have_cxx_v=${have_cxx#GLIBCXX_}
    if btx_ver_lt "$have_cxx_v" "$need_cxx_v"; then
      echo "BTX @BINARY@ requires $need_cxx (this host libstdc++ provides $have_cxx)." >&2
      echo "GLIBCXX_3.4.32 is libstdc++ from GCC 13; Debian 12 / Ubuntu 22.04 default libstdc++ cannot load this archive." >&2
      echo "ldd reported no missing .so files because libstdc++.so.6 is present; the version nodes are not." >&2
      echo "Build from source on this host, or unpack Debian 13 libc6/libstdc++6/libgcc-s1 into a private prefix and set BTX_GLIBC_PREFIX. See doc/btx-download-and-go.md." >&2
      echo "The packaged binary is located at: $REAL" >&2
      exit 127
    fi
  fi
fi
exec "$REAL" "$@"
"""


def source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None or not raw.strip():
        return 0
    return int(raw.strip())


def wrapper_payload(binary_name: str, platform_id: str) -> str | None:
    if platform_id.startswith("linux-"):
        extra_hint = ""
        if binary_name == "btxd":
            extra_hint = " libsqlite3-0 libzmq5"
        # ldd's "=> not found" only catches missing sonames. Debian 12 / Ubuntu
        # 22.04 have libc.so.6 and libstdc++.so.6, so that check passes, then
        # the loader dies on GLIBC_2.38 / GLIBCXX_3.4.32. Prefer objdump -T
        # (then readelf -V, then a grep of the ELF) against getconf /
        # libstdc++ version nodes. BTX_GLIBC_PREFIX skips the host check and
        # execs through a private loader (unprivileged dpkg-deb -x prefix).
        return (
            LINUX_WRAPPER.replace("@BINARY@", binary_name).replace(
                "@EXTRA_HINT@", extra_hint
            )
        )
    if platform_id.startswith("macos-"):
        return f"""#!/bin/sh
set -eu
SELF_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REAL="$SELF_DIR/../libexec/{binary_name}.real"
if [ ! -x "$REAL" ]; then
  echo "BTX packaged binary is missing: $REAL" >&2
  exit 127
fi
if command -v otool >/dev/null 2>&1; then
  missing=""
  while IFS= read -r dep; do
    case "$dep" in
      ""|@*|/System/*|/usr/lib/*) continue ;;
    esac
    if [ ! -e "$dep" ]; then
      missing="$missing $dep"
    fi
  done <<EOF
$(otool -L "$REAL" | awk 'NR>1 {{print $1}}')
EOF
  if [ -n "$missing" ]; then
    echo "BTX {binary_name} is missing runtime libraries:$missing" >&2
    echo "Install the matching Homebrew runtime packages with: brew install libevent sqlite zeromq" >&2
    echo "Apple Silicon default prefixes: /opt/homebrew/opt/libevent/lib /opt/homebrew/opt/sqlite/lib /opt/homebrew/opt/zeromq/lib" >&2
    echo "Intel default prefixes: /usr/local/opt/libevent/lib /usr/local/opt/sqlite/lib /usr/local/opt/zeromq/lib" >&2
    echo "The packaged binary is located at: $REAL" >&2
    exit 127
  fi
fi
exec "$REAL" "$@"
"""
    return None


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, help="Directory where the archive will be written.")
    parser.add_argument("--version", required=True, help="Release version string, for example 29.2.")
    parser.add_argument(
        "--platform-id",
        required=True,
        choices=sorted(PLATFORM_CONFIGS.keys()),
        help="Canonical release platform id.",
    )
    parser.add_argument("--btxd", required=True, help="Path to the btxd binary for this platform.")
    parser.add_argument("--btx-cli", required=True, help="Path to the btx-cli binary for this platform.")
    parser.add_argument(
        "--btx-util",
        help="Path to the btx-util binary for this platform. Defaults to a sibling of btx-cli or btxd.",
    )
    parser.add_argument("--matmul-metallib", help="Optional precompiled MatMul Metal library for macOS archives.")
    parser.add_argument("--oracle-metallib", help="Optional precompiled oracle Metal library for macOS archives.")
    parser.add_argument(
        "--metal-lib-dir",
        help="Directory of precompiled *.metallib files copied to libexec/metal/ on macOS archives.",
    )
    parser.add_argument(
        "--source-root",
        default=str(ROOT),
        help="Repository root used to source helper scripts and docs (default: repo root).",
    )
    parser.add_argument(
        "--archive-name",
        help="Optional output filename override. Defaults to btx-<version>-<target>.<ext>.",
    )
    return parser.parse_args(argv)


def ensure_input_file(path: Path, label: str) -> Path:
    if not path.is_file():
        raise FileNotFoundError(f"Missing {label}: {path}")
    return path


def _load_verify_module():
    script = Path(__file__).with_name("verify_release_btxd.py")
    spec = importlib.util.spec_from_file_location("verify_release_btxd", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_shipped_btxd(btxd_path: Path) -> None:
    """Refuse to package a btxd that advertises ZMQ without linking it.

    The path must be the real ELF/Mach-O/PE (build-tree bin/btxd, or already
    libexec/btxd.real). A packaged #!/bin/sh wrapper is not a binary; ldd
    and otool on it pass vacuously. An unrecognized file is FAIL — a skipped
    gate is how issues 111 and 122 shipped twice.
    """
    module = _load_verify_module()
    if module.is_shell_wrapper(btxd_path):
        raise RuntimeError(
            f"{btxd_path}: pass the real ELF/Mach-O (build/bin/btxd or "
            "libexec/btxd.real), not the packaged bin/btxd wrapper"
        )
    kind = module.classify(btxd_path)
    if kind == "other":
        raise RuntimeError(
            f"{btxd_path}: not an ELF, Mach-O, or PE binary; refusing to package "
            "an unrecognized file (a skipped gate is how issues 111 and 122 shipped)"
        )
    module.verify_path_for_ship(btxd_path)


def verify_shipped_cli(btx_cli_path: Path) -> None:
    """Refuse Homebrew dylibs / untyped files in btx-cli (same bar as btxd)."""
    module = _load_verify_module()
    if module.is_shell_wrapper(btx_cli_path):
        raise RuntimeError(
            f"{btx_cli_path}: pass the real ELF/Mach-O, not the packaged bin/btx-cli wrapper"
        )
    kind = module.classify(btx_cli_path)
    if kind == "other":
        raise RuntimeError(
            f"{btx_cli_path}: not an ELF, Mach-O, or PE binary; refusing to package "
            "an unrecognized file"
        )
    module.verify_binary(btx_cli_path)


# Back-compat name used by older tests and comments.
verify_shipped_macos_cli = verify_shipped_cli


def verify_shipped_helper(path: Path) -> None:
    """Portability gate for helpers (modeld, modelcheck, backend-info).

    These binaries are not btxd: they must not load Homebrew dylibs, but they
    do not carry the ENABLE_ZMQ help text. verify_shipped_cli would demand
    ZMQ on any name that is not btx-cli.
    """
    module = _load_verify_module()
    if module.is_shell_wrapper(path):
        raise RuntimeError(
            f"{path}: pass the real ELF/Mach-O, not a packaged bin/ wrapper"
        )
    kind = module.classify(path)
    if kind == "other":
        raise RuntimeError(
            f"{path}: not an ELF, Mach-O, or PE binary; refusing to package "
            "an unrecognized helper"
        )
    if kind == "macho":
        module.verify_macos_portable(path)


def resolve_optional_sibling_binaries(btxd_path: Path, exe_suffix: str) -> list[tuple[Path, str]]:
    found: list[tuple[Path, str]] = []
    for name in OPTIONAL_SIBLING_BINARIES:
        candidate = btxd_path.parent / f"{name}{exe_suffix}"
        if candidate.is_file():
            found.append((candidate, f"{name}{exe_suffix}"))
    return found


def resolve_btx_util_path(explicit_path: Path | None, btxd_path: Path, btx_cli_path: Path, exe_suffix: str) -> Path:
    if explicit_path is not None:
        return ensure_input_file(explicit_path, "btx-util binary")

    util_name = f"btx-util{exe_suffix}"
    candidates = [
        btx_cli_path.parent / util_name,
        btxd_path.parent / util_name,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "Missing btx-util binary; release archives must ship btx-util so PQ-signed auto-updates can verify. "
        "Pass --btx-util or place it next to btx-cli/btxd."
    )


def archive_filename(version: str, platform_id: str, override: str | None) -> str:
    if override:
        return override
    config = PLATFORM_CONFIGS[platform_id]
    suffix = ".zip" if config["archive_format"] == "zip" else ".tar.gz"
    return f"btx-{version}-{config['triple']}{suffix}"


def stage_release_tree(
    *,
    version: str,
    platform_id: str,
    btxd_path: Path,
    btx_cli_path: Path,
    btx_util_path: Path | None,
    matmul_metallib_path: Path | None,
    oracle_metallib_path: Path | None,
    metal_lib_dir: Path | None,
    source_root: Path,
    temp_root: Path,
) -> tuple[Path, list[str]]:
    config = PLATFORM_CONFIGS[platform_id]
    release_root = temp_root / f"btx-{version}"
    included: list[str] = []

    bin_dir = release_root / "bin"
    libexec_dir = release_root / "libexec"
    bin_dir.mkdir(parents=True, exist_ok=True)

    binary_pairs = [
        (ensure_input_file(btxd_path, "btxd binary"), f"btxd{config['exe_suffix']}"),
        (ensure_input_file(btx_cli_path, "btx-cli binary"), f"btx-cli{config['exe_suffix']}"),
        (
            resolve_btx_util_path(btx_util_path, btxd_path, btx_cli_path, config["exe_suffix"]),
            f"btx-util{config['exe_suffix']}",
        ),
        *resolve_optional_sibling_binaries(btxd_path, config["exe_suffix"]),
    ]
    verify_shipped_btxd(btxd_path)
    verify_shipped_cli(btx_cli_path)
    for helper_path, _helper_name in binary_pairs[3:]:
        verify_shipped_helper(helper_path)

    for source, dest_name in binary_pairs:
        wrapper = wrapper_payload(dest_name.removesuffix(config["exe_suffix"]), platform_id)
        if wrapper is None:
            destination = bin_dir / dest_name
            shutil.copy2(source, destination)
            included.append(str(destination.relative_to(release_root)))
            continue

        libexec_dir.mkdir(parents=True, exist_ok=True)
        real_destination = libexec_dir / f"{dest_name.removesuffix(config['exe_suffix'])}.real"
        shutil.copy2(source, real_destination)
        real_destination.chmod(0o755)
        included.append(str(real_destination.relative_to(release_root)))

        destination = bin_dir / dest_name
        destination.write_text(wrapper, encoding="utf-8")
        destination.chmod(0o755)
        included.append(str(destination.relative_to(release_root)))

    if "cuda" in platform_id:
        # libcublasLt and toolkit siblings live next to btxd.real ($ORIGIN).
        # bundle_cuda_runtime_libs.py must have been run on --btxd first.
        cuda_lib_re = re.compile(
            r"^lib(cublasLt|cublas|cudart|nvJitLink|nvrtc|culibos)(\.so(\.\d+)*)$"
        )
        libexec_dir.mkdir(parents=True, exist_ok=True)
        for source in sorted(btxd_path.parent.glob("lib*.so*")):
            if not cuda_lib_re.match(source.name):
                continue
            destination = libexec_dir / source.name
            shutil.copy2(source, destination)
            destination.chmod(destination.stat().st_mode | 0o111)
            included.append(str(destination.relative_to(release_root)))

    if platform_id.startswith("macos-"):
        metallib_by_name: dict[str, Path] = {}
        if metal_lib_dir is not None:
            if not metal_lib_dir.is_dir():
                raise FileNotFoundError(f"Missing Metal library directory: {metal_lib_dir}")
            for source in sorted(metal_lib_dir.glob("*.metallib")):
                metallib_by_name[source.name] = source
        if matmul_metallib_path is not None:
            metallib_by_name["matmul_accel_kernels.metallib"] = matmul_metallib_path
        if oracle_metallib_path is not None:
            metallib_by_name["oracle_accel_kernels.metallib"] = oracle_metallib_path
        metal_dir = libexec_dir / "metal"
        for dest_name, source_path in sorted(metallib_by_name.items()):
            source = ensure_input_file(source_path, dest_name)
            metal_dir.mkdir(parents=True, exist_ok=True)
            destination = metal_dir / dest_name
            shutil.copy2(source, destination)
            destination.chmod(0o644)
            included.append(str(destination.relative_to(release_root)))

    for relative_path in SUPPORT_FILES:
        source = ensure_input_file(source_root / relative_path, relative_path)
        destination = release_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        included.append(str(destination.relative_to(release_root)))

    return release_root, sorted(included)


def normalized_tarinfo(tarinfo: tarfile.TarInfo, epoch: int) -> tarfile.TarInfo:
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.uname = "root"
    tarinfo.gname = "root"
    tarinfo.mtime = epoch
    if tarinfo.isdir():
        tarinfo.mode = 0o755
    elif tarinfo.isfile():
        tarinfo.mode = 0o755 if (tarinfo.mode & 0o111) else 0o644
    return tarinfo


def write_tar_gz(archive_path: Path, release_root: Path) -> None:
    epoch = source_date_epoch()
    with archive_path.open("wb") as raw_handle:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_handle, mtime=epoch, compresslevel=9) as gzip_handle:
            with tarfile.open(fileobj=gzip_handle, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in [release_root, *sorted(release_root.rglob("*"))]:
                    arcname = str(path.relative_to(release_root.parent))
                    if path.is_dir():
                        tarinfo = normalized_tarinfo(archive.gettarinfo(str(path), arcname), epoch)
                        archive.addfile(tarinfo)
                        continue
                    tarinfo = normalized_tarinfo(archive.gettarinfo(str(path), arcname), epoch)
                    with path.open("rb") as handle:
                        archive.addfile(tarinfo, handle)


def zip_info_for(path: Path, arcname: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(arcname)
    info.date_time = (1980, 1, 1, 0, 0, 0)
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = 0o755 if (path.stat().st_mode & 0o111) else 0o644
    info.external_attr = mode << 16
    return info


def write_zip(archive_path: Path, release_root: Path) -> None:
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(release_root.rglob("*")):
            if not path.is_file():
                continue
            archive.writestr(zip_info_for(path, str(path.relative_to(release_root.parent))), path.read_bytes())


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    source_root = Path(args.source_root).expanduser().resolve()
    archive_path = output_dir / archive_filename(args.version, args.platform_id, args.archive_name)

    with tempfile.TemporaryDirectory(prefix="btx-release-archive-") as temp_dir:
        temp_root = Path(temp_dir)
        release_root, included_paths = stage_release_tree(
            version=args.version,
            platform_id=args.platform_id,
            btxd_path=Path(args.btxd).expanduser().resolve(),
            btx_cli_path=Path(args.btx_cli).expanduser().resolve(),
            btx_util_path=Path(args.btx_util).expanduser().resolve() if args.btx_util else None,
            matmul_metallib_path=Path(args.matmul_metallib).expanduser().resolve() if args.matmul_metallib else None,
            oracle_metallib_path=Path(args.oracle_metallib).expanduser().resolve() if args.oracle_metallib else None,
            metal_lib_dir=Path(args.metal_lib_dir).expanduser().resolve() if args.metal_lib_dir else None,
            source_root=source_root,
            temp_root=temp_root,
        )
        if PLATFORM_CONFIGS[args.platform_id]["archive_format"] == "zip":
            write_zip(archive_path, release_root)
        else:
            write_tar_gz(archive_path, release_root)

    json.dump(
        {
            "archive_path": str(archive_path),
            "archive_name": archive_path.name,
            "platform_id": args.platform_id,
            "archive_format": PLATFORM_CONFIGS[args.platform_id]["archive_format"],
            "included_paths": included_paths,
        },
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
