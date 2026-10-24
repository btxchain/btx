#!/usr/bin/env python3
"""Build actual Windows PE components; never label cross-compilation a native run."""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import run_tests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler", type=Path, required=True, help="MinGW x86_64 g++-posix executable")
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    cxx = args.compiler.resolve()
    cc = cxx.with_name(cxx.name.replace("g++", "gcc"))
    if not cc.is_file():
        raise RuntimeError(f"matching C compiler missing: {cc}")
    build = args.build_dir.resolve()
    build.mkdir(parents=True, exist_ok=True)
    root = run_tests.ROOT
    flags = ["-DWIN32", "-D_WINDOWS", "-D_MT", "-D_WIN32_WINNT=0x0A00", "-DWINVER=0x0A00",
             "-DNOMINMAX", "-DWIN32_LEAN_AND_MEAN", "-O1", "-ffunction-sections", "-fdata-sections"]
    includes = [f"-I{root / path}" for path in ["src/compat/mingw", "src", "src/univalue/include",
                "src/libbitcoinpqc/include", "src/libbitcoinpqc/dilithium/ref"]]

    def compile_one(source):
        obj = build / (source.replace("/", "_") + ".o")
        if source.endswith(".c"):
            compiler = [cc, "-std=c11", "-DDILITHIUM_MODE=2", "-DCUSTOM_RANDOMBYTES=1", "-Drandombytes=btx_mldsa_randombytes"]
        else:
            compiler = [cxx, "-std=c++20"]
        # COFF unwind sections can retain unused identity/delegation methods
        # in a component link. LTO removes those unreachable methods without
        # providing substitute crypto/RNG functions or changing production.
        if source == "src/modelnet/identity.cpp":
            compiler.append("-flto")
        run_tests.run(compiler + flags + includes + ["-c", root / source, "-o", obj])
        return obj

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        objects = list(pool.map(compile_one, run_tests.CPP_SOURCES + run_tests.C_SOURCES))
    binaries = {}
    for name, source in [
        ("btx-native-qualify", "src/modelnet/native_qualification_main.cpp"),
        ("btx-guardd", "src/btx-guardd.cpp"),
        ("guard-supervisor-tests", "test/util/native_qualification/guard_supervisor_tests.cpp"),
        ("windows-sandbox-probe", "test/util/native_qualification/windows_sandbox_probe.cpp"),
        ("windows-release-file-tests", "test/util/native_qualification/windows_release_file_tests.cpp"),
    ]:
        obj = compile_one(source)
        binary = build / (name + ".exe")
        run_tests.run([cxx, "-flto", "-static", "-Wl,--gc-sections", obj, *objects, "-pthread",
                       "-lbcrypt", "-luserenv", "-ladvapi32", "-lole32", "-lws2_32", "-o", binary])
        # PE/COFF signature proves we produced target artifacts, not host ELFs.
        data = binary.read_bytes()
        offset = int.from_bytes(data[60:64], "little")
        if data[:2] != b"MZ" or data[offset:offset + 4] != b"PE\0\0":
            raise RuntimeError(f"not a Windows executable: {binary}")
        binaries[name] = {"path": str(binary), "bytes": len(data), "sha384": hashlib.sha384(data).hexdigest()}
    report = {"schema": "BTX/WindowsCrossCompile/v1", "cross_compile_and_link": "PASS", "native_windows_execution": "NOT_RUN",
              "compiler": run_tests.run([cxx, "--version"]).stdout.splitlines()[0], "binaries": binaries,
              "btx_deployment_qualified": False, "automatic_spend_atoms": "0"}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
