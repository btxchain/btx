#!/usr/bin/env python3
"""Compile real PR245 native components and run bounded integration tests.

This runner needs only C/C++20 compilers. It links the repository's actual
ML-DSA implementation; no crypto, loader, parser or sandbox function is mocked.
It is a component build, not a full btxd build or deployment qualification.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


CPP_SOURCES = ["src/crypto/sha384.cpp", "src/modelnet/identity.cpp", "src/modelnet/load01/load01.cpp",
       "src/modelnet/cap02/cap02.cpp", "src/modelnet/hire01/hire01.cpp",
       "src/modelnet/swarm_confine.cpp", "src/modelnet/swarm_fsjail.cpp", "src/modelnet/swarm_windows_sandbox.cpp",
       "src/modelnet/guard_machine.cpp", "src/modelnet/guard_supervisor.cpp",
       "src/univalue/lib/univalue.cpp", "src/univalue/lib/univalue_get.cpp",
       "src/univalue/lib/univalue_read.cpp", "src/univalue/lib/univalue_write.cpp"]
C_SOURCES = [f"src/libbitcoinpqc/src/ml_dsa/{f}.c" for f in ["utils", "keygen", "sign", "verify"]]
C_SOURCES += [f"src/libbitcoinpqc/dilithium/ref/{f}.c" for f in [
    "sign", "packing", "polyvec", "poly", "ntt", "reduce", "rounding", "fips202", "symmetric-shake", "randombytes_custom"]]

def run(argv, **kwargs):
    result = subprocess.run([str(a) for a in argv], text=True, capture_output=True, timeout=180, **kwargs)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv}\n{result.stdout}\n{result.stderr}")
    return result


def build(build_dir: Path):
    cc, cxx = os.environ.get("CC", "cc"), os.environ.get("CXX", "c++")
    sections = ["-ffunction-sections", "-fdata-sections"]
    includes = [f"-I{ROOT / p}" for p in ["src", "src/univalue/include", "src/libbitcoinpqc/include", "src/libbitcoinpqc/dilithium/ref"]]
    def compile_one(source):
        obj = build_dir / (source.replace("/", "_") + ".o")
        if source.endswith(".c"):
            args = [cc, "-std=c11", "-DDILITHIUM_MODE=2", "-DCUSTOM_RANDOMBYTES=1", "-Drandombytes=btx_mldsa_randombytes"]
        else:
            args = [cxx, "-std=c++20"]
        run(args + ["-O1", *sections, *includes, "-c", ROOT / source, "-o", obj])
        return obj
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        objects = list(pool.map(compile_one, CPP_SOURCES + C_SOURCES))
    link_gc = ["-Wl,-dead_strip"] if platform.system() == "Darwin" else ["-Wl,--gc-sections"]
    binaries = {}
    for name, source in [("btx-native-qualify", "src/modelnet/native_qualification_main.cpp"),
                         ("loader-platform-tests", "test/util/native_qualification/loader_platform_tests.cpp"),
                         ("btx-guardd", "src/btx-guardd.cpp"),
                         ("guard-supervisor-tests", "test/util/native_qualification/guard_supervisor_tests.cpp")]:
        obj = compile_one(source)
        binary = build_dir / name
        run([cxx, *link_gc, obj, *objects, "-pthread", "-o", binary])
        binaries[name] = binary
    probe = build_dir / "sandbox-probe"
    static = ["-static"] if platform.system() == "Linux" else []
    run([cc, "-std=c11", "-O2", *static, HERE / "sandbox_probe.c", "-o", probe])
    return binaries, probe


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    build_dir = (args.build_dir or Path(tempfile.mkdtemp(prefix="btx-native-build-"))).resolve()
    build_dir.mkdir(parents=True, exist_ok=True)
    binaries, probe_binary = build(build_dir)
    with tempfile.TemporaryDirectory(prefix="btx-native-fixtures-") as temporary:
        fixtures = Path(temporary).resolve()
        library = json.loads(run([binaries["loader-platform-tests"], fixtures]).stdout)
        loaded = json.loads(run([binaries["btx-native-qualify"], "load", fixtures / "load-request.json"]).stdout)
        assert loaded["success"] and loaded["module_passed"] and loaded["output"] == [14.5, 31.5]
        assert loaded["verified_source_identities"] == 2 and not loaded["btx_deployment_qualified"]
        signed = json.loads(run([binaries["btx-native-qualify"], "sign-checkpoint", fixtures / "sign-request.json"]).stdout)
        assert signed["success"] and signed["scope"] == "SOURCE_ATTESTATION_ONLY"
        signed_request = json.loads((fixtures / "load-request.json").read_text())
        signed_request["sources"][0]["receipt"] = signed["receipt"]
        (fixtures / "newly-signed-load.json").write_text(json.dumps(signed_request))
        roundtrip = json.loads(run([binaries["btx-native-qualify"], "load", fixtures / "newly-signed-load.json"]).stdout)
        assert roundtrip["success"] and roundtrip["module_passed"]
        corrupt = json.loads((fixtures / "load-request.json").read_text())
        corrupt["sources"][1]["receipt"]["signature"] = "00" * 2420
        (fixtures / "bad-request.json").write_text(json.dumps(corrupt))
        bad = subprocess.run([str(binaries["btx-native-qualify"]), "load", str(fixtures / "bad-request.json")], text=True, capture_output=True, timeout=30)
        assert bad.returncode == 2 and json.loads(bad.stdout)["error"] == "CHECKPOINT_SIGNATURE"
        sandbox_root = fixtures / "sandbox"
        sandbox_root.mkdir()
        shutil.copy2(probe_binary, sandbox_root / "probe")
        expected = b"filesystem-denied network-denied environment-clean native-executed\n"
        binary_bytes = (sandbox_root / "probe").read_bytes()
        request = {"probe": {"root": str(sandbox_root), "executable": "probe", "files": [
            {"path": "probe", "sha384": hashlib.sha384(binary_bytes).hexdigest(), "bytes": len(binary_bytes)}],
            "output_relative_path": "probe-result.txt", "expected_output_sha384": hashlib.sha384(expected).hexdigest(),
            "expected_output_bytes": len(expected), "wall_seconds": 10, "max_package_bytes": 16 * 1024 * 1024}}
        (fixtures / "tool-request.json").write_text(json.dumps(request))
        environment = os.environ.copy()
        environment["BTX_NATIVE_SECRET_SENTINEL"] = "must-not-reach-child"
        native = subprocess.run([str(binaries["btx-native-qualify"]), "tool", str(fixtures / "tool-request.json")],
                                text=True, capture_output=True, timeout=30, env=environment)
        native_result = json.loads(native.stdout)
        if native.returncode == 0:
            assert native_result["success"] and native_result["module_passed"]
            assert (sandbox_root / "probe-result.txt").read_bytes() == expected
            sandbox_status = "PASS_NATIVE_LOCAL_PLATFORM"
            replay = subprocess.run([str(binaries["btx-native-qualify"]), "tool", str(fixtures / "tool-request.json")],
                                    text=True, capture_output=True, timeout=30)
            assert replay.returncode == 2 and json.loads(replay.stdout)["error"] == "NATIVE_TOOL_STALE_OUTPUT"
        else:
            assert native_result["error"] == "JAIL_ABSENT", native_result
            sandbox_status = "BLOCKED_OS_SANDBOX_UNAVAILABLE"
        guard = json.loads(run([binaries["guard-supervisor-tests"], binaries["btx-guardd"]]).stdout)
        stdio = subprocess.run([str(binaries["btx-guardd"]), "--stdio"],input="PING\n",text=True,capture_output=True,timeout=5)
        assert stdio.returncode == 0 and stdio.stdout == "READY BTX_GUARD/1\n"
        refused = subprocess.run([str(binaries["btx-guardd"]), "--port", "49153"],text=True,capture_output=True,timeout=5)
        assert refused.returncode == 1 and "TCP is disabled by default" in refused.stderr
        bounded = subprocess.run([str(binaries["btx-guardd"]), "--stdio"],input="x"*4097,text=True,capture_output=True,timeout=5)
        assert bounded.returncode == 2 and bounded.stdout == "ERR BTX035_LIMIT\n"
        report = {"guard": guard, "guard_stdio_eof": "PASS", "guard_no_default_tcp": "PASS", "guard_bounded_input": "PASS",
                  "component_build": "PASS", "library": library, "signed_second_source_cli": "PASS", "signer_loader_roundtrip_cli": "PASS",
                  "bad_signature_cli": "PASS", "sandbox": sandbox_status, "sandbox_result": native_result,
                  "btx_deployment_qualified": False, "source_revision": run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip(),
                  "platform": platform.platform(), "build_dir": str(build_dir)}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
