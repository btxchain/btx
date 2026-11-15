#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Collect actual native binaries, observed dependencies and assets into a lock.

This inspects owner-built executables on their native platform. It never downloads
or builds a runtime. Linux uses ldd on explicitly selected trusted build outputs;
macOS uses otool; Windows uses dumpbin from the selected developer environment.
OS libraries are recorded separately on macOS/Windows. The resulting archive is
an offline application runtime on that OS baseline, not a bootable OS image.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil

try:
    from .evidence import EvidenceError, atomic_json, run_command, sha256_file, source_identity
    from .offline_image import MAX_TOTAL, PLATFORMS, REQUIRED, safe_name, validate_lock
except ImportError:
    from evidence import EvidenceError, atomic_json, run_command, sha256_file, source_identity
    from offline_image import MAX_TOTAL, PLATFORMS, REQUIRED, safe_name, validate_lock


def linux_dependencies(stdout: str) -> list[tuple[str, str]]:
    dependencies = []
    for line in stdout.splitlines():
        line = line.strip()
        if "=> not found" in line:
            raise EvidenceError("native binary has an unresolved dynamic dependency: " + line)
        match = re.fullmatch(r"([^\s]+)\s+=>\s+(/.+?)\s+\(0x[0-9a-fA-F]+\)", line)
        if match:
            dependencies.append((match.group(1), match.group(2)))
        elif line.startswith("/"):
            path = re.sub(r"\s+\(0x[0-9a-fA-F]+\)$", "", line)
            dependencies.append((Path(path).name, path))
        elif line and not line.startswith(("linux-vdso", "linux-gate", "statically linked", "not a dynamic executable")):
            raise EvidenceError("unrecognized dependency inspection output: " + line)
    return dependencies


def mac_dependencies(stdout: str, binary: Path, roots: list[Path]) -> list[tuple[str, str]]:
    result = []
    for line in stdout.splitlines()[1:]:
        name = line.strip().split(" (compatibility version", 1)[0]
        if not name:
            continue
        if name.startswith("@loader_path/"):
            path = binary.parent / name[len("@loader_path/"):]
        elif name.startswith("@executable_path/"):
            path = roots[0] / name[len("@executable_path/"):]
        elif name.startswith("@rpath/"):
            tail = name[len("@rpath/"):]
            candidates = [root / tail for root in roots if (root / tail).is_file()]
            if len(candidates) != 1:
                raise EvidenceError("@rpath needs exactly one explicit matching --runtime-dir: " + name)
            path = candidates[0]
        elif name.startswith("/"):
            path = Path(name)
        else:
            raise EvidenceError("unresolved macOS dependency path: " + name)
        result.append((Path(name).name, str(path)))
    return result


def windows_dependencies(stdout: str, roots: list[Path]) -> list[tuple[str, str]]:
    names = sorted(set(re.findall(r"^\s+([A-Za-z0-9_.-]+\.dll)\s*$", stdout, re.MULTILINE | re.IGNORECASE)))
    result = []
    for name in names:
        matches = []
        for root in roots:
            if root.is_dir():
                matches.extend(path for path in root.iterdir() if path.name.casefold() == name.casefold() and path.is_file())
        if not matches:
            # API-set DLLs are OS contracts and often have no standalone file.
            if name.lower().startswith(("api-ms-win-", "ext-ms-win-")):
                result.append((name, "OS_API_SET"))
                continue
            raise EvidenceError("unresolved Windows dependency: " + name)
        result.append((name, str(matches[0])))
    return result


def check_native_header(path: Path, target: str) -> None:
    with path.open("rb") as source:
        header = source.read(64)
    if target.startswith("linux-"):
        machine = int.from_bytes(header[18:20], "little") if len(header) >= 20 else 0
        expected = 62 if target.endswith("x86_64") else 183
        if header[:6] != b"\x7fELF\x02\x01" or machine != expected:
            raise EvidenceError("native Linux executable architecture does not match lock platform")
    elif target.startswith("macos-"):
        if header[:4] not in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf"}:
            raise EvidenceError("macOS native executable is not Mach-O")
    elif header[:2] != b"MZ":
        raise EvidenceError("Windows native executable is not PE")


def collect(source: Path, bin_dir: Path, target: str, runtime_dirs: list[Path],
            assets: list[tuple[str, Path]], evidence_dir: Path) -> dict:
    actual_system = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(platform.system())
    if target not in PLATFORMS or not target.startswith(str(actual_system) + "-"):
        raise EvidenceError("dependency collection must execute on the named native OS")
    architecture = {"AMD64": "x86_64", "arm64": "aarch64"}.get(platform.machine(), platform.machine())
    expected_arch = "aarch64" if target.endswith(("arm64", "aarch64")) else "x86_64"
    if architecture != expected_arch:
        raise EvidenceError("dependency collection must execute on the named native CPU")
    if evidence_dir.exists() or evidence_dir.is_symlink():
        raise EvidenceError("runtime collection requires a fresh dependency-evidence directory")
    identity = source_identity(source)
    bin_dir = Path(bin_dir).resolve(strict=True)
    roots = [bin_dir] + [Path(root).resolve(strict=True) for root in runtime_dirs]
    records, names, dependencies, inspection, system_dependencies = [], {}, set(), [], []

    def add(path: Path, name: str, executable=False):
        name = safe_name(name)
        # Runtime libraries commonly have SONAME symlinks. Package their actual
        # regular bytes under the observed requested name, never archive links.
        path = path.resolve(strict=True)
        digest = sha256_file(path, MAX_TOTAL)
        if name.casefold() in names:
            if names[name.casefold()] != digest:
                raise EvidenceError("runtime dependency name has conflicting content: " + name)
            return
        names[name.casefold()] = digest
        records.append({"path": name, "source": str(path), "sha256": digest, "executable": executable})

    suffix = ".exe" if target.startswith("windows-") else ""
    binaries = [bin_dir / (name + suffix) for name in REQUIRED]
    qualifier = bin_dir / ("btx-native-qualify" + suffix)
    if qualifier.exists():
        binaries.append(qualifier)
    for binary in binaries:
        check_native_header(binary, target)
        add(binary, "bin/" + binary.name, True)
    tool_name = {"Linux": "ldd", "Darwin": "otool", "Windows": "dumpbin"}[platform.system()]
    tool = shutil.which(tool_name)
    if not tool:
        raise EvidenceError("native dependency inspector is missing: " + tool_name)
    tool = str(Path(tool).resolve())
    tool_sha256 = sha256_file(Path(tool))
    if platform.system() == "Windows":
        system_root = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32"
        roots.append(system_root)
    visited, queue = set(), list(binaries)
    while queue:
        binary = queue.pop(0).resolve(strict=True)
        if binary in visited:
            continue
        if len(visited) >= 1024:
            raise EvidenceError("native dependency graph exceeds bound")
        visited.add(binary)
        command = [tool, str(binary)] if platform.system() == "Linux" else (
            [tool, "-L", str(binary)] if platform.system() == "Darwin" else [tool, "/NOLOGO", "/DEPENDENTS", str(binary)])
        result = run_command(command, source, 30)
        if result["failure"]:
            raise EvidenceError("native dependency inspector timed out or overflowed")
        if result["returncode"] and not (platform.system() == "Linux" and "not a dynamic executable" in result["stdout"] + result["stderr"]):
            raise EvidenceError("native dependency inspector failed: " + str(binary))
        inspection.append({"binary_sha256": sha256_file(binary, MAX_TOTAL), "command": result})
        found = linux_dependencies(result["stdout"]) if platform.system() == "Linux" else (
            mac_dependencies(result["stdout"], binary, roots) if platform.system() == "Darwin" else windows_dependencies(result["stdout"], roots))
        for name, filename in found:
            if filename == "OS_API_SET":
                system_dependencies.append({"name": name, "kind": "WINDOWS_API_SET"})
                continue
            path = Path(filename)
            is_system = (platform.system() == "Darwin" and filename.startswith(("/usr/lib/", "/System/Library/"))) or (
                platform.system() == "Windows" and path.resolve().is_relative_to(system_root.resolve()))
            if is_system:
                system_dependencies.append({"name": name, "path": filename,
                                            "sha256": sha256_file(path.resolve(), MAX_TOTAL) if path.is_file() else None,
                                            "kind": "HOST_OS_BASELINE"})
            else:
                package_name = ("bin/" if platform.system() == "Windows" else "lib/") + name
                add(path, package_name, platform.system() != "Windows")
                dependencies.add(package_name)
                queue.append(path)
    for prefix, root in assets:
        prefix = safe_name(prefix)
        root = Path(root).resolve(strict=True)
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise EvidenceError("runtime assets must be materialized without symlinks")
            if path.is_file():
                name = prefix + "/" + path.relative_to(root).as_posix()
                add(path, name, bool(path.stat().st_mode & 0o111))
                dependencies.add(name)
    add(Path(source) / "COPYING", "licenses/BTX-COPYING")
    dependencies.add("licenses/BTX-COPYING")
    evidence_dir.mkdir(parents=True, mode=0o700)
    report_path = evidence_dir / "native-dependencies.json"
    atomic_json(report_path, {"schema": "BTX-NATIVE-DEPENDENCY-INSPECTION/1", "source": identity,
                             "system": platform.system(), "release": platform.release(), "version": platform.version(),
                             "inspector_sha256": tool_sha256, "inspections": inspection,
                             "system_dependencies": system_dependencies, "native_qualification": "NOT_RUN"})
    add(report_path, "share/native-dependencies.json")
    dependencies.add("share/native-dependencies.json")
    if sha256_file(Path(tool)) != tool_sha256 or source_identity(source) != identity:
        raise EvidenceError("source or dependency inspector changed during collection")
    lock = {"schema": "BTX-OFFLINE-LOCK/1", "platform": target,
            "source_commit": identity["commit"], "source_tree_sha256": identity["source_tree_sha256"],
            "files": sorted(records, key=lambda row: row["path"]), "dependency_closure": sorted(dependencies)}
    validate_lock(lock)
    return lock


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    parser.add_argument("--runtime-dir", type=Path, action="append", default=[])
    parser.add_argument("--asset", action="append", default=[], help="archive-prefix=absolute-local-directory")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        assets = []
        for item in args.asset:
            if "=" not in item:
                raise EvidenceError("asset requires archive-prefix=absolute-local-directory")
            prefix, path = item.split("=", 1)
            if not Path(path).is_absolute():
                raise EvidenceError("asset source must be absolute")
            assets.append((prefix, Path(path)))
        if args.out.exists() or args.out.is_symlink():
            raise EvidenceError("runtime lock output must be new")
        lock = collect(args.source, args.bin_dir, args.platform, args.runtime_dir, assets, args.evidence_dir)
        atomic_json(args.out, lock)
        print(json.dumps({"lock": str(args.out), "lock_sha256": sha256_file(args.out),
                          "files": len(lock["files"]), "native_qualification": "NOT_RUN"}))
        return 0
    except (EvidenceError, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "native_qualification": "NOT_RUN"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
