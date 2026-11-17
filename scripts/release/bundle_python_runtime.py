#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Copy the Python runtime that btxd links into a Linux release tree.

btxd links libpythonX.Y.so.1.0 for the in-process SwapNet worker
(cmake/SwapNet.cmake), so the library must load on every start, also with
-swapnet=0. -swapnet=1 also needs that interpreter's standard library and
the modules the frozen SwapNet sources import (cryptography). Everything is
taken from the build host's interpreter whose INSTSONAME is the one btxd
links, as bundle_qt_gui.py takes Qt from the build host:

  lib/libpythonX.Y.so.1.0     the library btxd links (RUNPATH $ORIGIN, as a shared Qt library)
  lib/pythonX.Y/              standard library and lib-dynload, without tests, GUI and bytecode
  lib/<site dir>/             third-party packages, at the host's path relative to sys.prefix
  lib/python-private/         shared libraries that only those modules load

src/swapnet/embed.cpp uses the archive root as Python home when the loaded
libpython sits in lib/ next to lib/pythonX.Y/os.py. A library that btxd
itself loads at startup (libsqlite3, libstdc++, OpenSSL when btxd links it)
is not copied again: the process already has it.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path

LIBPYTHON_RE = re.compile(r"^libpython(3\.\d+)t?\.so\.1\.0$")
PRIVATE_DIR = "python-private"
# Not used by an embedded worker that has no terminal or display.
STDLIB_EXCLUDED_DIRS = frozenset({
    "__pycache__", "test", "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3",
    "site-packages", "dist-packages",
})
STDLIB_EXCLUDED_PREFIXES = ("config-",)  # static libpython, Makefile and headers for extension builds
# Extension modules for a terminal, dbm files, crypt(3) and CPython's own tests. Distros
# ship several of them as separate packages; leaving them out keeps readline, ncurses,
# Berkeley DB and libcrypt out of the archive. The SwapNet sources import none of them.
# termios on CPython 3.14 binds cf*speed at GLIBC_2.42, above the archive ceiling.
# SwapNet does not import it.
DYNLOAD_EXCLUDED_PREFIXES = ("readline.", "_curses.", "_curses_panel.", "_dbm.", "_gdbm.", "_crypt.",
                             "_tkinter.", "_test", "_xxtestfuzz.", "xxlimited", "xxsubtype.", "_ctypes_test.",
                             "termios.")


def _skip_dynload(name: str) -> bool:
    return name.startswith(DYNLOAD_EXCLUDED_PREFIXES)


@lru_cache(maxsize=1)
def _verify_module():
    spec = importlib.util.spec_from_file_location(
        "python_bundle_elf_reader", Path(__file__).with_name("verify_release_btxd.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@lru_cache(maxsize=1)
def _qt_bundle():
    spec = importlib.util.spec_from_file_location(
        "python_bundle_qt_rules", Path(__file__).with_name("bundle_qt_gui.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _is_elf(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and _verify_module().classify(path) == "elf"


def _needed(path: Path) -> list[str]:
    return list(_verify_module().elf_dynamic_info(path).needed)


def linked_libpython(binary: Path) -> str | None:
    """The libpython soname in binary's DT_NEEDED, or None (also for a non-ELF test stub).

    package_release_archive.verify_shipped_btxd refuses a non-ELF btxd before this runs.
    """
    if not _is_elf(binary):
        return None
    return next((name for name in _needed(binary) if LIBPYTHON_RE.match(name)), None)


# An error string of src/swapnet/embed.cpp: present in every btxd that links the worker.
SWAPNET_MARKER = b"SwapNet Python initialization failed"


def embeds_swapnet(binary: Path) -> bool:
    tail = b""
    with binary.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            if SWAPNET_MARKER in tail + chunk:
                return True
            tail = chunk[-len(SWAPNET_MARKER):]
    return False


def swapnet_imports(source_root: Path) -> list[str]:
    """Absolute imports of the frozen SwapNet sources, outside the package itself.

    Function-level imports are included: the worker reaches them after start.
    """
    package = source_root / "contrib" / "swapnet" / "swapnet"
    sources = sorted(package.glob("*.py"))
    if not sources:
        raise FileNotFoundError(f"no SwapNet sources in {package}")
    names: set[str] = set()
    for source in sources:
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module)
    return sorted(name for name in names if name.split(".")[0] != "swapnet")


PROBE = r"""
import importlib, json, os, sys, sysconfig
before = set(sys.modules)  # site, and Debian's sitecustomize: host start-up policy, never shipped
failed = []
for name in json.loads(sys.argv[1]):
    try:
        importlib.import_module(name)
    except Exception as exc:
        failed.append(f"{name} ({type(exc).__name__})")
modules = {}
for name, module in sorted(sys.modules.items()):
    path = getattr(module, "__file__", None)
    if path and name not in before:
        modules[name] = os.path.realpath(path)
print(json.dumps({
    "version": "%d.%d" % sys.version_info[:2],
    "soname": sysconfig.get_config_var("INSTSONAME"),
    "libdir": sysconfig.get_config_var("LIBDIR"),
    "prefix": os.path.realpath(sys.prefix),
    "platlibdir": sys.platlibdir,
    "stdlib": os.path.realpath(os.path.dirname(os.__file__)),
    "lib_dynload": os.path.realpath(os.path.join(sys.exec_prefix, sys.platlibdir,
                                                  "python%d.%d" % sys.version_info[:2], "lib-dynload")),
    "failed": failed,
    "modules": modules,
}))
"""


def probe_interpreter(python: str, modules: list[str]) -> dict:
    # -I: the same isolation the worker uses (no PYTHON* variables, no user site).
    result = subprocess.run([python, "-I", "-c", PROBE, json.dumps(modules)],
                            capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{python} could not run the SwapNet import probe: {result.stderr.strip()}")
    return json.loads(result.stdout)


def find_interpreter(soname: str, explicit: str | None = None) -> str:
    version = LIBPYTHON_RE.match(soname).group(1)
    python = explicit or shutil.which(f"python{version}")
    if not python:
        raise FileNotFoundError(
            f"btxd links {soname}; python{version} is required on the packaging host to bundle its "
            "standard library and cryptography (pass --python)")
    return python


def _third_party_roots(info: dict) -> dict[str, Path]:
    """Top-level module path for every imported module outside the standard library."""
    stdlib = Path(info["stdlib"])
    dynload = Path(info["lib_dynload"])
    roots: dict[str, Path] = {}
    for name, file in info["modules"].items():
        path = Path(file)
        if path == stdlib or path == dynload or dynload in path.parents:
            continue
        # Prefix installs put third-party packages below stdlib, but the
        # stdlib copy deliberately excludes these two package directories.
        if (stdlib in path.parents
                and path.relative_to(stdlib).parts[0] not in ("site-packages", "dist-packages")):
            continue
        top = name.split(".")[0]
        top_file = Path(info["modules"].get(top, file))
        root = top_file.parent if top_file.name.startswith("__init__.") else top_file
        roots.setdefault(top, root)
    return roots


def _copy_stdlib(source: Path, destination: Path) -> list[str]:
    """Copy the standard library; return the symbolic links not copied (outside it, or to a directory)."""
    skipped: list[str] = []
    real_root = source.resolve()
    for directory, subdirs, files in os.walk(source):
        here = Path(directory)
        rel = here.relative_to(source)
        kept = []
        for d in sorted(subdirs):
            if d == "__pycache__" or (rel == Path(".") and (d in STDLIB_EXCLUDED_DIRS or d.startswith(STDLIB_EXCLUDED_PREFIXES))):
                continue
            if (here / d).is_symlink():  # os.walk does not enter it; say so rather than drop it quietly
                skipped.append(str((here / d).relative_to(source)) + "/")
                continue
            kept.append(d)
        subdirs[:] = kept
        for name in sorted(files):
            item = here / name
            if name.endswith((".pyc", ".pyo")) or (rel == Path("lib-dynload") and _skip_dynload(name)):
                continue
            if item.is_symlink():
                target = item.resolve()
                if target != real_root and real_root not in target.parents:
                    # Debian links sitecustomize.py to /etc/pythonX.Y: host policy, not stdlib.
                    skipped.append(str(item.relative_to(source)))
                    continue
            out = destination / rel / name
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, out)  # follows an in-tree symlink: the archive holds files only
    return skipped


def _copy_tree(source: Path, destination: Path) -> None:
    if source.is_dir():
        shutil.copytree(source, destination, symlinks=False,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _set_rpath(path: Path, rpath: str) -> None:
    _qt_bundle()._set_rpath(path, rpath)


def _install_library(source: Path, destination: Path, rpath: str) -> None:
    """Copy source with rpath; an existing file must be byte-identical to that result.

    bundle_qt_gui.py places libpython and its direct dependencies in lib/ with
    RUNPATH $ORIGIN when btx-qt is packed. The same file from the same host is
    accepted; anything else is a conflict, never a silent replacement.
    """
    with tempfile.TemporaryDirectory(prefix="btx-python-lib-") as tmp:
        candidate = Path(tmp) / source.name
        shutil.copy2(source, candidate)
        candidate.chmod(candidate.stat().st_mode | 0o200)
        _set_rpath(candidate, rpath)
        if destination.exists():
            if destination.read_bytes() != candidate.read_bytes():
                raise RuntimeError(f"Conflicting packaged dependency {destination.name}")
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(candidate, destination)
        destination.chmod(destination.stat().st_mode | 0o111)


def _origin_rpath(elf: Path, *dirs: Path) -> str:
    return ":".join("$ORIGIN/" + os.path.relpath(d, elf.parent) for d in dirs)


def _is_shared_object_name(path: Path) -> bool:
    return path.name.endswith(".so") or ".so." in path.name


def startup_sonames(binary: Path, skip: str) -> set[str]:
    """Sonames the loader maps for binary at start, not counting what only `skip` pulls in.

    The process already holds these when the worker imports a module, so a
    module that needs one shares btxd's copy (libsqlite3 is the wallet's).
    """
    qt = _qt_bundle()
    names: set[str] = set()
    pending, seen = [binary], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        needed = [name for name in _needed(current) if name != skip]
        names.update(needed)
        pending.extend(qt._ldd_map(current, {n for n in needed if not qt._host_soname(n)}).values())
    return names


def runtime_problems(release_root: Path, files: list[Path], loaded: set[str]) -> list[str]:
    """Each bundled ELF must reach every non-host soname through its own RUNPATH."""
    qt = _qt_bundle()
    problems: list[str] = []
    for path in files:
        info = _verify_module().elf_dynamic_info(path)
        dirs = [Path(os.path.normpath(str(path.parent) + entry[len("$ORIGIN"):]))
                for entry in info.search if entry.startswith("$ORIGIN")]
        for name in info.needed:
            if qt._host_soname(name) or name in loaded:
                continue
            if not any((d / name).is_file() for d in dirs):
                problems.append(f"{path.relative_to(release_root)} cannot reach {name}")
    return problems


CHECK = r"""
import importlib, json, os, sys
root = os.path.realpath(sys.argv[2])
for name in json.loads(sys.argv[1]):
    importlib.import_module(name)
outside = sorted(f"{n} {os.path.realpath(m.__file__)}" for n, m in sys.modules.items()
                 if getattr(m, "__file__", None) and not os.path.realpath(m.__file__).startswith(root + os.sep))
print(json.dumps({"outside": outside}))
"""


def verify_staged_imports(python: str, release_root: Path, modules: list[str]) -> None:
    """Import the SwapNet list from the staged tree only (PYTHONHOME, no host site)."""
    # As on a host without the build prefix: no OpenSSL provider directory, and the
    # wrapper's CRYPTOGRAPHY_OPENSSL_NO_LEGACY (package_release_archive.LINUX_SWAPNET_ENV).
    env = {"PATH": "/usr/bin:/bin", "PYTHONHOME": str(release_root), "PYTHONNOUSERSITE": "1", "LC_ALL": "C.UTF-8",
           "OPENSSL_MODULES": "/nonexistent-btx-python-bundle-modules", "CRYPTOGRAPHY_OPENSSL_NO_LEGACY": "1",
           "PYTHONDONTWRITEBYTECODE": "1"}
    # -B: no __pycache__ in the staged tree (it would name the staging path and change the archive).
    result = subprocess.run([python, "-B", "-s", "-P", "-c", CHECK, json.dumps(modules), str(release_root)],
                            capture_output=True, text=True, env=env, check=False)
    if result.returncode != 0:
        raise RuntimeError("the staged Python runtime cannot import what the SwapNet sources import: "
                           + (result.stderr.strip().splitlines() or ["no output"])[-1])
    report = json.loads(result.stdout)
    if report["outside"]:
        raise RuntimeError("the staged Python runtime loaded modules from outside the archive: "
                           + "; ".join(report["outside"][:5]))


def bundle_linux_python(btxd_real: Path, release_root: Path, *, source_root: Path,
                        python: str | None = None) -> list[str]:
    """Bundle the runtime btxd_real links. Returns the archive paths written ([] without SwapNet)."""
    soname = linked_libpython(btxd_real)
    if soname is None:
        if _is_elf(btxd_real) and embeds_swapnet(btxd_real):
            # A static libpython: embed.cpp finds the archive's standard library only
            # through the libpython it loaded, so this archive could not start -swapnet=1.
            raise RuntimeError(f"{btxd_real} contains the SwapNet worker but links no libpython shared "
                               "library; the Linux archive needs libpythonX.Y.so.1.0 (cmake/SwapNet.cmake)")
        return []
    qt = _qt_bundle()
    resolved = qt._ldd_map(btxd_real, {soname})[soname]
    interpreter = find_interpreter(soname, python)
    modules = swapnet_imports(source_root)
    info = probe_interpreter(interpreter, modules)
    version = LIBPYTHON_RE.match(soname).group(1)
    if info["version"] != version or info["soname"] != soname:
        raise RuntimeError(f"{interpreter} is Python {info['version']} ({info['soname']}); btxd links {soname}")
    host_lib = Path(info["libdir"]) / soname
    if not host_lib.is_file():
        raise RuntimeError(f"{interpreter} reports {host_lib}, which does not exist")
    # Outside the staged tree, btxd must load this interpreter's library. Inside it,
    # the Qt bundle placed a copy; _install_library below requires it to be identical.
    inside = resolved.resolve() == release_root.resolve() or release_root.resolve() in resolved.resolve().parents
    if not inside and not resolved.samefile(host_lib):
        raise RuntimeError(f"btxd loads {resolved}, not {host_lib} of {interpreter}")
    if info["failed"]:
        raise RuntimeError(f"{interpreter} cannot import what the SwapNet sources import: {', '.join(info['failed'])}")
    if info["platlibdir"] != "lib":
        raise RuntimeError(f"{interpreter} uses platlibdir {info['platlibdir']!r}; the archive layout is lib/python{version}")
    stdlib, dynload, prefix = Path(info["stdlib"]), Path(info["lib_dynload"]), Path(info["prefix"])
    if not dynload.is_dir():
        raise RuntimeError(f"{interpreter} has no lib-dynload directory at {dynload}")

    lib_dir = release_root / "lib"
    private_dir = lib_dir / PRIVATE_DIR
    stdlib_dest = lib_dir / f"python{version}"
    if stdlib_dest.exists():
        raise RuntimeError(f"{stdlib_dest} already exists in the staged tree")
    skipped = _copy_stdlib(stdlib, stdlib_dest)
    if dynload != stdlib / "lib-dynload":
        shutil.copytree(dynload, stdlib_dest / "lib-dynload", symlinks=False,
                        ignore=lambda _, names: [n for n in names if _skip_dynload(n) or n == "__pycache__"])
    roots = [stdlib_dest]
    for top, root in sorted(_third_party_roots(info).items()):
        site = root.parent
        if site != prefix and prefix not in site.parents:
            raise RuntimeError(f"{top} is imported from {root}, outside {prefix}; the archive cannot place it")
        destination = release_root / site.relative_to(prefix) / root.name
        _copy_tree(root, destination)
        roots.append(destination)
        for meta in sorted(site.glob(f"{top}-*.dist-info")):
            _copy_tree(meta, release_root / site.relative_to(prefix) / meta.name)

    # libpython and what it needs go in lib/ with RUNPATH $ORIGIN, as the Qt
    # bundle places a library btxd shares with btx-qt; what only the extension
    # modules need goes in lib/python-private.
    loaded = startup_sonames(btxd_real, soname)
    _install_library(host_lib, lib_dir / soname, "$ORIGIN")
    pending: list[tuple[Path, Path, bool]] = [(host_lib, lib_dir / soname, True)]
    for root in roots:
        for path in sorted([root] if root.is_file() else root.rglob("*")):
            if _is_shared_object_name(path) and _is_elf(path):
                pending.append((path, path, False))
    placed = {soname}
    bundled = [staged for _, staged, _ in pending]
    while pending:
        source, staged, shared = pending.pop(0)
        wanted = [name for name in _needed(source) if not qt._host_soname(name) and name not in loaded]
        if not wanted:
            continue
        found = qt._ldd_map(source, set(wanted))
        for name in wanted:
            if name in placed:
                continue
            placed.add(name)
            destination = (lib_dir if shared else private_dir) / name
            _install_library(found[name], destination, "$ORIGIN" if shared else "$ORIGIN:$ORIGIN/..")
            pending.append((found[name], destination, shared))
            bundled.append(destination)
        if staged.parent not in (lib_dir, private_dir):
            _set_rpath(staged, _origin_rpath(staged, private_dir, lib_dir))

    problems = runtime_problems(release_root, bundled, loaded)
    if problems:
        raise RuntimeError("bundled Python runtime is incomplete:\n  - " + "\n  - ".join(problems))
    verify_staged_imports(interpreter, release_root, modules)
    if skipped:
        print(f"bundle_python_runtime: not copied (symbolic links): {', '.join(skipped)}",
              file=sys.stderr)
    written = [lib_dir / soname, *roots, *([private_dir] if private_dir.is_dir() else [])]
    return [str(path.relative_to(release_root)) for path in written]
