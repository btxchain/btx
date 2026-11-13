#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Copy the Qt GUI stack into a release tree so btx-qt launches without a
distro or Homebrew Qt install.

Linux: Qt, qrencode, and their private dependencies go in the supplied lib_dir. The
platform plugin goes in lib/qt6/plugins. The launch wrapper sets
QT_PLUGIN_PATH. Host libc, GL/X11 and GTK desktop services stay on the machine so
the GUI uses that machine's display driver.

macOS: macdeployqt fills btx-qt.app. A load command that still points at
Homebrew or /usr/local/opt is a hard failure.
"""

from __future__ import annotations

import importlib.util
import os
import re
from functools import lru_cache
import shutil
import subprocess
from pathlib import Path


# Sonames the host display stack and C library must provide. Everything else
# that ldd names for btx-qt or its platform plugin is copied into the archive.
_HOST_SONAME_PREFIXES = (
    "libc.so",
    "libm.so",
    "libdl.so",
    "libpthread.so",
    "librt.so",
    "libresolv.so",
    "libutil.so",
    "ld-linux",
    "libGL.so",
    "libEGL.so",
    "libGLdispatch.so",
    "libGLX.so",
    "libOpenGL.so",
    "libX11.so",
    "libXext.so",
    "libxcb.so",
    "libXau.so",
    "libXdmcp.so",
    "libXrender.so",
    "libSM.so",
    "libICE.so",
    "libXi.so",
    "libXfixes.so",
    "libxkbcommon.so",
    "libxkbcommon-x11.so",
    "libwayland",
    # Atlas already requires the host GTK/WebKit desktop stack. Do not shadow
    # those services with the copies that Qt happened to use on the builder.
    "libglib-2.0.so",
    "libgobject-2.0.so",
    "libgio-2.0.so",
    "libgmodule-2.0.so",
    "libgthread-2.0.so",
    "libdbus-1.so",
)


def _host_soname(name: str) -> bool:
    return any(name.startswith(prefix) for prefix in _HOST_SONAME_PREFIXES)


@lru_cache(maxsize=1)
def _elf_reader():
    # Reuse the release gate's bounded ELF parser, including static executables.
    spec = importlib.util.spec_from_file_location("qt_bundle_elf_reader", Path(__file__).with_name("verify_release_btxd.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.elf_dynamic_info


def _needed(path: Path) -> set[str]:
    return set(_elf_reader()(path).needed)


def _ldd_map(path: Path, required: set[str] | None = None) -> dict[str, Path]:
    # ldd prints a flattened closure. Follow direct edges only; otherwise
    # dependencies of a host-owned library leak back into the archive.
    needed = _needed(path)
    if required is not None:
        needed &= required
    if not needed:
        return {}
    try:
        result = subprocess.run(
            ["ldd", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"ldd is required to bundle Qt for {path}") from exc
    if result.returncode != 0 and required is None:
        raise RuntimeError(f"ldd failed on {path}: {result.stderr.strip()}")
    found: dict[str, Path] = {}
    for line in result.stdout.splitlines():
        if "=>" not in line:
            continue
        soname, rest = line.strip().split("=>", 1)
        soname = soname.strip()
        if soname not in needed:
            continue
        token = rest.strip().split()
        if not token or token[0] == "not":
            if not _host_soname(soname):
                raise RuntimeError(f"{path} is missing {soname}; cannot bundle the Qt GUI")
            continue
        lib = Path(token[0])
        if lib.is_file():
            found[soname] = lib
    missing = sorted(name for name in needed if not _host_soname(name) and name not in found)
    if missing:
        raise RuntimeError(f"{path} has unresolved private dependencies: {', '.join(missing)}")
    return found


_QT_SONAME_RE = re.compile(r"^libQt(\d+)")


def _qt_majors(linked: dict[str, Path]) -> set[str]:
    """Qt major versions an ldd map names (libQt5Core.so.5 -> "5")."""
    return {match.group(1) for match in map(_QT_SONAME_RE.match, linked) if match}


def _collect_private_libs(roots: list[Path]) -> dict[str, Path]:
    pending = list(roots)
    collected: dict[str, Path] = {}
    seen: set[Path] = set()
    while pending:
        current = pending.pop()
        if current in seen or not current.is_file():
            continue
        seen.add(current)
        for soname, lib in _ldd_map(current).items():
            if _host_soname(soname) or soname in collected:
                continue
            collected[soname] = lib
            pending.append(lib)
    return collected


def _qt_plugins_root() -> Path | None:
    for argv in (
        ["qtpaths6", "-query", "QT_INSTALL_PLUGINS"],
        ["qmake6", "-query", "QT_INSTALL_PLUGINS"],
        ["qtpaths", "-query", "QT_INSTALL_PLUGINS"],
    ):
        try:
            result = subprocess.run(argv, capture_output=True, text=True, check=False)
        except OSError:
            continue
        if result.returncode != 0:
            continue
        path = Path(result.stdout.strip())
        if path.is_dir():
            return path
    return None


def _set_rpath(path: Path, rpath: str) -> None:
    patchelf = shutil.which("patchelf")
    if patchelf is None:
        raise RuntimeError("patchelf is required to point bundled Qt libraries at $ORIGIN")
    subprocess.check_call([patchelf, "--set-rpath", rpath, str(path)])


def bundle_linux_qt(qt_binary: Path, lib_dir: Path, shared_roots: list[Path] | None = None) -> None:
    """Copy Qt into lib_dir and point qt_binary at it. No-op if Qt is absent."""
    linked = _ldd_map(qt_binary)
    if not any(name.startswith("libQt") for name in linked):
        raise RuntimeError(
            f"{qt_binary} is not linked to Qt. Release archives must ship a GUI "
            "built with -DBUILD_GUI=ON."
        )
    # The plugin directory, qt.conf and the launch wrapper are Qt 6 only.
    # CMake defaults WITH_QT_VERSION to 5 (doc/build-unix.md); a Qt 5 btx-qt
    # next to a Qt 6 libqxcb.so cannot load its platform plugin (0.34.16).
    binary_majors = _qt_majors(linked)
    if binary_majors != {"6"}:
        raise RuntimeError(
            f"{qt_binary} links Qt {', '.join(sorted(binary_majors))}; the Linux archive "
            "ships the Qt 6 platform plugin. Configure with -DBUILD_GUI=ON -DWITH_QT_VERSION=6."
        )
    plugin_roots: list[Path] = []
    plugins = _qt_plugins_root()
    platform = plugins / "platforms" / "libqxcb.so" if plugins is not None else None
    if platform is None or not platform.is_file():
        raise RuntimeError(
            "Qt platform plugin libqxcb.so was not found. Install qt6-base and "
            "ensure qtpaths6 -query QT_INSTALL_PLUGINS points at it."
        )
    plugin_majors = _qt_majors(_ldd_map(platform))
    if plugin_majors != binary_majors:
        raise RuntimeError(
            f"{platform} links Qt {', '.join(sorted(plugin_majors)) or 'none'}, but {qt_binary} "
            f"links Qt {', '.join(sorted(binary_majors))}. Point qtpaths6 at the Qt the GUI was built with."
        )
    plugin_roots.append(platform)
    collected = _collect_private_libs([qt_binary, *plugin_roots])
    # Preserve the shared part of the former Qt bundle for non-GUI consumers.
    # Resolve it from those consumers, not from Qt's possibly older toolchain.
    shared: dict[str, Path] = {}
    pending = list(shared_roots or [])
    seen: set[Path] = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        # Do not acquire or validate unrelated node/CUDA dependencies here.
        relevant = _needed(current) & collected.keys()
        if not relevant:
            continue
        for soname, source in _ldd_map(current, relevant).items():
            if soname in shared:
                if shared[soname].read_bytes() != source.read_bytes():
                    raise RuntimeError(f"Conflicting shared dependency {soname}")
                continue
            shared[soname] = source
            pending.append(source)
    shared_dir = qt_binary.parent.parent / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)
    shared_dir.mkdir(parents=True, exist_ok=True)
    for soname, qt_source in sorted(collected.items()):
        source = shared.get(soname, qt_source)
        destination = (shared_dir if soname in shared else lib_dir) / soname
        if destination.exists():
            # Existing authoritative runtime files, especially OpenSSL, win only
            # when their identity agrees; never silently replace them with Qt's.
            if destination.read_bytes() != source.read_bytes():
                raise RuntimeError(f"Conflicting packaged dependency {soname}")
            continue
        shutil.copy2(source, destination)
        destination.chmod(destination.stat().st_mode | 0o111)
        if not soname.startswith(("libssl.so", "libcrypto.so")):
            rpath = "$ORIGIN" if soname in shared else "$ORIGIN:$ORIGIN/.."
            current_rpath = subprocess.check_output(["patchelf", "--print-rpath", str(destination)], text=True).strip()
            if current_rpath != rpath:
                _set_rpath(destination, rpath)
    plugin_dest_dir = lib_dir / "qt6" / "plugins" / "platforms"
    plugin_dest_dir.mkdir(parents=True, exist_ok=True)
    plugin_dest = plugin_dest_dir / platform.name
    shutil.copy2(platform, plugin_dest)
    plugin_dest.chmod(plugin_dest.stat().st_mode | 0o111)
    _set_rpath(plugin_dest, "$ORIGIN/../../../:$ORIGIN/../../../../")
    relative_lib = os.path.relpath(lib_dir, qt_binary.parent)
    _set_rpath(qt_binary, "$ORIGIN/" + relative_lib + ":$ORIGIN/../lib")
    # Without this, Qt also searches the distro plugin directory and can load
    # a system xcb plugin that does not see the bundled libxcb-cursor.
    release_lib = os.path.relpath(lib_dir, qt_binary.parent.parent)
    (qt_binary.parent / "qt.conf").write_text(
        f"[Paths]\nPrefix = ..\nPlugins = {release_lib}/qt6/plugins\nLibraries = {release_lib}\n",
        encoding="utf-8",
    )


def _macdeployqt() -> Path:
    found = shutil.which("macdeployqt")
    if found:
        return Path(found)
    for candidate in (
        "/opt/homebrew/opt/qt@6/bin/macdeployqt",
        "/opt/homebrew/opt/qt@5/bin/macdeployqt",
        "/usr/local/opt/qt@6/bin/macdeployqt",
        "/usr/local/opt/qt@5/bin/macdeployqt",
    ):
        path = Path(candidate)
        if path.is_file():
            return path
    raise FileNotFoundError(
        "macdeployqt is required so the macOS GUI does not depend on Homebrew Qt"
    )


def _info_plist(version: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>btx-qt</string>
  <key>CFBundleIdentifier</key>
  <string>dev.btx.btx-qt</string>
  <key>CFBundleName</key>
  <string>BTX</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>{version}</string>
  <key>CFBundleVersion</key>
  <string>{version}</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
"""


def _is_homebrew(name: str) -> bool:
    return name.startswith("/opt/homebrew") or name.startswith("/usr/local/opt") or "/Cellar/" in name


def _rewrite_homebrew_ids(app: Path) -> None:
    """macdeployqt leaves a plugin's own install id pointing at Homebrew.

    dyld loads the plugin from the bundle directory, so the id is not a
    runtime search path. Rewrite it so the shipped image does not name
    Homebrew at all.
    """
    for path in app.rglob("*"):
        if not path.is_file() or path.stat().st_size < 4:
            continue
        if path.read_bytes()[:4] != b"\xcf\xfa\xed\xfe":
            continue
        try:
            output = subprocess.check_output(["otool", "-D", str(path)], text=True, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.CalledProcessError):
            continue
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if len(lines) < 2 or not _is_homebrew(lines[1]):
            continue
        subprocess.check_call(["install_name_tool", "-id", f"@rpath/{path.name}", str(path)])


def _remove_homebrew_rpaths(app: Path) -> None:
    """Drop builder-only search paths after deployment and before signing."""
    for path in app.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as image:
            magic = image.read(4)
        if magic not in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
            continue
        loads = subprocess.check_output(["otool", "-l", str(path)], text=True)
        rpaths = re.findall(
            r"^\s*cmd LC_RPATH\s*\n\s*cmdsize \d+\s*\n\s*path (.+) \(offset \d+\)$",
            loads, re.MULTILINE,
        )
        for rpath in dict.fromkeys(rpaths):
            if _is_homebrew(rpath):
                subprocess.check_call(["install_name_tool", "-delete_rpath", rpath, str(path)])


def _macho_homebrew_loads(path: Path) -> list[str]:
    if path.stat().st_size < 4 or path.read_bytes()[:4] != b"\xcf\xfa\xed\xfe":
        return []
    try:
        output = subprocess.check_output(["otool", "-L", str(path)], text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return []
    bad: list[str] = []
    # The first dependency line is the install id, not a library the file loads.
    for line in output.splitlines()[2:]:
        token = line.strip().split()
        if not token:
            continue
        name = token[0]
        if _is_homebrew(name):
            bad.append(name)
    return bad


def deploy_macos_qt_app(source_binary: Path, release_root: Path, version: str) -> Path:
    """Create btx-qt.app with Qt copied inside. Returns the inner executable."""
    app = release_root / "btx-qt.app"
    macos_dir = app / "Contents" / "MacOS"
    macos_dir.mkdir(parents=True, exist_ok=True)
    dest = macos_dir / "btx-qt"
    shutil.copy2(source_binary, dest)
    dest.chmod(0o755)
    (app / "Contents" / "Info.plist").write_text(_info_plist(version), encoding="utf-8")
    deploy_tool = _macdeployqt()
    # Split Qt module installations may share a prefix while living outside
    # QtCore's library directory. This is a build-time lookup hint only.
    result = subprocess.run(
        [str(deploy_tool), str(app), "-always-overwrite",
         f"-libpath={deploy_tool.parent.parent / 'lib'}"],
        check=True, capture_output=True, text=True,
    )
    diagnostics = result.stdout + result.stderr
    if any(line.lstrip().startswith("ERROR:") for line in diagnostics.splitlines()):
        errors = [line.strip() for line in diagnostics.splitlines()
                  if line.lstrip().startswith("ERROR:")]
        if any(not line.startswith(("ERROR: Cannot resolve rpath", "ERROR:  using"))
               for line in errors):
            raise RuntimeError("macdeployqt reported an incomplete deployment: " + diagnostics)
        # Some split Qt installations omit plugin-only frameworks from the
        # first pass. Treat the staged plugins as additional dependency roots.
        plugins = sorted((app / "Contents" / "PlugIns").rglob("*.dylib"))
        if not plugins:
            raise RuntimeError("macdeployqt reported an incomplete deployment: " + diagnostics)
        search_path = str(deploy_tool.parent.parent / "lib")
        adjusted = []
        try:
            for plugin in plugins:
                loads = subprocess.check_output(["otool", "-l", str(plugin)], text=True)
                if f"path {search_path} (offset" not in loads:
                    subprocess.check_call(["install_name_tool", "-add_rpath", search_path, str(plugin)])
                    adjusted.append(plugin)
            result = subprocess.run(
                [str(deploy_tool), str(app), "-always-overwrite", "-no-plugins",
                 *[f"-executable={plugin}" for plugin in plugins],
                 f"-libpath={search_path}"],
                check=True, capture_output=True, text=True,
            )
            diagnostics = result.stdout + result.stderr
            if any(line.lstrip().startswith("ERROR:") for line in diagnostics.splitlines()):
                raise RuntimeError("macdeployqt reported an incomplete deployment: " + diagnostics)
        finally:
            for plugin in adjusted:
                loads = subprocess.check_output(["otool", "-l", str(plugin)], text=True)
                if f"path {search_path} (offset" in loads:
                    subprocess.check_call(["install_name_tool", "-delete_rpath", search_path, str(plugin)])
    _rewrite_homebrew_ids(app)
    _remove_homebrew_rpaths(app)
    if shutil.which("codesign"):
        subprocess.check_call(["codesign", "--force", "--deep", "--sign", "-", str(app)])
    offenders: list[str] = []
    for path in app.rglob("*"):
        if not path.is_file():
            continue
        offenders.extend(f"{path.relative_to(app)} -> {name}" for name in _macho_homebrew_loads(path))
    if offenders:
        raise RuntimeError(
            "macOS btx-qt.app still loads Homebrew libraries after macdeployqt: "
            + "; ".join(offenders[:12])
        )
    return dest
