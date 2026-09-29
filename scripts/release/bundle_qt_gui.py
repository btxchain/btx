#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Copy the Qt GUI stack into a release tree so btx-qt launches without a
distro or Homebrew Qt install.

Linux: Qt, qrencode, and their non-display dependencies go in lib/. The
platform plugin goes in lib/qt6/plugins. The launch wrapper sets
QT_PLUGIN_PATH. Host libc, libstdc++, and GL/X11 stay on the machine so
the GUI uses that machine's display driver.

macOS: macdeployqt fills btx-qt.app. A load command that still points at
Homebrew or /usr/local/opt is a hard failure.
"""

from __future__ import annotations

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
)


def _host_soname(name: str) -> bool:
    return any(name.startswith(prefix) for prefix in _HOST_SONAME_PREFIXES)


def _ldd_map(path: Path) -> dict[str, Path]:
    try:
        result = subprocess.run(
            ["ldd", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"ldd is required to bundle Qt for {path}") from exc
    if result.returncode != 0:
        raise RuntimeError(f"ldd failed on {path}: {result.stderr.strip()}")
    found: dict[str, Path] = {}
    for line in result.stdout.splitlines():
        if "=>" not in line:
            continue
        soname, rest = line.strip().split("=>", 1)
        soname = soname.strip()
        token = rest.strip().split()
        if not token or token[0] == "not":
            if not _host_soname(soname):
                raise RuntimeError(f"{path} is missing {soname}; cannot bundle the Qt GUI")
            continue
        lib = Path(token[0])
        if lib.is_file():
            found[soname] = lib
    return found


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


def bundle_linux_qt(qt_binary: Path, lib_dir: Path) -> None:
    """Copy Qt into lib_dir and point qt_binary at it. No-op if Qt is absent."""
    linked = _ldd_map(qt_binary)
    if not any(name.startswith("libQt") for name in linked):
        raise RuntimeError(
            f"{qt_binary} is not linked to Qt. Release archives must ship a GUI "
            "built with -DBUILD_GUI=ON."
        )
    plugin_roots: list[Path] = []
    plugins = _qt_plugins_root()
    platform = plugins / "platforms" / "libqxcb.so" if plugins is not None else None
    if platform is None or not platform.is_file():
        raise RuntimeError(
            "Qt platform plugin libqxcb.so was not found. Install qt6-base and "
            "ensure qtpaths6 -query QT_INSTALL_PLUGINS points at it."
        )
    plugin_roots.append(platform)
    collected = _collect_private_libs([qt_binary, *plugin_roots])
    lib_dir.mkdir(parents=True, exist_ok=True)
    for soname, source in sorted(collected.items()):
        destination = lib_dir / soname
        shutil.copy2(source, destination)
        destination.chmod(destination.stat().st_mode | 0o111)
        _set_rpath(destination, "$ORIGIN")
    plugin_dest_dir = lib_dir / "qt6" / "plugins" / "platforms"
    plugin_dest_dir.mkdir(parents=True, exist_ok=True)
    plugin_dest = plugin_dest_dir / platform.name
    shutil.copy2(platform, plugin_dest)
    plugin_dest.chmod(plugin_dest.stat().st_mode | 0o111)
    _set_rpath(plugin_dest, "$ORIGIN/../../../")
    _set_rpath(qt_binary, "$ORIGIN/../lib")
    # Without this, Qt also searches the distro plugin directory and can load
    # a system xcb plugin that does not see the bundled libxcb-cursor.
    (qt_binary.parent / "qt.conf").write_text(
        "[Paths]\nPrefix = ..\nPlugins = lib/qt6/plugins\nLibraries = lib\n",
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
    subprocess.check_call([str(_macdeployqt()), str(app), "-always-overwrite"])
    _rewrite_homebrew_ids(app)
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
