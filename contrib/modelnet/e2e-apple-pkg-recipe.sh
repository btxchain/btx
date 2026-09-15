#!/usr/bin/env bash
# APPLE-PKG recipe completeness on a non-Darwin builder. Does not produce a .pkg/.dmg.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
die() { echo "e2e-apple-pkg-recipe: $*" >&2; exit 1; }

[[ -f "$ROOT/contrib/macdeploy/macdeployqtplus" ]] || die "macdeployqtplus missing"
[[ -f "$ROOT/contrib/macdeploy/detached-sig-create.sh" ]] || die "detached-sig-create.sh missing"
[[ -f "$ROOT/cmake/module/Maintenance.cmake" ]] || die "Maintenance.cmake missing"
grep -n 'add_macos_deploy_target' "$ROOT/cmake/module/Maintenance.cmake" >/dev/null || die "macos deploy target missing"
grep -n 'macdeployqtplus' "$ROOT/cmake/module/Maintenance.cmake" >/dev/null || die "macdeployqtplus not wired"
grep -n 'CMAKE_SYSTEM_NAME STREQUAL "Darwin"' "$ROOT/src/qt/CMakeLists.txt" >/dev/null || die "Darwin qt cmake missing"
grep -n 'QCocoaIntegrationPlugin' "$ROOT/src/qt/CMakeLists.txt" >/dev/null || die "Cocoa plugin missing"
grep -n 'BTX_ENABLE_METAL' "$ROOT/src/CMakeLists.txt" >/dev/null || die "Metal cmake missing"
[[ -f "$ROOT/contrib/init/org.btx.btxd.plist" ]] || die "org.btx.btxd.plist missing"

python3 - "$ROOT/cmake/module/Maintenance.cmake" "$ROOT/CMakeLists.txt" <<'PY'
from pathlib import Path
import sys
maint, top = (Path(p).read_text() for p in sys.argv[1:])
if "add_macos_deploy_target" not in maint:
    raise SystemExit("add_macos_deploy_target missing")
if "add_macos_deploy_target()" not in top:
    raise SystemExit("top-level CMakeLists does not call add_macos_deploy_target")
print("Apple packaging sources present (deploy target + macdeployqtplus)")
PY

if [[ "$(uname -s)" == Darwin ]]; then
  echo "Darwin host: recipe is complete"
  if [[ "${APPLE_PKG_BUILD:-0}" == "1" ]]; then
    BUILD_DIR="${APPLE_PKG_BUILD_DIR:-$ROOT/build-metal}"
    [[ -f "$BUILD_DIR/CMakeCache.txt" ]] || die "missing Darwin build cache: $BUILD_DIR"
    cmake --build "$BUILD_DIR" --target deploy
    artifact="$(find "$BUILD_DIR" -maxdepth 1 -type f \( -name '*.zip' -o -name '*.dmg' -o -name '*.pkg' \) -print -quit)"
    [[ -n "$artifact" ]] || die "deploy completed without a zip, dmg, or pkg artifact"
    echo "APPLE-PKG artifact PASS $artifact"
  else
    echo "Set APPLE_PKG_BUILD=1 to execute the Darwin deploy target"
  fi
else
  echo "not Darwin; .pkg/.zip artifact not produced (recipe verified)"
fi
echo "APPLE-PKG recipe PASS"
