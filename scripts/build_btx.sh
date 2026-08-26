#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-${ROOT_DIR}/build-btx}"

if [[ $# -gt 0 ]]; then
  shift
fi

if command -v getconf >/dev/null 2>&1; then
  JOBS="$(getconf _NPROCESSORS_ONLN)"
else
  JOBS=4
fi

# WITH_ZMQ defaults ON in CMakeLists.txt; pass it explicitly so a stale cache
# cannot silently drop notifications the way 0.33.4.2 native tarballs did.
# Callers may still override with -DWITH_ZMQ=OFF (last -D wins).
cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DBUILD_TESTS=ON -DBUILD_UTIL=ON -DWITH_ZMQ=ON "$@"
# Build the full configured graph so every CTest target exists in CI.
cmake --build "${BUILD_DIR}" -j"${JOBS}"
