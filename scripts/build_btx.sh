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

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DBUILD_TESTS=ON -DBUILD_UTIL=ON "$@"
# Build the full configured graph so every CTest target exists in CI.
cmake --build "${BUILD_DIR}" -j"${JOBS}"
