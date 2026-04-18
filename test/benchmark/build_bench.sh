#!/usr/bin/env bash
export LC_ALL=C
# Build script for BTX MatMul Phase 2 verification benchmark.
# Requires: g++ with C++17 support, OpenSSL development headers (libssl-dev).
#
# Usage: ./build_bench.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building matmul_phase2_bench..."
g++ -O2 -std=c++17 -o matmul_bench matmul_phase2_bench.cpp -lcrypto
echo "Build successful: ${SCRIPT_DIR}/matmul_bench"
echo ""
echo "Run with: ./matmul_bench"
