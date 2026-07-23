#!/usr/bin/env bash
#
# ENC_RC v4.6 (Resident Curriculum) — canonical hardware / verify measurement.
#
# This is the ONLY recommended measure entrypoint on current tips. Do NOT use
# bare `measure-hardware.sh cuda|cpu` for product decisions: that path builds
# `matmul-v4-report` and measures LEGACY v4.1 ENC-S8 / v4.2 BMX4C / v4.4-LT PoW,
# which is NOT the v4.6 Resident Curriculum workload.
#
# Spec / status: doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md
# Aggregation:   contrib/matmul-v4/rc-gate.py
#
# --- What to run ---
#
# CPU Stage G campaigns (same-tip, multi-run, rc-gate schema):
#   contrib/matmul-v4/measure-enc-rc-v46.sh cpu --profile coupled
#   contrib/matmul-v4/measure-enc-rc-v46.sh cpu --profile coupled-medium
#   contrib/matmul-v4/measure-enc-rc-v46.sh cpu --profile rc-toy
#   contrib/matmul-v4/measure-enc-rc-v46.sh cpu --profile rc-medium
#
# Direct harness (single run):
#   contrib/matmul-v4/measure-enc-rc-v46.sh cpu rc --toy
#   contrib/matmul-v4/measure-enc-rc-v46.sh cpu rc --coupled-v3-ci
#   contrib/matmul-v4/measure-enc-rc-v46.sh cpu rc --coupled-medium
#
# Production-shape *verifier floor* ( Freivalds sampled carrier, 900 ms budget ):
#   contrib/matmul-v4/measure-enc-rc-v46.sh verify-carrier [--threads N] [--full]
#
# CUDA episode context (digest / probe; requires CUDA-built test_btx):
#   contrib/matmul-v4/measure-enc-rc-v46.sh cuda-episode-tests
#
# Heights stay INT32_MAX. Toy/PARTIAL never raises activation.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MEASURE="$ROOT/contrib/matmul-v4/measure-hardware.sh"

usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

cmd="${1:-}"
shift || true

case "$cmd" in
  -h|--help|help|"")
    usage
    ;;
  verify-carrier)
    THREADS=32
    FULL=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --threads) THREADS="${2:?}"; shift 2 ;;
        --full) FULL=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
      esac
    done
    BIN=""
    for d in "$ROOT/build" "$ROOT"/build-*; do
      [ -x "$d/bin/test_btx" ] && BIN="$d/bin/test_btx" && break
    done
    if [ -z "$BIN" ]; then
      echo "test_btx not found; build Release with BUILD_TESTS=ON first" >&2
      exit 2
    fi
    echo "== ENC_RC v4.6 production carrier verify compute bench =="
    echo "-- tip $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "-- binary $BIN"
    echo "-- threads=$THREADS full=$FULL"
    export BTX_RC_PROD_CARRIER_VERIFY_BENCH=1
    export BTX_RC_PROD_CARRIER_VERIFY_BENCH_THREADS="$THREADS"
    if [ "$FULL" -eq 1 ]; then
      export BTX_RC_PROD_CARRIER_VERIFY_BENCH_FULL=1
    fi
    set +e
    "$BIN" --logger=HRF,all \
      --run_test=matmul_v4_rc_datacenter_tests/rc_dc_production_carrier_verify_compute_benchmark
    CODE=$?
    set -e
    echo ""
    echo "Interpret: total_ms ≤ 900 and stopped_at_budget=0 ⇒ verifier-floor GO candidate."
    echo "nMatMulRCHeight remains INT32_MAX (never raise from this bench alone)."
    exit "$CODE"
    ;;
  cuda-episode-tests)
    BIN=""
    for d in "$ROOT/build-cuda-rc46" "$ROOT/build-cuda" "$ROOT/build-measure-cuda" "$ROOT"/build*; do
      [ -x "$d/bin/test_btx" ] && BIN="$d/bin/test_btx" && break
    done
    if [ -z "$BIN" ]; then
      echo "CUDA test_btx not found; build with ENABLE_CUDA / build-cuda first" >&2
      exit 2
    fi
    echo "== ENC_RC v4.6 CUDA episode context tests =="
    echo "-- tip $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "-- binary $BIN"
    set +e
    "$BIN" --logger=HRF,all --run_test=matmul_v4_rc_datacenter_tests/rc_dc_cuda_episode*
    CODE=$?
    set -e
    exit "$CODE"
    ;;
  cpu|cuda|metal|hip)
    # Force RC mode for any bare backend: never fall through to matmul-v4-report.
    if [ $# -eq 0 ]; then
      echo "error: ENC_RC v4.6 measure requires an RC profile or harness args." >&2
      echo "  Example: $0 cpu --profile coupled" >&2
      echo "  Example: $0 cpu rc --coupled-v3-ci" >&2
      echo "Legacy v4.1/v4.2/LT PoW measure is blocked here; use measure-hardware.sh" >&2
      echo "with BTX_ALLOW_LEGACY_MATMUL_MEASURE=1 only if you truly need it." >&2
      exit 2
    fi
    # If caller already passed `rc` or --profile Stage-G, forward as-is under RC.
    has_rc=0
    prev=""
    for a in "$@"; do
      if [ "$a" = "rc" ] && [ "$prev" != "--profile" ]; then has_rc=1; fi
      if [ "$prev" = "--profile" ]; then
        case "$a" in coupled|coupled-medium|rc-toy|rc-medium) has_rc=1 ;; esac
      fi
      prev="$a"
    done
    if [ "$has_rc" -eq 0 ]; then
      set -- rc "$@"
    fi
    exec "$MEASURE" "$cmd" "$@"
    ;;
  rc)
    # `measure-enc-rc-v46.sh rc cpu --toy` → measure-hardware.sh cpu rc --toy
    backend="${1:?backend after rc}"
    shift
    exec "$MEASURE" "$backend" rc "$@"
    ;;
  *)
    echo "unknown command: $cmd" >&2
    usage
    ;;
esac
