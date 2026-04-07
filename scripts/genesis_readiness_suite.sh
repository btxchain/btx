#!/usr/bin/env bash
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
#
# Genesis Readiness Benchmark Suite
# ==================================
#
# Comprehensive validation suite that determines whether BTX is ready
# for genesis block creation and mainnet launch.
#
# Components:
#   1. C++ Genesis Calibration Benchmark - Hardware solve timing at powLimit
#   2. DGW Convergence Stress Test - Multi-scenario difficulty adjustment
#   3. Genesis Readiness Functional Test - Full lifecycle chain simulation
#   4. Multi-Node Consensus Test - Peer sync and reorg handling
#
# Usage:
#   ./scripts/genesis_readiness_suite.sh [OPTIONS]
#
# Options:
#   --build-dir DIR    CMake build directory (default: build)
#   --skip-build       Skip building, assume binaries are current
#   --bench-only       Only run the C++ benchmark (fastest)
#   --functional-only  Only run functional tests
#   --report FILE      Write JSON report to FILE (default: genesis_readiness_report.json)
#   --verbose          Show full test output
#   --help             Show this help
#

export LC_ALL=C

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build"
REPORT_FILE="${REPO_ROOT}/genesis_readiness_report.json"
SKIP_BUILD=false
BENCH_ONLY=false
FUNCTIONAL_ONLY=false
VERBOSE=false

resolve_btx_binary() {
    local canonical="$1"
    local legacy="$2"
    if [[ -x "${canonical}" ]]; then
        printf '%s\n' "${canonical}"
    elif [[ -x "${legacy}" ]]; then
        printf '%s\n' "${legacy}"
    else
        printf '%s\n' "${canonical}"
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --bench-only)
            BENCH_ONLY=true
            shift
            ;;
        --functional-only)
            FUNCTIONAL_ONLY=true
            shift
            ;;
        --report)
            REPORT_FILE="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            head -30 "$0" | tail -25
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }
log_pass()   { echo -e "  ${GREEN}PASS${NC}: $1"; }
log_fail()   { echo -e "  ${RED}FAIL${NC}: $1"; }
log_warn()   { echo -e "  ${YELLOW}WARN${NC}: $1"; }
log_info()   { echo -e "  $1"; }

SUITE_START=$(date +%s)
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

record_pass() { ((PASS_COUNT++)); log_pass "$1"; }
record_fail() { ((FAIL_COUNT++)); log_fail "$1"; }
record_warn() { ((WARN_COUNT++)); log_warn "$1"; }

# ---------------------------------------------------------------------------
# Step 0: Build
# ---------------------------------------------------------------------------

if [[ "$SKIP_BUILD" == false ]]; then
    log_header "Step 0: Building BTX (bench + test binaries)"
    if [[ ! -d "$BUILD_DIR" ]]; then
        echo "Build directory not found: $BUILD_DIR"
        echo "Run cmake first, or use --build-dir to specify."
        exit 1
    fi
    cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || echo 4)" --target bench_btx --target test_btx 2>&1 | tail -5
    log_info "Build complete."
else
    log_info "Skipping build (--skip-build)."
fi

BITCOIND_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btxd" "${BUILD_DIR}/bin/bitcoind")"
BITCOIN_CLI_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btx-cli" "${BUILD_DIR}/bin/bitcoin-cli")"

# ---------------------------------------------------------------------------
# Step 1: C++ Genesis Calibration Benchmark
# ---------------------------------------------------------------------------

if [[ "$FUNCTIONAL_ONLY" == false ]]; then
    log_header "Step 1: C++ Genesis Calibration Benchmark"
    BENCH_BIN="${BUILD_DIR}/src/bench/bench_btx"

    if [[ ! -x "$BENCH_BIN" ]]; then
        record_fail "bench_btx not found at $BENCH_BIN"
    else
        BENCH_OUTPUT=$(mktemp)
        if "$BENCH_BIN" -filter='MatMulGenesisCalibration*' 2>&1 | tee "$BENCH_OUTPUT"; then
            record_pass "Genesis calibration benchmark completed"

            # Extract key metrics from output
            if grep -q "PASS:" "$BENCH_OUTPUT"; then
                record_pass "powLimit difficulty calibration"
            elif grep -q "FAIL:" "$BENCH_OUTPUT"; then
                record_fail "powLimit difficulty calibration"
            fi

            if grep -q "Phase 2 verification budget.*OK" "$BENCH_OUTPUT"; then
                record_pass "Phase 2 verification budget"
            elif grep -q "Phase 2 verification budget.*INSUFFICIENT" "$BENCH_OUTPUT"; then
                record_fail "Phase 2 verification budget"
            fi
        else
            record_fail "Genesis calibration benchmark execution"
        fi
        rm -f "$BENCH_OUTPUT"
    fi

    # Also run the existing solve bench for comparison
    log_header "Step 1b: Existing Solve Benchmark (comparison)"
    if [[ -x "$BENCH_BIN" ]]; then
        if "$BENCH_BIN" -filter='MatMulSolve*' 2>&1 | tail -5; then
            record_pass "Existing solve benchmark completed"
        else
            record_warn "Existing solve benchmark had issues"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Step 2: C++ Unit Tests (DGW + MatMul specific)
# ---------------------------------------------------------------------------

if [[ "$BENCH_ONLY" == false ]]; then
    log_header "Step 2: C++ Unit Tests (DGW + MatMul)"
    TEST_BIN="${BUILD_DIR}/src/test/test_btx"

    if [[ ! -x "$TEST_BIN" ]]; then
        record_fail "test_btx not found at $TEST_BIN"
    else
        UNIT_TESTS=(
            "matmul_dgw_tests"
            "matmul_pow_tests"
            "matmul_field_tests"
            "matmul_transcript_tests"
            "matmul_validation_tests"
            "matmul_params_tests"
            "matmul_subsidy_tests"
            "matmul_trust_model_tests"
            "pow_tests"
        )

        for test_suite in "${UNIT_TESTS[@]}"; do
            if "$TEST_BIN" --run_test="$test_suite" 2>&1 | tail -1 | grep -q "No errors detected"; then
                record_pass "Unit test: $test_suite"
            else
                record_fail "Unit test: $test_suite"
            fi
        done
    fi
fi

# ---------------------------------------------------------------------------
# Step 3: Functional Tests
# ---------------------------------------------------------------------------

if [[ "$BENCH_ONLY" == false ]]; then
    log_header "Step 3: Functional Tests"
    FUNC_TEST_DIR="${REPO_ROOT}/test/functional"

    FUNCTIONAL_TESTS=(
        "feature_btx_genesis_readiness.py"
        "feature_btx_dgw_convergence.py"
        "feature_btx_multinode_genesis.py"
        "feature_btx_fast_mining_phase.py"
        "feature_btx_matmul_consensus.py"
        "feature_btx_subsidy_schedule.py"
    )

    for test_file in "${FUNCTIONAL_TESTS[@]}"; do
        test_path="${FUNC_TEST_DIR}/${test_file}"
        if [[ ! -f "$test_path" ]]; then
            record_warn "Functional test not found: $test_file"
            continue
        fi

        log_info "Running $test_file ..."
        TEST_OUTPUT=$(mktemp)

        if $VERBOSE; then
            if python3 "$test_path" --bitcoind="${BITCOIND_BIN}" \
                       --bitcoin-cli="${BITCOIN_CLI_BIN}" 2>&1 | tee "$TEST_OUTPUT"; then
                record_pass "Functional test: $test_file"
            else
                record_fail "Functional test: $test_file"
            fi
        else
            if python3 "$test_path" --bitcoind="${BITCOIND_BIN}" \
                       --bitcoin-cli="${BITCOIN_CLI_BIN}" > "$TEST_OUTPUT" 2>&1; then
                record_pass "Functional test: $test_file"
            else
                record_fail "Functional test: $test_file"
                echo "    Last 10 lines of output:"
                tail -10 "$TEST_OUTPUT" | sed 's/^/    /'
            fi
        fi
        rm -f "$TEST_OUTPUT"
    done
fi

# ---------------------------------------------------------------------------
# Step 4: Summary Report
# ---------------------------------------------------------------------------

SUITE_END=$(date +%s)
SUITE_DURATION=$((SUITE_END - SUITE_START))

log_header "Genesis Readiness Suite Summary"

echo ""
echo -e "  ${GREEN}Passed${NC}: $PASS_COUNT"
echo -e "  ${RED}Failed${NC}: $FAIL_COUNT"
echo -e "  ${YELLOW}Warnings${NC}: $WARN_COUNT"
echo -e "  Duration: ${SUITE_DURATION}s"
echo ""

# Write JSON report
cat > "$REPORT_FILE" <<EOF
{
  "suite": "genesis_readiness",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration_s": $SUITE_DURATION,
  "passed": $PASS_COUNT,
  "failed": $FAIL_COUNT,
  "warnings": $WARN_COUNT,
  "verdict": "$([ $FAIL_COUNT -eq 0 ] && echo 'READY' || echo 'NOT_READY')",
  "notes": [
    "Run bench_btx -filter='MatMulGenesis*' for detailed hardware timing.",
    "Run individual functional tests with --verbose for full output.",
    "50,000 blocks at 0.25s target = ~3.5h minimum fast-phase duration.",
    "Verify mainnet powLimit calibration on actual mining hardware."
  ]
}
EOF

log_info "Report written to: $REPORT_FILE"

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo ""
    echo -e "${GREEN}================================================================${NC}"
    echo -e "${GREEN}  GENESIS READINESS: ALL CHECKS PASSED${NC}"
    echo -e "${GREEN}================================================================${NC}"
    echo ""
    echo "  Remaining manual gates before launch:"
    echo "    1. Run C++ bench on actual mainnet mining hardware"
    echo "    2. Confirm powLimit produces ~0.25s blocks at expected hashrate"
    echo "    3. Decide on fast-phase block count (50,000 = ~3.5h)"
    echo "    4. Run multi-node test on separate physical machines"
    echo ""
    exit 0
else
    echo ""
    echo -e "${RED}================================================================${NC}"
    echo -e "${RED}  GENESIS READINESS: $FAIL_COUNT CHECK(S) FAILED${NC}"
    echo -e "${RED}================================================================${NC}"
    echo ""
    echo "  Fix failing checks before proceeding to genesis."
    echo ""
    exit 1
fi
