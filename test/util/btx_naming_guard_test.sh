#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

declare -a SCOPE=(
  "${ROOT_DIR}/README.md"
  "${ROOT_DIR}/src/test/README.md"
  "${ROOT_DIR}/scripts"
  "${ROOT_DIR}/doc/btx"*.md
  "${ROOT_DIR}/doc/btx-"*.md
  "${ROOT_DIR}/doc/benchmarking.md"
  "${ROOT_DIR}/doc/JSON-RPC-interface.md"
  "${ROOT_DIR}/doc/developer-notes.md"
  "${ROOT_DIR}/doc/freivalds-algorithm-analysis.md"
  "${ROOT_DIR}/doc/m15-full-lifecycle-runbook.md"
  "${ROOT_DIR}/doc/pq-multisig-full-implementation-tracker.md"
  "${ROOT_DIR}/doc/productivity.md"
  "${ROOT_DIR}/doc/pq-benchmark-results.md"
  "${ROOT_DIR}/doc/release-process.md"
  "${ROOT_DIR}/doc/matmul_external_miner_backend_tracking.md"
  "${ROOT_DIR}/contrib/valgrind.supp"
  "${ROOT_DIR}/contrib/devtools/README.md"
  "${ROOT_DIR}/contrib/devtools/test_deterministic_coverage.sh"
  "${ROOT_DIR}/scripts/refresh_btx_util_vectors.py"
  "${ROOT_DIR}/scripts/update_chain_hardening_manifest.py"
  "${ROOT_DIR}/test/functional/feature_btx_genesis_readiness.py"
  "${ROOT_DIR}/test/util/test_runner.py"
  "${ROOT_DIR}/test/util/update_chain_hardening_manifest_test.sh"
)

fail=0

check_absent() {
  local pattern="$1"
  local label="$2"
  if rg -n --color=never -S -e "${pattern}" "${SCOPE[@]}" >/tmp/btx_naming_guard_hits.txt; then
    echo "btx_naming_guard_test: found legacy ${label} references:" >&2
    cat /tmp/btx_naming_guard_hits.txt >&2
    fail=1
  fi
}

check_absent "\\btest_bitcoin\\b" "test binary naming"
check_absent "\\btest_bitcoin-qt\\b" "qt test binary naming"
check_absent "\\bbench_bitcoin\\b" "bench binary naming"
check_absent "--target[[:space:]]+test_bitcoin\\b" "cmake test target naming"
check_absent "--target[[:space:]]+bench_bitcoin\\b" "cmake bench target naming"
check_absent "--target[[:space:]]+bitcoind\\b" "cmake daemon target naming"
check_absent "--target[[:space:]]+bitcoin-cli\\b" "cmake cli target naming"
check_absent "--target[[:space:]]+bitcoin-qt\\b" "cmake gui target naming"
check_absent "--bitcoin-cli[[:space:]]+build-btx/bin/bitcoin-cli\\b" "release command legacy cli naming"
check_absent "\"method\": \"getbalance\"" "shielded JSON-RPC balance method example"
check_absent "test/util/data/bitcoin-util-test\\.json" "utility testcase filename naming"
check_absent "ninja[[:space:]]+-C[[:space:]]+build[[:space:]]+test_btx[[:space:]]+bitcoind\\b" "legacy daemon binary in BTX build command"
check_absent "\\bbitcoind[[:space:]]+-regtest\\b" "legacy daemon invocation in BTX runbooks"

if [[ "${fail}" -ne 0 ]]; then
  exit 1
fi

echo "btx_naming_guard_test: PASS"
