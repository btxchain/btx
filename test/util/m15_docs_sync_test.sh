#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PARENT_README="${ROOT_DIR}/../README.md"
NODE_README="${ROOT_DIR}/README.md"
RUNBOOK="${ROOT_DIR}/doc/m15-full-lifecycle-runbook.md"
TRACKER="${ROOT_DIR}/doc/btx-final-pass-lifecycle-tracker.md"

test -f "${PARENT_README}"
test -f "${NODE_README}"
test -f "${RUNBOOK}"
test -f "${TRACKER}"

rg -q "m15_full_lifecycle_matrix\\.sh" "${PARENT_README}"
rg -q "m15_single_node_wallet_lifecycle\\.sh" "${PARENT_README}"
rg -q "Startup/wallet creation/mining/send/receive/lock/unlock all validated" "${PARENT_README}"
rg -q "M15 single-node lifecycle checks passed" "${PARENT_README}"
rg -q "\"skipped_steps\": \\[\\]" "${PARENT_README}"
rg -q "m15_full_lifecycle_matrix\\.sh" "${NODE_README}"
rg -q "m15_single_node_wallet_lifecycle\\.sh" "${NODE_README}"
rg -q "M15 single-node lifecycle checks passed" "${NODE_README}"
rg -q "Overall status: pass" "${PARENT_README}"
rg -q "\"skipped_phases\": \\[\\]" "${PARENT_README}"
rg -q "Overall status: pass" "${NODE_README}"
rg -q "Expected output" "${RUNBOOK}"
rg -q "Bridge Lifecycle \\(macOS <-> CentOS\\)" "${RUNBOOK}"
rg -q "Failure Triage" "${RUNBOOK}"
rg -q "\"skipped_steps\": \\[\\]" "${RUNBOOK}"
rg -q "\"skipped_phases\": \\[\\]" "${RUNBOOK}"
rg -q "M15-6" "${TRACKER}"

echo "m15_docs_sync_test: PASS"
