#!/usr/bin/env bash
# V4.5 V3 production campaign harness (scaffold).
# Records absolute device-timed nonce/s JSON conforming to
# contrib/matmul-v4/v45-v3-benchmark.schema.json.
#
# Does NOT raise activation heights. Does NOT claim peak_ready.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-/tmp/btx-v45-v3-sample.json}"
COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
DIRTY="$(git -C "$ROOT" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"

cat >"$OUT" <<EOF
{
  "git_commit": "$COMMIT",
  "dirty": $([ "$DIRTY" = "0" ] && echo false || echo true),
  "backend": "unmeasured",
  "config_version": 3,
  "bank_pages": 1536,
  "rows_per_lobe": 128,
  "pages_per_barrier_lobe": 24,
  "packed_bytes": $((1536 * 8192 * 8192 * 17 / 32)),
  "expanded_bytes": $((1536 * 8192 * 8192)),
  "residency_mode": "not_run",
  "q_batch": 0,
  "device_event_ns": 0,
  "host_wall_ns": 0,
  "nonce_per_s": 0,
  "exact_match": false,
  "peak_ready": false,
  "peak_ready_deficit": "campaign_scaffold_only_no_silicon_run",
  "note": "PLAUSIBLE BUT UNMEASURED — fill after B200/5090 matched runs"
}
EOF
echo "wrote $OUT"
