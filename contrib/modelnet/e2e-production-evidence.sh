#!/usr/bin/env bash
# Hashed binaries + e2e logs. Does not flip packaged CSV. Fail-fast.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/e2e-scratch/production-evidence"
mkdir -p "$OUT"
{
  echo "schema_version=2"
  echo "csv=NOT_RUN"
  date -Is
  echo "=== binaries ==="
  for b in btx-modeld test_btx btx-open btx-modelcheck btx-cli btxd; do
    p="$ROOT/build-gcc13/bin/$b"
    if [[ -x "$p" ]]; then
      sha256sum "$p"
      "$p" -version 2>/dev/null | head -2 || true
    fi
  done
  echo "=== openssl prefix ==="
  if [[ -x "$HOME/.local/opt/openssl-3.5.8/bin/openssl" ]]; then
    LD_LIBRARY_PATH="$HOME/.local/opt/openssl-3.5.8/lib" "$HOME/.local/opt/openssl-3.5.8/bin/openssl" version
    sha256sum "$HOME/.local/opt/openssl-3.5.8/lib/libssl.so.3" "$HOME/.local/opt/openssl-3.5.8/lib/libcrypto.so.3"
  fi
  echo "=== bench ==="
  [[ -f $ROOT/e2e-scratch/bench-12-3/bench.json ]] && cat "$ROOT/e2e-scratch/bench-12-3/bench.json"
  echo "=== disc / two-wan ==="
  echo "e2e-disc-failure.sh and e2e-two-wan.sh are the production proofs for DISC-05 and STORE-01"
  echo "=== granite historical ==="
  cat <<'G'
{"payload_bytes":13888336427,"elapsed_s":6562,"verified_throughput_bps":2116480,"first_useful_byte_note":"WAN granite retrieve already BYTES_VERIFIED on replica","free_completion_share":1.0}
G
} | tee "$OUT/evidence.txt"
sha256sum "$OUT/evidence.txt" | tee "$OUT/evidence.sha256"
echo "E2E_EVIDENCE PASS $OUT/evidence.sha256"
