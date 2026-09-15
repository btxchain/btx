#!/usr/bin/env bash
# Two seeders + fetcher on one dedicated host (same OpenSSL). STORE-01 resume.
# Coordinator copies payload and optionally checks production PIDs. Fail-fast.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRATCH="$ROOT/e2e-scratch/two-wan"
HOST="${SEEDER_HOST:?set SEEDER_HOST to SSH alias of the two-seeder host}"
PORT="${TWOWAN_PORT:-29451}"
PORT2=$((PORT + 1))
BYTES=$((32 * 1024 * 1024))
die() { echo "E2E_TWO_WAN FAIL: $*" >&2; cleanup || true; exit 1; }
cleanup() {
  ssh -o BatchMode=yes "$HOST" 'for f in /tmp/btx-twowan-a/modeld.pid /tmp/btx-twowan-b/modeld.pid /tmp/btx-twowan-f/modeld.pid; do
    if [ -f "$f" ]; then kill -TERM "$(cat "$f")" 2>/dev/null || true; fi
  done' || true
}
trap cleanup EXIT
check_pids() {
  local host="$1" pids="${2:-}"
  [[ -n "$pids" ]] || return 0
  local have p
  have="$(ssh -o BatchMode=yes "$host" "ps -p ${pids} -o pid=" || true)"
  IFS=',' read -r -a want <<<"$pids"
  for p in "${want[@]}"; do
    echo "$have" | grep -q "$p" || die "$host production pid $p is gone"
  done
}
rm -rf "$SCRATCH"; mkdir -p "$SCRATCH/payload"
python3 "$ROOT/contrib/modelnet/write_safetensors_payload.py" "$SCRATCH/payload/model.safetensors" "$BYTES"
check_pids "${FETCHER_HOST:-}" "${FETCHER_PROD_PIDS:-}"
check_pids "$HOST" "${SEEDER_PROD_PIDS:-}"
scp -o BatchMode=yes "$SCRATCH/payload/model.safetensors" "$HOST:/tmp/btx-twowan-model.safetensors"
scp -o BatchMode=yes "$ROOT/contrib/modelnet/e2e-two-wan-remote.sh" "$HOST:/tmp/e2e-two-wan-remote.sh"
ssh -o BatchMode=yes "$HOST" "bash /tmp/e2e-two-wan-remote.sh $PORT $PORT2"
RESULT="$(ssh -o BatchMode=yes "$HOST" 'cat /tmp/btx-twowan-result.json')"
echo "$RESULT" | python3 -c 'import json,sys; m=json.load(sys.stdin); assert int(m.get("bytes") or 0)>1024, m; assert m.get("seeded") is True, m; print("ok", m)'
check_pids "${FETCHER_HOST:-}" "${FETCHER_PROD_PIDS:-}"
check_pids "$HOST" "${SEEDER_PROD_PIDS:-}"
echo "E2E_TWO_WAN PASS $RESULT"
