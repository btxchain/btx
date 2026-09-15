#!/usr/bin/env bash
# Fail-fast production PID watch on two operator hosts while other e2e jobs run.
# Requires FETCHER_HOST, SEEDER_HOST, FETCHER_PROD_PIDS, SEEDER_PROD_PIDS.
# Exits 0 when $1/stop-watch appears, or after 300s. Never SIGKILL.
export LC_ALL=C
set -euo pipefail
FETCHER_HOST="${FETCHER_HOST:?set FETCHER_HOST}"
SEEDER_HOST="${SEEDER_HOST:?set SEEDER_HOST}"
FETCHER_PROD_PIDS="${FETCHER_PROD_PIDS:?set FETCHER_PROD_PIDS}"
SEEDER_PROD_PIDS="${SEEDER_PROD_PIDS:?set SEEDER_PROD_PIDS}"
LOG="${1:-/tmp/e2e-watch}"
mkdir -p "$LOG"
deadline=$((SECONDS + 300))
while (( SECONDS < deadline )); do
  if [[ -f "$LOG/stop-watch" ]]; then
    echo "WATCH PASS stop-watch"
    exit 0
  fi
  fetcher="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$FETCHER_HOST" "ps -p ${FETCHER_PROD_PIDS} -o pid=" || true)"
  IFS=',' read -r -a fp <<<"$FETCHER_PROD_PIDS"
  for p in "${fp[@]}"; do
    echo "$fetcher" | grep -q "$p" || { echo "WATCH FAIL fetcher pid $p gone" >&2; exit 1; }
  done
  seeder="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$SEEDER_HOST" "ps -p ${SEEDER_PROD_PIDS} -o pid=; nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv" || true)"
  IFS=',' read -r -a sp <<<"$SEEDER_PROD_PIDS"
  for p in "${sp[@]}"; do
    echo "$seeder" | grep -q "$p" || { echo "WATCH FAIL seeder pid $p gone" >&2; exit 1; }
  done
  echo "$seeder" | grep -q btxd.real || { echo "WATCH FAIL seeder GPU lost btxd.real" >&2; exit 1; }
  sleep 5
done
echo "WATCH FAIL timeout waiting for stop-watch" >&2
exit 1
