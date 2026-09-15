#!/usr/bin/env bash
# Fresh buyer: empty modeldir retrieves a published URI from a dedicated seeder.
# Second-process helper only. Never production helper getmodel. Fail-fast.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FETCHER="${FETCHER_HOST:?set FETCHER_HOST to SSH alias of a non-production fetcher}"
URI="${URI:-btx://pqc0whmrlv2emtc8eknxja6l6ffdj5mta0nj9msfsdkrz6qg0de448gm0a3kcctd92p9ekje2c97wd5glyrdl}"
SEEDER_SSH="${SEEDER_SSH:?set SEEDER_SSH to SSH alias of the dedicated seeder}"
SEEDER_HOST_NAME="$(ssh -G "$SEEDER_SSH" | awk 'tolower($1)=="hostname"{print $2; exit}')"
SEEDER="${SEEDER_ENDPOINT:-${SEEDER_HOST_NAME}:${SEEDER_PORT:-29448}}"
# Hairpin NAT through a public hostname is not a retrieve test.
if [[ -z "${SEEDER_ENDPOINT:-}" && "$FETCHER" == "$SEEDER_SSH" ]]; then
  SEEDER="127.0.0.1:${SEEDER_PORT:-29448}"
fi
WAN_TIMEOUT_S="${WAN_TIMEOUT_S:-28800}"
die() { echo "E2E_FRESH_BUYER FAIL: $*" >&2; exit 1; }

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

check_pids "$FETCHER" "${FETCHER_PROD_PIDS:-}"

scp -o BatchMode=yes "$ROOT/contrib/modelnet/granite_second_process_retrieve.py" \
  "$FETCHER:/tmp/granite_second_process_retrieve.py"
ATTACH_FLAG=()
if [[ "${ATTACH:-}" == "1" ]]; then
  ATTACH_FLAG+=(--attach)
fi
ssh -o BatchMode=yes "$FETCHER" \
  "export BTX_MODELD_DIRNAME=e2e-fresh-buyer; python3 /tmp/granite_second_process_retrieve.py --host '$SEEDER' --uri '$URI' --timeout ${WAN_TIMEOUT_S} --keep ${ATTACH_FLAG[*]}"
check_pids "$FETCHER" "${FETCHER_PROD_PIDS:-}"
echo "E2E_FRESH_BUYER PASS"
