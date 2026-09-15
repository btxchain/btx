#!/usr/bin/env bash
# Search index scale: bulk unsigned ModelSearchRecord import via importmodelindex (unix RPC).
# Default documents unit-test coverage; set BTX_SEARCH_SCALE_RUN=1 to execute (memory-capped batches).
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${BIN_DIR:-$ROOT/build-gcc13/bin}"
MODELD="${MODELD:-$BIN/btx-modeld}"
CONTRIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="/tmp/btx-search-scale-$$"
TARGET="${BTX_SEARCH_SCALE_COUNT:-100000}"
BATCH="${BTX_SEARCH_SCALE_BATCH:-200}"
HELPER_PID=""

cleanup() {
  local rc=$?
  if [[ -n "${HELPER_PID}" ]] && kill -0 "$HELPER_PID" 2>/dev/null; then
    kill -TERM "$HELPER_PID" 2>/dev/null || true
  fi
  rm -rf "$BASE"
  rm -rf /tmp/test_runner_*
  rm -rf /tmp/btx-search-scale-*
  exit "$rc"
}
trap cleanup EXIT

if [[ "${BTX_SEARCH_SCALE_RUN:-}" != "1" ]]; then
  cat <<EOF
NOT_RUN: scale import disabled (set BTX_SEARCH_SCALE_RUN=1 to run).

Primary scale evidence: C++ unit suite modelnet_search_tests (index cap 100000, publisher
spam bounds, query limits). This script optionally loads BTX_SEARCH_SCALE_COUNT (default
100000) unsigned records in batches of BTX_SEARCH_SCALE_BATCH (default 200) via
importmodelindex — no catalog file reads, bounded RAM.

Example:
  BTX_SEARCH_SCALE_RUN=1 BTX_SEARCH_SCALE_COUNT=5000 TIMEOUT_FACTOR=1 \\
    contrib/modelnet/e2e-search-scale.sh
EOF
  exit 2
fi

if [[ ! -x "$MODELD" ]]; then
  echo "NOT_RUN: btx-modeld missing at $MODELD" >&2
  exit 2
fi

rm -rf "$BASE"
mkdir -p "$BASE/h"

SOCK="$BASE/h/modeld.sock"
"$MODELD" \
  -modeldir="$BASE/h" \
  -modelstorage=8MiB \
  -modelrpcsocket="$SOCK" \
  >"$BASE/h/modeld.log" 2>&1 &
HELPER_PID=$!
export HELPER_PID

python3 - "$SOCK" "$CONTRIB" "$TARGET" "$BATCH" <<'PY'
import json
import os
import socket
import sys
import time
from pathlib import Path

sock = Path(sys.argv[1])
contrib = Path(sys.argv[2])
target = int(sys.argv[3])
batch = max(1, min(int(sys.argv[4]), 100))
sys.path.insert(0, str(contrib))
from failfast import wait_unix

poll = max(0.05, 0.1 * float(os.environ.get("TIMEOUT_FACTOR", "1")))
pid = int(os.environ.get("HELPER_PID", "0"))


def rpc(method, params=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(120)
    s.connect(str(sock))
    s.sendall(
        (json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}) + "\n").encode()
    )
    s.shutdown(socket.SHUT_WR)
    data = s.recv(1 << 22).decode()
    s.close()
    reply = json.loads(data)
    if reply.get("error"):
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply["result"]


def wait_ready():
    def connect():
        if not sock.exists():
            return None
        info = rpc("getmodelnetworkinfo", [])
        return info if info.get("helper_ready") else None

    return wait_unix(connect, timeout=30, pid=pid or None, log=sock.parent / "modeld.log")


wait_ready()

imported_total = 0
tag = 0
while imported_total < target:
    n = min(batch, target - imported_total)
    records = []
    for i in range(n):
        t = tag + i
        mid = f"{t:096x}"
        records.append(
            {
                "type": "btx-model-search-v1",
                "model_id": mid,
                "canonical_name": f"scale-{t}",
                "display_name": f"Scale Record {t}",
                "publisher_display_name": f"pub-{t % 128}",
                "expires_at": 0,
            }
        )
    tag += n
    res = rpc("importmodelindex", [{"records": records}])
    imported_total += int(res.get("imported", 0))
    if int(res.get("imported", 0)) == 0 and int(res.get("rejected", 0)) > 0:
        raise SystemExit(f"import stalled at {imported_total}: {res}")
    if imported_total % (batch * 10) == 0:
        print("imported", imported_total, flush=True)
    time.sleep(poll * 0.1)

stats = rpc("getnetworkmodelstats", [])
known = int(stats.get("search_records_known", stats.get("models_known", 0)))
print("E2E_SEARCH_SCALE imported_total", imported_total, "index_known", known)
if known < min(imported_total, target):
    raise SystemExit(f"index size suspicious: known={known} imported={imported_total}")
print("E2E_SEARCH_SCALE PASS")
PY

echo "e2e-search-scale: PASS"
