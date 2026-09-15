#!/usr/bin/env bash
# SEARCH-CREATOR-E2E: publishmodelsearchrecord then LOCAL search (GUI Publish tab RPC).
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CONTRIB="$ROOT/contrib/modelnet"
SCRATCH="$ROOT/e2e-scratch/search-creator"
PA=""
die() { printf 'e2e-search-creator: %s\n' "$*" >&2; exit 1; }
cleanup() {
  local rc=$?
  [[ -n "${PA:-}" ]] && kill -TERM "$PA" 2>/dev/null || true
  sleep 0.2
  [[ -n "${PA:-}" ]] && kill -KILL "$PA" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$SCRATCH"
  exit "$rc"
}
trap cleanup EXIT
[[ -x "$BIN" ]] || die "missing $BIN"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/a"
"$BIN" -modeldir="$SCRATCH/a" -modelstorage=8MiB -modelrpcsocket="$SCRATCH/a/modeld.sock" \
  >"$SCRATCH/a/modeld.log" 2>&1 &
PA=$!
python3 - "$SCRATCH/a/modeld.sock" "$PA" "$CONTRIB" <<'PY'
import json, socket, sys
from pathlib import Path
sock, pid = Path(sys.argv[1]), int(sys.argv[2])
sys.path.insert(0, sys.argv[3])
from failfast import wait_unix

def rpc(method, params, timeout=20):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        data += c
        if b"\n" in data:
            break
    s.close()
    m = json.loads(data.decode())
    if m.get("error"):
        raise SystemExit("%s: %s" % (method, m["error"]))
    return m["result"]

def connect():
    if not sock.exists():
        return None
    i = rpc("getmodelnetworkinfo", [])
    return i if i.get("helper_ready") else None

wait_unix(connect, timeout=20, pid=pid, log=sock.parent / "modeld.log")
mid = "aa" + "00" * 47
pub = rpc("publishmodelsearchrecord", [mid, {
    "type": "btx-model-search-v1",
    "canonical_name": "GUI Creator Model",
    "display_name": "GUI Creator Model",
    "short_description": "creator publish flow",
}])
assert pub.get("automatic_spend_atoms") == 0
assert pub.get("wallet_key") is False
hits = rpc("searchmodels", [{"text": "GUI Creator", "scope": "LOCAL"}])
blob = json.dumps(hits)
assert "GUI Creator" in blob, hits
print("SEARCH-CREATOR-E2E PASS")
PY
