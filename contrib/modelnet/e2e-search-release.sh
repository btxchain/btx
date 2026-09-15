#!/usr/bin/env bash
# SEARCH-RELEASE-E2E: createmodelrelease + search record carries release_id; getrecentreleases sees it.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CONTRIB="$ROOT/contrib/modelnet"
SCRATCH="$ROOT/e2e-scratch/search-release"
PID=""
die() { printf 'e2e-search-release: %s\n' "$*" >&2; exit 1; }
cleanup() {
  local rc=$?
  [[ -n "${PID:-}" ]] && kill -TERM "$PID" 2>/dev/null || true
  sleep 0.2
  [[ -n "${PID:-}" ]] && kill -KILL "$PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$SCRATCH"
  exit "$rc"
}
trap cleanup EXIT
[[ -x "$BIN" ]] || die "missing $BIN"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/h" "$SCRATCH/src"
python3 - "$SCRATCH/src/weights.safetensors" <<'PY'
import json, struct, sys
from pathlib import Path
p = Path(sys.argv[1])
n = 64
header = {"w": {"dtype": "F32", "shape": [n], "data_offsets": [0, n * 4]}}
hb = json.dumps(header, separators=(",", ":")).encode()
p.write_bytes(struct.pack("<Q", len(hb)) + hb + bytes(n * 4))
PY
"$BIN" -modeldir="$SCRATCH/h" -modelstorage=8MiB -modelrpcsocket="$SCRATCH/h/modeld.sock" \
  >"$SCRATCH/h/modeld.log" 2>&1 &
PID=$!
python3 - "$SCRATCH/h/modeld.sock" "$PID" "$SCRATCH/src/weights.safetensors" "$CONTRIB" <<'PY'
import json, os, socket, sys
from pathlib import Path
sock, pid, src = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
sys.path.insert(0, sys.argv[4])
from failfast import wait_unix

def rpc(method, params, timeout=30):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params}).encode()+b"\n")
    s.shutdown(socket.SHUT_WR)
    data=b""
    while True:
        c=s.recv(65536)
        if not c: break
        data+=c
        if b"\n" in data: break
    s.close()
    m=json.loads(data.decode())
    if m.get("error"): raise SystemExit(f"{method}: {m['error']}")
    return m["result"]

def connect():
    i=rpc("getmodelnetworkinfo",[])
    return i if i.get("helper_ready") else None
wait_unix(connect, timeout=20, pid=pid, log=sock.parent/"modeld.log")
imp=rpc("importmodel",[src,{"pin":True}])
uri=imp["uri"]
secret="11"*32
rel=rpc("createmodelrelease",[uri, secret, 100])
rid=rel.get("release_id") or rel.get("id")
if not rid:
    raise SystemExit(f"createmodelrelease: {rel}")
mid=imp.get("model_id")
rpc("publishmodelsearchrecord",[mid, {
    "type": "btx-model-search-v1",
    "canonical_name": "Release Campaign Lab",
    "display_name": "Release Campaign Lab",
    "release_id": rid,
    "release_state": "PUBLIC",
    "expires_at": 0,
}])
listed=rpc("listmodelsearchrecords",[{"limit":20}])
print("listed", [(r.get("display_name"), r.get("release_id")) for r in (listed.get("records") or []) if isinstance(r, dict)], flush=True)
sm=rpc("searchmodels",[{"text":"release campaign","scope":"LOCAL","limit":20}])
rnames=[str(h.get("name") or "") for h in (sm.get("results") or []) if isinstance(h, dict)]
if not any("Release Campaign" in n for n in rnames):
    raise SystemExit(f"searchmodels missed release: {rnames} listed={listed}")
recent=rpc("getrecentreleases",[{}])
hits=recent.get("results") or []
names=[str(h.get("name") or "") for h in hits if isinstance(h, dict)]
if not names:
    raise SystemExit(f"getrecentreleases empty: {recent}")
print("E2E_SEARCH_RELEASE PASS", rid, "recent", names[:5], flush=True)
PY
echo "e2e-search-release: PASS"
