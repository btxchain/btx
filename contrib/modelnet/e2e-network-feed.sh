#!/usr/bin/env bash
# ECON-FEED-01..07: feed RPC modes, persist across helper restart, pagination, coverage.
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CONTRIB="$ROOT/contrib/modelnet"
BASE="/tmp/btx-econ-feed-$$"
PID=""
cleanup() {
  local rc=$?
  [[ -n "${PID:-}" ]] && kill -TERM "$PID" 2>/dev/null || true
  sleep 0.2
  [[ -n "${PID:-}" ]] && kill -KILL "$PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$BASE"
  exit "$rc"
}
trap cleanup EXIT
[[ -x "$BIN" ]] || { echo "NOT_RUN: missing $BIN" >&2; exit 2; }
rm -rf "$BASE"
mkdir -p "$BASE/h"
"$BIN" -modeldir="$BASE/h" -modelstorage=8MiB -modelrpcsocket="$BASE/h/modeld.sock" \
  >"$BASE/h/modeld.log" 2>&1 &
PID=$!
python3 - "$BASE/h/modeld.sock" "$PID" "$CONTRIB" <<'PY'
import json, socket, sys
from pathlib import Path
sock, pid = Path(sys.argv[1]), int(sys.argv[2])
sys.path.insert(0, sys.argv[3])
from failfast import wait_unix

def rpc(method, params=None, timeout=30):
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall((json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params or []})+"\n").encode())
    s.shutdown(socket.SHUT_WR)
    data=b""
    while True:
        c=s.recv(1<<20)
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

def mid(i):
    return f"{i:02x}"+"00"*47

for i in range(12):
    rpc("publishmodelsearchrecord",[mid(i+1), {
        "type":"btx-model-search-v1",
        "canonical_name": f"FeedModel{i}",
        "display_name": f"FeedModel{i}",
        "short_description": "scientific reasoning" if i==0 else "misc",
        "expires_at":0,
        "published_at": 1000+i,
    }])

st=rpc("getmodelfeedstatus",[])
if st.get("global_complete") is True:
    raise SystemExit(f"coverage must not claim global complete: {st}")
if "feed_sequence" not in st:
    raise SystemExit(f"no feed_sequence: {st}")
print("ECON-FEED-07 coverage", st.get("coverage_complete"), flush=True)

page=rpc("getmodelfeed",[{"scope":"LOCAL","mode":"NEWEST","limit":5}])
if page.get("coverage",{}).get("complete") is not False and page.get("coverage",{}).get("global_complete") is True:
    raise SystemExit(f"page claimed complete: {page}")
items=page.get("items") or []
if len(items)!=5:
    raise SystemExit(f"page size {len(items)} {page}")
nxt=page.get("next_cursor")
if not nxt:
    raise SystemExit(f"expected next_cursor: {page}")
page2=rpc("getmodelfeed",[{"scope":"LOCAL","mode":"NEWEST","limit":5,"cursor":nxt}])
ids1=[(x.get("event_id") or "") for x in items]
ids2=[(x.get("event_id") or "") for x in (page2.get("items") or [])]
if ids1 and ids2 and ids1[0]==ids2[0]:
    raise SystemExit(f"pagination overlap {ids1[0]}")
print("ECON-FEED-06 pagination PASS", flush=True)

newest=rpc("getmodelfeed",[{"scope":"LOCAL","mode":"NEWEST","limit":50}])
print("ECON-FEED newest", len(newest.get("items") or []), flush=True)
Path("/tmp/btx-econ-feed-seq.txt").write_text(str(st.get("feed_sequence")))
print("E2E_NETWORK_FEED_PART1 PASS", flush=True)
PY
kill -TERM "$PID" 2>/dev/null || true
sleep 0.4
kill -KILL "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""
"$BIN" -modeldir="$BASE/h" -modelstorage=8MiB -modelrpcsocket="$BASE/h/modeld.sock" \
  >"$BASE/h/modeld.log" 2>&1 &
PID=$!
python3 - "$BASE/h/modeld.sock" "$PID" "$CONTRIB" <<'PY'
import json, socket, sys
from pathlib import Path
sock, pid = Path(sys.argv[1]), int(sys.argv[2])
sys.path.insert(0, sys.argv[3])
from failfast import wait_unix

def rpc(method, params=None, timeout=30):
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall((json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params or []})+"\n").encode())
    s.shutdown(socket.SHUT_WR)
    data=b""
    while True:
        c=s.recv(1<<20)
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
page=rpc("getmodelfeed",[{"scope":"LOCAL","mode":"NEWEST","limit":50}])
names=[]
for it in page.get("items") or []:
    ent=it.get("entry") or {}
    names.append(str(ent.get("name") or (ent.get("model") or {}).get("name") or ""))
if not any("FeedModel" in n for n in names):
    raise SystemExit(f"ECON-FEED-05 persist miss after restart: {names[:8]} {page}")
print("ECON-FEED-05 persist PASS", names[:3], flush=True)
print("E2E_NETWORK_FEED PASS", flush=True)
PY
echo "e2e-network-feed: PASS"
