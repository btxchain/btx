#!/usr/bin/env bash
# ECON-RELEASE-02 + ECON-FUND-02: lifecycle identity + pledged != funded.
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CONTRIB="$ROOT/contrib/modelnet"
BASE="/tmp/btx-econ-trans-$$"
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
mkdir -p "$BASE/h" "$BASE/src"
python3 - "$BASE/src/weights.safetensors" <<'PY'
import json, struct, sys
from pathlib import Path
p=Path(sys.argv[1]); n=64
header={"w":{"dtype":"F32","shape":[n],"data_offsets":[0,n*4]}}
hb=json.dumps(header,separators=(",",":")).encode()
p.write_bytes(struct.pack("<Q",len(hb))+hb+bytes(n*4))
PY
"$BIN" -modeldir="$BASE/h" -modelstorage=8MiB -modelrpcsocket="$BASE/h/modeld.sock" \
  >"$BASE/h/modeld.log" 2>&1 &
PID=$!
python3 - "$BASE/h/modeld.sock" "$PID" "$CONTRIB" "$BASE/src/weights.safetensors" <<'PY'
import json, socket, sys
from pathlib import Path
sock, pid = Path(sys.argv[1]), int(sys.argv[2])
sys.path.insert(0, sys.argv[3])
src = sys.argv[4]
from failfast import wait_unix

def rpc(method, params=None, timeout=40):
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
imp=rpc("importmodel",[src,{"pin":True}])
rel=rpc("createmodelrelease",[imp["uri"],"22"*32, 100, 10, {
    "publish_search_record": True,
    "display_name":"TransitionX",
    "short_description":"lifecycle identity continuity",
}])
rid=rel["release_id"]
mid=imp["model_id"]
e1=rpc("getmodeleconomyentry",[mid])
life=(e1.get("lifecycle") or {}).get("state") or e1.get("lifecycle_state")
if life != "FUNDING":
    raise SystemExit(f"want FUNDING got {life} {e1}")
rpc("pledgemodelrelease",[rid, 450])
eco=rpc("getmodelreleaseeconomics",[rid])
if int(eco.get("pledged_atoms") or 0) != 450:
    raise SystemExit(f"ECON-FUND-02 pledged {eco}")
if eco.get("value_known") is True:
    raise SystemExit(f"helper must not invent confirmed funded: {eco}")
print("ECON-FUND-02 PASS pledged!=funded", flush=True)
rpc("claimmodelrelease",[mid])
e2=rpc("getmodeleconomyentry",[mid])
id1=(e1.get("model") or {}).get("model_id") or e1.get("model_id")
id2=(e2.get("model") or {}).get("model_id") or e2.get("model_id")
if id1 != id2:
    raise SystemExit(f"identity split {id1} {id2}")
print("ECON-RELEASE-02 PASS", mid, flush=True)
print("E2E_RELEASE_TRANSITION PASS", flush=True)
PY
echo "e2e-release-transition: PASS"
