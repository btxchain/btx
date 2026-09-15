#!/usr/bin/env bash
# Default peer-follow: fetcher MUST retrieve a seeded model from -modelpeer
# without getmodel, seedmodel, or -modelpreserverare. Loopback only.
# Isolated datadirs. Never production btxd.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch/peer-follow"
DIR_A="$SCRATCH/a"
DIR_B="$SCRATCH/b"
SEEDER_PID="" FETCHER_PID=""
die() { printf 'e2e-peer-follow: %s\n' "$*" >&2; exit 1; }
cleanup() {
  local rc=$?
  [[ -n "${FETCHER_PID}" ]] && kill -TERM "$FETCHER_PID" 2>/dev/null || true
  [[ -n "${SEEDER_PID}" ]] && kill -TERM "$SEEDER_PID" 2>/dev/null || true
  sleep 0.2
  exit "$rc"
}
trap cleanup EXIT
[[ -x "$BIN" ]] || die "missing $BIN"
rm -rf "$SCRATCH"
mkdir -p "$DIR_A/src" "$DIR_B"
python3 -c 'import struct; from pathlib import Path; p=Path("'"$DIR_A"'/src/model.safetensors"); Path(p).parent.mkdir(parents=True, exist_ok=True); p.write_bytes(struct.pack("<Q",2)+b"{}")'
PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)"
"$BIN" -modeldir="$DIR_A" -modelstorage=80MiB -modelbind="127.0.0.1:${PORT}" -modelhost \
  -modelrpcsocket="$DIR_A/modeld.sock" >"$DIR_A/modeld.log" 2>&1 &
SEEDER_PID=$!
python3 - "$DIR_A/modeld.sock" "$DIR_A/src" "$SEEDER_PID" "$ROOT/contrib/modelnet" <<'PY'
import json, socket, sys
from pathlib import Path
sock, src, pid = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
sys.path.insert(0, sys.argv[4])
from failfast import wait_unix
def rpc(method, params):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(15)
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
    if m.get("error"): raise SystemExit(str(m["error"]))
    return m["result"]
def connect():
    i=rpc("getmodelnetworkinfo",[])
    return i if i.get("helper_ready") else None
wait_unix(connect, timeout=20, pid=pid, log=sock.parent/"modeld.log")
imp=rpc("importmodel",[str(src),{"pin":True}])
if imp.get("seeded") is not True: raise SystemExit("seeder not demand-seeded")
print("seeder imported", imp.get("uri"), flush=True)
PY
"$BIN" -modeldir="$DIR_B" -modelstorage=80MiB \
  -modelpeer="127.0.0.1:${PORT}" -modelrpcsocket="$DIR_B/modeld.sock" >"$DIR_B/modeld.log" 2>&1 &
FETCHER_PID=$!
python3 - "$DIR_B/modeld.sock" "$FETCHER_PID" "$ROOT/contrib/modelnet" <<'PY'
import json, socket, sys, time
from pathlib import Path
sock_b, fb = Path(sys.argv[1]), int(sys.argv[2])
sys.path.insert(0, sys.argv[3])
from failfast import wait_unix, helper_fatal

def rpc(method, params, timeout=15):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock_b))
    s.sendall(json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params}).encode()+b"\n")
    s.shutdown(socket.SHUT_WR)
    data=b""
    while True:
        c=s.recv(65536)
        if not c: break
        data+=c
        if b"\n" in data: break
    s.close()
    msg=json.loads(data.decode())
    if msg.get("error"): raise SystemExit("%s: %s"%(method,msg["error"]))
    return msg["result"]

def connect():
    i=rpc("getmodelnetworkinfo",[])
    return i if i.get("helper_ready") else None
wait_unix(connect, timeout=20, pid=fb, log=sock_b.parent/"modeld.log")
info=rpc("getmodelnetworkinfo",[])
prop=(info or {}).get("propagation") or {}
if not prop.get("peer_follow_propagation"):
    raise SystemExit("peer_follow_propagation false: %s"%prop)
if prop.get("preservation_propagation"):
    raise SystemExit("preserve-rare must stay off for this test: %s"%prop)
# MUST NOT call getmodel.
t0=time.time()
listed={}
while time.time()-t0 < 25:
    fatal=helper_fatal(pid=fb, log=sock_b.parent/"modeld.log")
    if fatal: raise SystemExit(fatal)
    listed=rpc("listmodels",[])
    if int(listed.get("local_count") or 0)>=1:
        m=(listed.get("models") or [{}])[0]
        if m.get("seeded") is True:
            print("PEER_FOLLOW PASS", json.dumps({"bytes":m.get("bytes"),"seeded":m.get("seeded"),"elapsed":round(time.time()-t0,3)}))
            raise SystemExit(0)
    time.sleep(0.2)
raise SystemExit("peer-follow did not fetch without getmodel: %s"%listed)
PY
echo "E2E_PEER_FOLLOW PASS"
