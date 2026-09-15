#!/usr/bin/env bash
# Two independent seeders; fetcher retrieves from both contacts (STORE-01 multi-source).
# Fail-fast. Loopback. Not production.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch/two-source"
PA="" PB="" PF=""
die() { echo "e2e-two-source: $*" >&2; exit 1; }
cleanup() {
  local rc=$?
  for p in "$PF" "$PA" "$PB"; do [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true; done
  sleep 0.2
  exit "$rc"
}
trap cleanup EXIT
[[ -x "$BIN" ]] || die "missing $BIN"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/a/src" "$SCRATCH/b" "$SCRATCH/f"
python3 -c 'import struct; from pathlib import Path; Path("'"$SCRATCH"'/a/src/model.safetensors").write_bytes(struct.pack("<Q",2)+b"{}")'
pick() { python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORTA="$(pick)"; PORTB="$(pick)"
"$BIN" -modeldir="$SCRATCH/a" -modelstorage=16MiB -modelbind="127.0.0.1:${PORTA}" -modelhost -modelrpcsocket="$SCRATCH/a/modeld.sock" >"$SCRATCH/a/modeld.log" 2>&1 &
PA=$!
"$BIN" -modeldir="$SCRATCH/b" -modelstorage=16MiB -modelbind="127.0.0.1:${PORTB}" -modelhost -modelrpcsocket="$SCRATCH/b/modeld.sock" >"$SCRATCH/b/modeld.log" 2>&1 &
PB=$!
"$BIN" -modeldir="$SCRATCH/f" -modelstorage=16MiB -modelpeer="127.0.0.1:${PORTA}" -modelpeer="127.0.0.1:${PORTB}" -modelrpcsocket="$SCRATCH/f/modeld.sock" >"$SCRATCH/f/modeld.log" 2>&1 &
PF=$!
python3 - "$SCRATCH" "$PA" "$PB" "$PF" "$ROOT/contrib/modelnet" <<'PY'
import json, socket, sys, time
from pathlib import Path
root=Path(sys.argv[1]); pa,pb,pf=int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4])
sys.path.insert(0, sys.argv[5])
from failfast import wait_unix, poll_job

def rpc(sock, method, params, timeout=20):
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(timeout)
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
    if m.get("error"): raise SystemExit("%s: %s"%(method,m["error"]))
    return m["result"]

def ready(path, pid):
    def c():
        i=rpc(path,"getmodelnetworkinfo",[])
        return i if i.get("helper_ready") else None
    return wait_unix(c, timeout=20, pid=pid, log=path.parent/"modeld.log")

sa, sb, sf = root/"a/modeld.sock", root/"b/modeld.sock", root/"f/modeld.sock"
ready(sa, pa); ready(sb, pb); ready(sf, pf)
src=str(root/"a/src")
imp=rpc(sa,"importmodel",[src,{"pin":True}])
uri=imp["uri"]
# second seeder independently hosts the same bytes
impb=rpc(sb,"importmodel",[src,{"pin":True}])
if impb.get("uri")!=uri: raise SystemExit("uri mismatch %s vs %s"%(uri,impb.get("uri")))
peers=rpc(sf,"getmodelpeers",[])
if len(peers.get("peers") or [])<2: raise SystemExit("need 2 peers: %s"%peers)
got=rpc(sf,"getmodel",[uri,"FREE_ONLY"])
if got.get("status") in ("retrieved","local"):
    pass
elif got.get("job_id"):
    poll_job(lambda: rpc(sf,"getmodeljob",[got["job_id"]]), timeout=30)
else:
    raise SystemExit("getmodel: %s"%got)
listed=rpc(sf,"listmodels",[])
if int(listed.get("local_count") or 0)<1: raise SystemExit(listed)
# resume: already local
got2=rpc(sf,"getmodel",[uri,"FREE_ONLY"])
if got2.get("status") not in ("retrieved","local"): raise SystemExit("resume: %s"%got2)
print("TWO_SOURCE PASS", json.dumps({"uri":uri,"peers":len(peers["peers"]),"resume":got2.get("status")}))
PY
echo "E2E_TWO_SOURCE PASS"
