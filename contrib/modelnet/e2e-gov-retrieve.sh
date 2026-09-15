#!/usr/bin/env bash
# GOV-RETRIEVE-REG: two concurrent FREE_ONLY retrieves against one seeder still complete.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CONTRIB="$ROOT/contrib/modelnet"
SCRATCH="$ROOT/e2e-scratch/gov-retrieve"
PA="" PB="" PC=""
die() { printf 'e2e-gov-retrieve: %s\n' "$*" >&2; exit 1; }
cleanup() {
  local rc=$?
  for p in "$PC" "$PB" "$PA"; do [[ -n "${p:-}" ]] && kill -TERM "$p" 2>/dev/null || true; done
  sleep 0.3
  for p in "$PC" "$PB" "$PA"; do [[ -n "${p:-}" ]] && kill -KILL "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$SCRATCH"
  exit "$rc"
}
trap cleanup EXIT
[[ -x "$BIN" ]] || die "missing $BIN"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/src" "$SCRATCH/a" "$SCRATCH/b" "$SCRATCH/c"
python3 - "$SCRATCH/src" <<'PY'
import json, struct, sys
from pathlib import Path
p = Path(sys.argv[1])
target = 8 * 1024 * 1024
n = (target - 256) // 4
header = {"w": {"dtype": "F32", "shape": [n], "data_offsets": [0, n * 4]}}
hb = json.dumps(header, separators=(",", ":")).encode()
raw = struct.pack("<Q", len(hb)) + hb + bytes(n * 4)
(p / "weights.safetensors").write_bytes(raw[:target] if len(raw) > target else raw)
print("wrote", (p / "weights.safetensors").stat().st_size, flush=True)
PY
pick() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORT="$(pick)"
"$BIN" -modeldir="$SCRATCH/a" -modelstorage=64MiB -modelbind="127.0.0.1:${PORT}" -modelhost \
  -modelrpcsocket="$SCRATCH/a/modeld.sock" >"$SCRATCH/a/modeld.log" 2>&1 &
PA=$!
"$BIN" -modeldir="$SCRATCH/b" -modelstorage=64MiB -modelpeer="127.0.0.1:${PORT}" \
  -modelrpcsocket="$SCRATCH/b/modeld.sock" >"$SCRATCH/b/modeld.log" 2>&1 &
PB=$!
"$BIN" -modeldir="$SCRATCH/c" -modelstorage=64MiB -modelpeer="127.0.0.1:${PORT}" \
  -modelrpcsocket="$SCRATCH/c/modeld.sock" >"$SCRATCH/c/modeld.log" 2>&1 &
PC=$!
python3 - "$SCRATCH" "$PA" "$PB" "$PC" "$CONTRIB" <<'PY'
import json, socket, sys, time
from pathlib import Path
root=Path(sys.argv[1]); pa,pb,pc=map(int, sys.argv[2:5])
sys.path.insert(0, sys.argv[5])
from failfast import wait_unix, poll_job

def rpc(sock, method, params, timeout=60):
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
    return wait_unix(c, timeout=25, pid=pid, log=path.parent/"modeld.log")

sa,sb,sc=[root/x/"modeld.sock" for x in "abc"]
ready(sa, pa); ready(sb, pb); ready(sc, pc)
imp=rpc(sa,"importmodel",[str(root/"src"/"weights.safetensors"),{"pin":True}])
uri=imp["uri"]
t0=time.time()
gb=rpc(sb,"getmodel",[uri,"FREE_ONLY"])
gc=rpc(sc,"getmodel",[uri,"FREE_ONLY"])
for sock, got in ((sb, gb), (sc, gc)):
    if got.get("job_id"):
        poll_job(lambda g=got, so=sock: rpc(so,"getmodeljob",[g["job_id"]]), timeout=120, stall_s=60)
    elif got.get("status") not in ("retrieved","local"):
        raise SystemExit("retrieve %s"%got)
elapsed=time.time()-t0
man_b=rpc(sb,"getmodelmanifest",[uri])
man_c=rpc(sc,"getmodelmanifest",[uri])
sha_b=(man_b.get("files") or [{}])[0].get("sha384")
sha_c=(man_c.get("files") or [{}])[0].get("sha384")
if not sha_b or sha_b!=sha_c:
    raise SystemExit("sha mismatch")
print("E2E_GOV_RETRIEVE PASS concurrent_s", round(elapsed, 3), flush=True)
PY
echo "e2e-gov-retrieve: PASS"
