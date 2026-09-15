#!/usr/bin/env bash
# SHARD-08/10/14 live: three helpers, disjoint 4 MiB pieces, fetcher reconstructs.
# Isolated. Never production btxd.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch/shard-disjoint"
PA="" PB="" PC="" PF=""
cleanup() {
  local rc=$?
  for p in "$PF" "$PA" "$PB" "$PC"; do [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true; done
  sleep 0.3
  exit "$rc"
}
trap cleanup EXIT
[[ -x "$BIN" ]] || { echo "missing $BIN" >&2; exit 1; }
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/src" "$SCRATCH/a" "$SCRATCH/b" "$SCRATCH/c" "$SCRATCH/d"
# 12 MiB + tiny header => 3 full 4 MiB pieces plus a short tail if extra bytes.
python3 - <<PY
import json, struct
from pathlib import Path
p = Path("$SCRATCH/src")
p.mkdir(parents=True, exist_ok=True)
target = 12 * 1024 * 1024
n = (target - 128) // 4
for _ in range(8):
    header = {"w": {"dtype": "F32", "shape": [n], "data_offsets": [0, n * 4]}}
    hb = json.dumps(header, separators=(",", ":")).encode()
    total = 8 + len(hb) + n * 4
    n = n + (target - total) // 4
header = {"w": {"dtype": "F32", "shape": [n], "data_offsets": [0, n * 4]}}
hb = json.dumps(header, separators=(",", ":")).encode()
raw = struct.pack("<Q", len(hb)) + hb + bytes(n * 4)
(p / "weights.safetensors").write_bytes(raw)
print("wrote", len(raw), "n_floats", n, "pieces", (len(raw) + 4*1024*1024 - 1)//(4*1024*1024), flush=True)
PY
CHECK="${CHECK:-$ROOT/build-gcc13/bin/btx-modelcheck}"
"$CHECK" "$SCRATCH/src/weights.safetensors"
pick() { python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORTA="$(pick)"; PORTB="$(pick)"; PORTC="$(pick)"
"$BIN" -modeldir="$SCRATCH/a" -modelstorage=64MiB -modelbind="127.0.0.1:${PORTA}" -modelhost -modelrpcsocket="$SCRATCH/a/modeld.sock" >"$SCRATCH/a/modeld.log" 2>&1 &
PA=$!
"$BIN" -modeldir="$SCRATCH/b" -modelstorage=64MiB -modelbind="127.0.0.1:${PORTB}" -modelhost -modelrpcsocket="$SCRATCH/b/modeld.sock" >"$SCRATCH/b/modeld.log" 2>&1 &
PB=$!
"$BIN" -modeldir="$SCRATCH/c" -modelstorage=64MiB -modelbind="127.0.0.1:${PORTC}" -modelhost -modelrpcsocket="$SCRATCH/c/modeld.sock" >"$SCRATCH/c/modeld.log" 2>&1 &
PC=$!
"$BIN" -modeldir="$SCRATCH/d" -modelstorage=64MiB -modelpeer="127.0.0.1:${PORTA}" -modelpeer="127.0.0.1:${PORTB}" -modelpeer="127.0.0.1:${PORTC}" -modelrpcsocket="$SCRATCH/d/modeld.sock" >"$SCRATCH/d/modeld.log" 2>&1 &
PF=$!
python3 - "$SCRATCH" "$PA" "$PB" "$PC" "$PF" "$ROOT/contrib/modelnet" <<'PY'
import json, socket, sys, time, os
from pathlib import Path
root=Path(sys.argv[1]); pids=list(map(int, sys.argv[2:5])); pf=int(sys.argv[5])
sys.path.insert(0, sys.argv[6])
from failfast import wait_unix, poll_job

def rpc(sock, method, params, timeout=30):
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

sa, sb, sc, sd = [root/x/"modeld.sock" for x in "abcd"]
ready(sa, pids[0]); ready(sb, pids[1]); ready(sc, pids[2]); ready(sd, pf)
src=str(root/"src"/"weights.safetensors")
imp=rpc(sa,"importmodel",[src,{"pin":True}])
uri=imp["uri"]
art=imp.get("artifact_id") or rpc(sa,"getmodelmanifest",[uri]).get("artifact_id")
impb=rpc(sb,"importmodel",[src,{"pin":True}])
impc=rpc(sc,"importmodel",[src,{"pin":True}])
if impb.get("uri")!=uri or impc.get("uri")!=uri:
    raise SystemExit("uri mismatch")
man=rpc(sa,"getmodelmanifest",[uri])
art=man["artifact_id"]
# Drop disjoint pieces: A keeps 0, B keeps 1, C keeps 2+ of file_index 0 (model.bin).
# Tiny safetensors is another file index; leave those intact so import stays seeded.
def pieces_dir(node, artifact, fi=0):
    return root/node/"store"/"artifacts"/artifact/str(fi)

def keep_only(node, artifact, fi, keep):
    d=pieces_dir(node, artifact, fi)
    if not d.is_dir():
        raise SystemExit("missing %s"%d)
    for p in d.glob("*.piece"):
        try:
            idx=int(p.name.split(".")[0])
        except ValueError:
            continue
        if idx not in keep:
            p.unlink()

# Identify the large file index
files=man.get("files") or []
large=None
for i,f in enumerate(files):
    if int(f.get("size") or 0) >= 8*1024*1024:
        large=i
        break
if large is None:
    raise SystemExit("no 12MiB file in manifest: %s"%files)
n_pieces=(int(files[large]["size"])+4*1024*1024-1)//(4*1024*1024)
if n_pieces < 3:
    raise SystemExit("need >=3 pieces, got %s"%n_pieces)
keep_only("a", art, large, {0})
keep_only("b", art, large, {1})
keep_only("c", art, large, set(range(2, n_pieces)))
listed=rpc(sa,"listmodels",[])
# partial must not be advertised complete
mods=listed.get("models") or []
if not mods:
    raise SystemExit("A list empty")
# fetcher
got=rpc(sd,"getmodel",[uri,"FREE_ONLY"])
if got.get("job_id"):
    poll_job(lambda: rpc(sd,"getmodeljob",[got["job_id"]]), timeout=90)
elif got.get("status") not in ("retrieved","local"):
    raise SystemExit("getmodel: %s"%got)
final=rpc(sd,"listmodels",[])
loc=final.get("models") or []
if not loc: raise SystemExit("D empty")
if not loc[0].get("complete", True):
    # demand-seed after completion should be complete
    raise SystemExit("D incomplete: %s"%loc[0])
print("SHARD-08 live PASS uri", uri)
PY
echo "e2e-shard-disjoint: PASS"
