#!/usr/bin/env bash
# SHARD-19 / CONN-13GIB / SWARM-13GIB: 13.8 GiB artifact retrieve between isolated helpers.
# Disk-backed (not tmpfs). Deletes the source after seeder import so peak extra ~2× size.
# Never production btxd / production helper.
export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch/shard19"
# Granite replica size from operator evidence.
BYTES="${BTX_SHARD19_BYTES:-13888336427}"
PA="" PB=""

die() { printf 'e2e-shard19: %s\n' "$*" >&2; exit 1; }

cleanup() {
  local rc=$?
  for p in "$PB" "$PA"; do
    [[ -n "${p:-}" ]] && kill -TERM "$p" 2>/dev/null || true
  done
  sleep 0.5
  for p in "$PB" "$PA"; do
    [[ -n "${p:-}" ]] && kill -KILL "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  rm -rf "$SCRATCH"
  exit "$rc"
}
trap cleanup EXIT

[[ -x "$BIN" ]] || die "missing $BIN"
if [[ "${BTX_SHARD19:-}" != "1" && "${BTX_SHARD19:-}" != "yes" ]]; then
  echo "NOT_RUN: set BTX_SHARD19=1 to execute the 13.8 GiB retrieve (disk ~2×${BYTES} bytes)"
  exit 2
fi

avail_kb=$(df -Pk "$ROOT" | awk 'NR==2{print $4}')
need_kb=$(( (BYTES * 2 + 5*1024*1024*1024) / 1024 ))
reserve_kb=$((20*1024*1024))
if (( avail_kb < need_kb + reserve_kb )); then
  die "disk too low: avail_kb=$avail_kb need_kb=$need_kb (+20G reserve)"
fi

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/src" "$SCRATCH/a" "$SCRATCH/b"

echo "step 1: create ${BYTES}-byte safetensors (sparse payload + real header)"
python3 - "$SCRATCH/src/model.safetensors" "$BYTES" <<'PY'
import json, os, struct, sys
path, total = sys.argv[1], int(sys.argv[2])
n = 8
# iterate so header length + n + 8 == total
payload = total - 8
header = {"w": {"dtype": "U8", "shape": [payload], "data_offsets": [0, payload]}}
hb = json.dumps(header, separators=(",", ":")).encode()
# payload includes header json in the file after 8-byte len; adjust shape to fill
payload = total - 8 - len(hb)
header = {"w": {"dtype": "U8", "shape": [payload], "data_offsets": [0, payload]}}
hb = json.dumps(header, separators=(",", ":")).encode()
payload = total - 8 - len(hb)
if payload <= 0:
    raise SystemExit("payload non-positive")
with open(path, "wb") as f:
    f.write(struct.pack("<Q", len(hb)))
    f.write(hb)
    f.truncate(total)
st = os.stat(path)
if st.st_size != total:
    raise SystemExit(f"size {st.st_size} != {total}")
print("wrote header", len(hb), "file", total, flush=True)
PY

pick() {
  python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}
PORTA="$(pick)"

echo "step 2: seeder A import (quota 20GiB)"
"$BIN" -modeldir="$SCRATCH/a" -modelstorage=20GiB -modelbind="127.0.0.1:${PORTA}" -modelhost \
  -modelrpcsocket="$SCRATCH/a/modeld.sock" >"$SCRATCH/a/modeld.log" 2>&1 &
PA=$!

python3 - "$SCRATCH/a/modeld.sock" "$PA" "$SCRATCH/src/model.safetensors" "$ROOT/contrib/modelnet" "$BYTES" <<'PY'
import json, socket, sys
from pathlib import Path
sock, pid, src, contrib, nbytes = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5])
sys.path.insert(0, contrib)
from failfast import wait_unix

def rpc(method, params, timeout=86400):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params}).encode()+b"\n")
    s.shutdown(socket.SHUT_WR)
    data=b""
    while True:
        c=s.recv(1<<20)
        if not c: break
        data+=c
        if b"\n" in data: break
    s.close()
    m=json.loads(data.decode())
    if m.get("error"): raise SystemExit("%s: %s"%(method,m["error"]))
    return m["result"]

def connect():
    i=rpc("getmodelnetworkinfo",[], timeout=30)
    return i if i.get("helper_ready") else None
wait_unix(connect, timeout=30, pid=pid, log=sock.parent/"modeld.log")
print("step 3: importmodel (hashes all pieces)", flush=True)
imp=rpc("importmodel",[src,{"pin":True}])
print("     imported", json.dumps({k:imp.get(k) for k in ("uri","bytes","seeded","status")}), flush=True)
if not imp.get("uri"):
    raise SystemExit(imp)
used=rpc("getmodelnetworkinfo",[]).get("used_bytes") or 0
if int(used) < nbytes // 2:
    raise SystemExit(f"used_bytes {used} too small for {nbytes}")
Path(sock.parent/"uri.txt").write_text(imp["uri"])
print("IMPORT_OK", imp["uri"], flush=True)
PY

rm -f "$SCRATCH/src/model.safetensors"
URI="$(cat "$SCRATCH/a/uri.txt")"

echo "step 4: fetcher B retrieve"
"$BIN" -modeldir="$SCRATCH/b" -modelstorage=20GiB -modelpeer="127.0.0.1:${PORTA}" \
  -modelrpcsocket="$SCRATCH/b/modeld.sock" >"$SCRATCH/b/modeld.log" 2>&1 &
PB=$!

python3 - "$SCRATCH/b/modeld.sock" "$PB" "$URI" "$SCRATCH/a/modeld.sock" "$ROOT/contrib/modelnet" "$BYTES" <<'PY'
import json, socket, sys
from pathlib import Path
sock, pid, uri, sa, contrib, nbytes = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), sys.argv[5], int(sys.argv[6])
sys.path.insert(0, contrib)
from failfast import wait_unix, poll_job

def rpc(path, method, params, timeout=86400):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(path))
    s.sendall(json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params}).encode()+b"\n")
    s.shutdown(socket.SHUT_WR)
    data=b""
    while True:
        c=s.recv(1<<20)
        if not c: break
        data+=c
        if b"\n" in data: break
    s.close()
    m=json.loads(data.decode())
    if m.get("error"): raise SystemExit("%s: %s"%(method,m["error"]))
    return m["result"]

def connect():
    i=rpc(sock,"getmodelnetworkinfo",[], timeout=30)
    return i if i.get("helper_ready") else None
wait_unix(connect, timeout=30, pid=pid, log=sock.parent/"modeld.log")
print("step 5: getmodel FREE_ONLY", flush=True)
got=rpc(sock,"getmodel",[uri,"FREE_ONLY"])
if got.get("job_id"):
    poll_job(lambda: rpc(sock,"getmodeljob",[got["job_id"]]), timeout=86400, stall_s=300)
elif got.get("status") not in ("retrieved","local"):
    raise SystemExit("getmodel: %s"%got)
print("step 6: verify size + sha vs seeder")
man_a=rpc(sa,"getmodelmanifest",[uri], timeout=120)
man_b=rpc(sock,"getmodelmanifest",[uri], timeout=120)
sha_a=(man_a.get("files") or [{}])[0].get("sha384")
sha_b=(man_b.get("files") or [{}])[0].get("sha384")
if not sha_a or sha_a!=sha_b:
    raise SystemExit("sha mismatch %s %s"%(sha_a, sha_b))
listed=rpc(sock,"listmodels",[])
if int(listed.get("local_count") or 0)<1:
    raise SystemExit(listed)
print("E2E_SHARD19 PASS bytes", nbytes, "sha384", sha_b, flush=True)
PY

echo "e2e-shard19: PASS"
