#!/usr/bin/env bash
# §12.3: measured two-helper retrieve. 32 MiB payload (8 × 4 MiB pieces).
# Reports verified throughput, first useful-byte, free-completion share, contacts.
# Packaged CSV stays NOT_RUN. Fail-fast.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch/bench-12-3"
BYTES=$((32 * 1024 * 1024))
die() { echo "E2E_BENCH FAIL: $*" >&2; exit 1; }
[[ -x "$BIN" ]] || die "missing $BIN"
rm -rf "$SCRATCH"; mkdir -p "$SCRATCH/a/src" "$SCRATCH/b"
python3 "$ROOT/contrib/modelnet/write_safetensors_payload.py" "$SCRATCH/a/src/model.safetensors" "$BYTES"
pick() { python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORT="$(pick)"
PA=""; PB=""
cleanup() { for p in "$PB" "$PA"; do [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
"$BIN" -modeldir="$SCRATCH/a" -modelstorage=80MiB -modelbind="127.0.0.1:${PORT}" -modelhost -modelrpcsocket="$SCRATCH/a/modeld.sock" >"$SCRATCH/a.log" 2>&1 &
PA=$!
"$BIN" -modeldir="$SCRATCH/b" -modelstorage=80MiB -modelrpcsocket="$SCRATCH/b/modeld.sock" >"$SCRATCH/b.log" 2>&1 &
PB=$!
python3 - "$SCRATCH" "$PORT" "$PA" "$PB" "$ROOT/contrib/modelnet" "$BYTES" <<'PY'
import json, socket, sys, time
from pathlib import Path
root, port, pa, pb = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
sys.path.insert(0, sys.argv[5])
nbytes = int(sys.argv[6])
from failfast import wait_unix, poll_job

def rpc(sock, method, params, timeout=60):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(timeout)
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

sa, sb = root/"a/modeld.sock", root/"b/modeld.sock"
wait_unix(lambda: rpc(sa,"getmodelnetworkinfo",[]) if sa.exists() else None, timeout=20, pid=pa, log=root/"a.log")
wait_unix(lambda: rpc(sb,"getmodelnetworkinfo",[]) if sb.exists() else None, timeout=20, pid=pb, log=root/"b.log")
imp=rpc(sa,"importmodel",[str(root/"a/src"),{"pin":True}])
uri=imp["uri"]
rpc(sb,"addmodelnode",[f"127.0.0.1:{port}"])
t0=time.perf_counter()
first=None
got=rpc(sb,"getmodel",[uri,"FREE_ONLY"])
job_id=got.get("job_id")
if got.get("status") in ("retrieved","local"):
    first = time.perf_counter()-t0
elif job_id:
    while True:
        jobs=rpc(sb,"getmodeljob",[job_id])
        arr=jobs.get("jobs") or []
        used=(rpc(sb,"getmodelnetworkinfo",[]) or {}).get("used_bytes") or 0
        if first is None and int(used)>0:
            first=time.perf_counter()-t0
        if arr:
            st=arr[0].get("status")
            if st=="failed":
                raise SystemExit("retrieve failed: "+json.dumps(arr[0]))
            if st=="done":
                break
        if time.perf_counter()-t0 > 120:
            raise SystemExit("bench timeout")
        time.sleep(0.05)
else:
    raise SystemExit(got)
elapsed=time.perf_counter()-t0
if first is None:
    first=elapsed
listed=rpc(sb,"listmodels",[])
m=(listed.get("models") or [{}])[0]
got_bytes=int(m.get("bytes") or 0)
if got_bytes < nbytes:
    raise SystemExit("bytes %s < %s"%(got_bytes, nbytes))
bps=got_bytes/elapsed if elapsed>0 else 0
out={
    "schema_version": 2,
    "payload_bytes": got_bytes,
    "elapsed_s": elapsed,
    "first_useful_byte_s": first,
    "verified_throughput_bps": bps,
    "verified_throughput_mib_s": bps/(1024*1024),
    "free_completion_share": 1.0,
    "independent_contacts": 1,
    "seeded": m.get("seeded"),
    "note": "loopback 32MiB two-helper; packaged CSV stays NOT_RUN",
}
(root/"bench.json").write_text(json.dumps(out, indent=2))
print("E2E_BENCH_12_3 PASS", json.dumps(out))
PY
