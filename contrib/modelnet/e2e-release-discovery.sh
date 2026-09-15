#!/usr/bin/env bash
# ECON-RELEASE-01: searchable unreleased campaign without plaintext on the searcher.
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CONTRIB="$ROOT/contrib/modelnet"
BASE="/tmp/btx-econ-rel-$$"
PIDS=()
cleanup() {
  local rc=$?
  for p in "${PIDS[@]:-}"; do kill -TERM "$p" 2>/dev/null || true; done
  sleep 0.2
  for p in "${PIDS[@]:-}"; do kill -KILL "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$BASE"
  exit "$rc"
}
trap cleanup EXIT
[[ -x "$BIN" ]] || { echo "NOT_RUN: missing $BIN" >&2; exit 2; }
rm -rf "$BASE"
mkdir -p "$BASE/a" "$BASE/c" "$BASE/src"
python3 - "$BASE/src/weights.safetensors" <<'PY'
import json, struct, sys
from pathlib import Path
p=Path(sys.argv[1]); n=64
header={"w":{"dtype":"F32","shape":[n],"data_offsets":[0,n*4]}}
hb=json.dumps(header,separators=(",",":")).encode()
p.write_bytes(struct.pack("<Q",len(hb))+hb+bytes(n*4))
PY
pick() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORT="$(pick)"
"$BIN" -modeldir="$BASE/a" -modelstorage=8MiB -modelbind="127.0.0.1:${PORT}" \
  -modelrpcsocket="$BASE/a/modeld.sock" >"$BASE/a/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$BASE/c" -modelstorage=8MiB \
  -modelrpcsocket="$BASE/c/modeld.sock" >"$BASE/c/modeld.log" 2>&1 &
PIDS+=($!)
python3 - "$BASE" "$PORT" "$CONTRIB" "${PIDS[0]}" "${PIDS[1]}" <<'PY'
import json, socket, sys
from pathlib import Path
base=Path(sys.argv[1]); port=int(sys.argv[2])
sys.path.insert(0, sys.argv[3])
from failfast import wait_unix
pid_a, pid_c = int(sys.argv[4]), int(sys.argv[5])

def rpc(sock, method, params=None, timeout=40):
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

def wait(name, pid):
    sock=base/name/"modeld.sock"
    def connect():
        i=rpc(sock,"getmodelnetworkinfo",[])
        return i if i.get("helper_ready") else None
    wait_unix(connect, timeout=20, pid=pid, log=base/name/"modeld.log")

wait("a", pid_a); wait("c", pid_c)
a=base/"a"/"modeld.sock"; c=base/"c"/"modeld.sock"
imp=rpc(a,"importmodel",[str(base/"src"/"weights.safetensors"),{"pin":True}])
uri=imp["uri"]; mid=imp["model_id"]
rel=rpc(a,"createmodelrelease",[uri,"11"*32, 100, 50000000000, {
    "publish_search_record": True,
    "display_name":"Unreleased Coder",
    "short_description":"advanced repository maintenance and autonomous coding model",
}])
rid=rel.get("release_id") or rel.get("id")
if not rid: raise SystemExit(f"createmodelrelease {rel}")
econ=rpc(a,"getmodeleconomyentry",[mid if isinstance(mid,str) else mid])
# mid from import may be hex
econ=rpc(a,"getmodelreleaseeconomics",[rid])
if econ.get("hashlock_algorithm")!="SHA256":
    raise SystemExit(f"ECON-FUND-03 hashlock {econ}")
if econ.get("assurance")!="KEY_RELEASE_ONLY":
    raise SystemExit(f"assurance {econ}")
if "secret" in econ:
    raise SystemExit("secret leaked")
print("ECON-FUND-03 PASS", flush=True)

rpc(c,"addmodelindex",[f"127.0.0.1:{port}"])
rpc(c,"addmodelnode",[f"127.0.0.1:{port}"])
sm=rpc(c,"searchmodels",[{"text":"repository maintenance","scope":"NETWORK"}])
hits=sm.get("results") or []
if not any("Unreleased" in str(h.get("name") or "") for h in hits):
    raise SystemExit(f"ECON-RELEASE-01 miss {sm}")
card=next(h for h in hits if "Unreleased" in str(h.get("name") or ""))
if card.get("downloadable_now") is True:
    raise SystemExit(f"plaintext should be false {card}")
if card.get("fundable_now") is not True:
    raise SystemExit(f"fundable_now {card}")
feed=rpc(c,"getmodelfeed",[{"scope":"NETWORK","mode":"NEW_RELEASE_CAMPAIGNS","limit":50}])
print("ECON-FEED-03 campaigns", len(feed.get("items") or []), flush=True)
cache=rpc(c,"cacheencryptedmodel",[rid])
if cache.get("plaintext_unavailable") is not True:
    raise SystemExit(f"ECON-CACHE-01 {cache}")
if cache.get("automatic_download") is not False:
    raise SystemExit(f"auto download {cache}")
print("ECON-CACHE-01 PASS", flush=True)
print("ECON-RELEASE-01 PASS", flush=True)
print("E2E_RELEASE_DISCOVERY PASS", flush=True)
PY
echo "e2e-release-discovery: PASS"
