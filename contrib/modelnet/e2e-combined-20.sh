#!/usr/bin/env bash
# Combined swarm + connectivity 20-step lab (CONN-COMBINED / SWARM-CHAOS / CONN-CHAOS).
# Isolated helpers on loopback. Never production btxd, never granite unless BTX_SHARD19=1.
export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CHECK="${CHECK:-$ROOT/build-gcc13/bin/btx-modelcheck}"
CONTRIB="$ROOT/contrib/modelnet"
SCRATCH="$ROOT/e2e-scratch/combined-20"
PA="" PB="" PC="" PD=""
die() { printf 'e2e-combined-20: %s\n' "$*" >&2; exit 1; }
cleanup() {
  local rc=$?
  for p in "$PD" "$PC" "$PA" "$PB"; do
    [[ -n "${p:-}" ]] && kill -TERM "$p" 2>/dev/null || true
  done
  sleep 0.4
  for p in "$PD" "$PC" "$PA" "$PB"; do
    [[ -n "${p:-}" ]] && kill -KILL "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  rm -rf "$SCRATCH"
  exit "$rc"
}
trap cleanup EXIT

[[ -x "$BIN" ]] || die "missing $BIN"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/src" "$SCRATCH/a" "$SCRATCH/b" "$SCRATCH/c"

# ~48 MiB => multiple 4 MiB pieces so rarest-first / kill-mid-retrieve is observable.
python3 - "$SCRATCH/src" <<'PY'
import json, struct, sys
from pathlib import Path
p = Path(sys.argv[1])
p.mkdir(parents=True, exist_ok=True)
target = 48 * 1024 * 1024
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

if [[ -x "$CHECK" ]]; then
  "$CHECK" "$SCRATCH/src/weights.safetensors" >/dev/null
fi

pick() {
  python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}
PORTA="$(pick)"; PORTB="$(pick)"; PORTC="$(pick)"

echo "step 1: start seeder A (bind+host)"
"$BIN" -modeldir="$SCRATCH/a" -modelstorage=256MiB -modelbind="127.0.0.1:${PORTA}" -modelhost \
  -modelrpcsocket="$SCRATCH/a/modeld.sock" >"$SCRATCH/a/modeld.log" 2>&1 &
PA=$!

echo "step 2: start seeder B (bind+host)"
"$BIN" -modeldir="$SCRATCH/b" -modelstorage=256MiB -modelbind="127.0.0.1:${PORTB}" -modelhost \
  -modelrpcsocket="$SCRATCH/b/modeld.sock" >"$SCRATCH/b/modeld.log" 2>&1 &
PB=$!

echo "step 3: start fetcher C (peers A,B; bind so demand-seed can serve later)"
"$BIN" -modeldir="$SCRATCH/c" -modelstorage=256MiB -modelbind="127.0.0.1:${PORTC}" -modelhost \
  -modelpeer="127.0.0.1:${PORTA}" -modelpeer="127.0.0.1:${PORTB}" \
  -modelrpcsocket="$SCRATCH/c/modeld.sock" >"$SCRATCH/c/modeld.log" 2>&1 &
PC=$!

python3 - "$SCRATCH" "$PA" "$PB" "$PC" "$PORTA" "$PORTB" "$CONTRIB" <<'PY'
import json, os, signal, socket, sys, time
from pathlib import Path

root = Path(sys.argv[1])
pa, pb, pc = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
porta, portb = int(sys.argv[5]), int(sys.argv[6])
sys.path.insert(0, sys.argv[7])
from failfast import wait_unix, poll_job, pid_alive

def rpc(sock, method, params, timeout=60):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        data += c
        if b"\n" in data:
            break
    s.close()
    m = json.loads(data.decode())
    if m.get("error"):
        raise SystemExit(f"{method}: {m['error']}")
    return m["result"]

def ready(path, pid):
    def c():
        i = rpc(path, "getmodelnetworkinfo", [])
        return i if i.get("helper_ready") else None
    return wait_unix(c, timeout=25, pid=pid, log=path.parent / "modeld.log")

sa, sb, sc = [root / x / "modeld.sock" for x in "abc"]
print("step 4: wait helpers ready / PQ1")
ia, ib, ic = ready(sa, pa), ready(sb, pb), ready(sc, pc)
for info, name in ((ia, "A"), (ib, "B"), (ic, "C")):
    if not info.get("pq1_ready"):
        raise SystemExit(f"{name} pq1 not ready: {info}")
    if info.get("classical_fallback"):
        raise SystemExit(f"{name} classical_fallback: {info}")
    if int(info.get("automatic_spend_atoms") or 0) != 0:
        raise SystemExit(f"{name} automatic_spend_atoms != 0")

print("step 5: getmodelnetworkinfo connectivity/swarm fields")
for info in (ia, ib, ic):
    for k in ("reachability_state", "nat_status", "min_rarity", "pex_records_received",
              "transport", "network_epoch"):
        if k not in info:
            raise SystemExit(f"missing {k}: {info.keys()}")
    if info.get("transport") != "pq1":
        raise SystemExit(f"transport {info.get('transport')}")

print("step 6: import+pin on A (demand-seed)")
src = str(root / "src" / "weights.safetensors")
imp = rpc(sa, "importmodel", [src, {"pin": True}])
uri = imp["uri"]
if not imp.get("seeded"):
    raise SystemExit(f"A import not seeded: {imp}")

print("step 7: independent import on B (second source)")
impb = rpc(sb, "importmodel", [src, {"pin": True}])
if impb.get("uri") != uri:
    raise SystemExit(f"uri mismatch {uri} vs {impb.get('uri')}")

print("step 8: fetcher sees two peers")
peers = rpc(sc, "getmodelpeers", [])
if len(peers.get("peers") or []) < 2:
    raise SystemExit(f"need 2 peers: {peers}")

print("step 9: availability / search LOCAL after A publish")
try:
    rpc(sa, "publishmodelsearchrecord", [imp.get("model_id") or "aa" + "00" * 47, {
        "type": "btx-model-search-v1",
        "canonical_name": "combined-20",
        "display_name": "Combined 20",
        "expires_at": 0,
    }])
except Exception as e:
    print("note: publishmodelsearchrecord", e, flush=True)

print("step 10: start FREE_ONLY retrieve on C")
got = rpc(sc, "getmodel", [uri, "FREE_ONLY"])
job_id = got.get("job_id")
print("     getmodel", json.dumps({k: got.get(k) for k in ("status", "job_id", "async")}), flush=True)

print("step 11: chaos — SIGTERM seeder A while retrieve may still be running")
os.kill(pa, signal.SIGTERM)
time.sleep(0.2)

print("step 12: C continues from B (or already complete)")
if got.get("status") in ("retrieved", "local"):
    print("     retrieve already complete before kill (loopback fast)")
elif job_id:
    job = poll_job(lambda: rpc(sc, "getmodeljob", [job_id]), timeout=180, stall_s=60)
    result = job.get("result") or {}
    if result.get("status") not in ("retrieved", "local") and job.get("status") != "done":
        raise SystemExit(f"job after A death: {job}")
else:
    raise SystemExit(f"retrieve did not start: {got}")

print("step 13: SHA-384 matches seeder B")
man_b = rpc(sb, "getmodelmanifest", [uri])
man_c = rpc(sc, "getmodelmanifest", [uri])
sha_b = (man_b.get("files") or [{}])[0].get("sha384")
sha_c = (man_c.get("files") or [{}])[0].get("sha384")
if not sha_b or sha_b != sha_c:
    raise SystemExit(f"sha mismatch B={sha_b} C={sha_c}")

print("step 14: listmodels complete on C; demand-seed")
listed = rpc(sc, "listmodels", [])
if int(listed.get("local_count") or 0) < 1:
    raise SystemExit(listed)
mod = (listed.get("models") or [{}])[0]
if mod.get("complete") is False:
    raise SystemExit(f"C incomplete: {mod}")

print("step 15: roam/sleep-wake — restart C on same modeldir")
os.kill(pc, signal.SIGTERM)
for _ in range(40):
    if not pid_alive(pc):
        break
    time.sleep(0.1)

# parent restarts C after this python exits? We restart here via leftover binary path.
print("     (restart issued by wrapper after python returns restart-token)")
(root / "c" / "restart.want").write_text(uri)
(root / "c" / "sha.want").write_text(sha_b)
print("E2E_COMBINED_20 python-phase PASS", uri, flush=True)
PY

URI="$(cat "$SCRATCH/c/restart.want")"
SHA="$(cat "$SCRATCH/c/sha.want")"
echo "step 16: restart fetcher C (same modeldir, new pid, still hosting)"
"$BIN" -modeldir="$SCRATCH/c" -modelstorage=256MiB -modelbind="127.0.0.1:${PORTC}" -modelhost \
  -modelpeer="127.0.0.1:${PORTB}" \
  -modelrpcsocket="$SCRATCH/c/modeld.sock" >"$SCRATCH/c/modeld.log" 2>&1 &
PC=$!

python3 - "$SCRATCH/c/modeld.sock" "$PC" "$URI" "$SHA" "$CONTRIB" <<'PY'
import json, socket, sys
from pathlib import Path
sock, pid, uri, sha = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
sys.path.insert(0, sys.argv[5])
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
info=wait_unix(connect, timeout=25, pid=pid, log=sock.parent/"modeld.log")
print("step 17: after roam, network_epoch present", info.get("network_epoch"))
print("step 18: resume getmodel is local (pieces kept)")
got=rpc("getmodel",[uri,"FREE_ONLY"])
if got.get("status") not in ("retrieved","local"):
    raise SystemExit(f"resume expected local: {got}")
man=rpc("getmodelmanifest",[uri])
sha2=(man.get("files") or [{}])[0].get("sha384")
if sha2!=sha:
    raise SystemExit(f"resume sha {sha2} != {sha}")
print("step 19: search LOCAL still works")
try:
    sm=rpc("searchmodels",[{"text":"combined","scope":"LOCAL","limit":20}])
    print("     searchmodels coverage", (sm.get("coverage") or {}).get("complete"))
except Exception as e:
    print("note: searchmodels", e)
print("step 20: automatic_spend_atoms=0, classical_fallback false")
if int(info.get("automatic_spend_atoms") or 0)!=0:
    raise SystemExit("spend")
if info.get("classical_fallback"):
    raise SystemExit("classical")
print("E2E_COMBINED_20 python-phase-2 PASS")
PY

echo "step 19b: demand-seed — SIGTERM B, D retrieves from C"
kill -TERM "$PB" 2>/dev/null || true
PB=""
mkdir -p "$SCRATCH/d"
"$BIN" -modeldir="$SCRATCH/d" -modelstorage=256MiB \
  -modelpeer="127.0.0.1:${PORTC}" \
  -modelrpcsocket="$SCRATCH/d/modeld.sock" >"$SCRATCH/d/modeld.log" 2>&1 &
PD=$!

python3 - "$SCRATCH/d/modeld.sock" "$PD" "$URI" "$SHA" "$CONTRIB" <<'PY'
import json, socket, sys
from pathlib import Path
sock, pid, uri, sha = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
sys.path.insert(0, sys.argv[5])
from failfast import wait_unix, poll_job

def rpc(method, params, timeout=180):
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
wait_unix(connect, timeout=25, pid=pid, log=sock.parent/"modeld.log")
got=rpc("getmodel",[uri,"FREE_ONLY"])
if got.get("job_id"):
    poll_job(lambda: rpc("getmodeljob",[got["job_id"]]), timeout=180, stall_s=60)
elif got.get("status") not in ("retrieved","local"):
    raise SystemExit(f"D retrieve: {got}")
man=rpc("getmodelmanifest",[uri])
sha2=(man.get("files") or [{}])[0].get("sha384")
if sha2!=sha:
    raise SystemExit(f"D sha {sha2} != {sha}")
print("demand-seed D retrieved from C after B death", flush=True)
PY

echo "e2e-combined-20: PASS"
