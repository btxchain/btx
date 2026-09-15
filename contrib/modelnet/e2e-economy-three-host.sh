#!/usr/bin/env bash
# ECON three-host: A creator, B index, C fresh. No model URI copied to C.
# Topology: A -- B -- C  (C never talks to A).
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CONTRIB="$ROOT/contrib/modelnet"
BASE="/tmp/btx-econ-3h-$$"
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
mkdir -p "$BASE/a" "$BASE/b" "$BASE/c"
pick() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORT_A="$(pick)"
PORT_B="$(pick)"
"$BIN" -modeldir="$BASE/a" -modelstorage=8MiB -modelbind="127.0.0.1:${PORT_A}" \
  -modelrpcsocket="$BASE/a/modeld.sock" >"$BASE/a/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$BASE/b" -modelstorage=8MiB -modelbind="127.0.0.1:${PORT_B}" \
  -modelrpcsocket="$BASE/b/modeld.sock" >"$BASE/b/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$BASE/c" -modelstorage=8MiB \
  -modelrpcsocket="$BASE/c/modeld.sock" >"$BASE/c/modeld.log" 2>&1 &
PIDS+=($!)
python3 - "$BASE" "$PORT_A" "$PORT_B" "$CONTRIB" "${PIDS[0]}" "${PIDS[1]}" "${PIDS[2]}" <<'PY'
import json, socket, sys
from pathlib import Path
base=Path(sys.argv[1]); port_a=int(sys.argv[2]); port_b=int(sys.argv[3])
sys.path.insert(0, sys.argv[4])
from failfast import wait_unix
pid_a, pid_b, pid_c = int(sys.argv[5]), int(sys.argv[6]), int(sys.argv[7])

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

wait("a", pid_a); wait("b", pid_b); wait("c", pid_c)
a=base/"a"/"modeld.sock"; b=base/"b"/"modeld.sock"; c=base/"c"/"modeld.sock"

def mid(tag):
    return f"{tag:02x}"+"00"*47

rpc(a,"publishmodelsearchrecord",[mid(0x50), {
    "type":"btx-model-search-v1",
    "canonical_name":"PublicCoder",
    "display_name":"PublicCoder",
    "short_description":"specialized coding agent model",
    "expires_at":0,
}])
rpc(a,"publishmodelsearchrecord",[mid(0x52), {
    "type":"btx-model-search-v1",
    "canonical_name":"ResearchCoder70B",
    "display_name":"ResearchCoder70B",
    "short_description":"advanced repository maintenance and autonomous coding model",
    "release_id":"cc"*48,
    "release_state":"FUNDING",
    "release_target_atoms": 50000000000,
    "key_hash": "ab"+"00"*31,
    "refund_height": 200,
    "expires_at":0,
}])

# B learns from A (index), C only knows B.
rpc(b,"addmodelindex",[f"127.0.0.1:{port_a}"])
rpc(b,"addmodelnode",[f"127.0.0.1:{port_a}"])
learned=rpc(b,"searchmodels",[{"text":"coding","scope":"NETWORK"}])
if not (learned.get("results") or []):
    raise SystemExit(f"B did not learn from A: {learned}")

rpc(c,"addmodelindex",[f"127.0.0.1:{port_b}"])
rpc(c,"addmodelnode",[f"127.0.0.1:{port_b}"])

feed=rpc(c,"getmodelfeed",[{"scope":"NETWORK","mode":"NEWEST","limit":50}])
sm1=rpc(c,"searchmodels",[{"text":"coding agent","scope":"NETWORK"}])
n1=[str(h.get("name") or "") for h in (sm1.get("results") or [])]
if "PublicCoder" not in n1:
    raise SystemExit(f"C coding agent miss (no URI was given): {n1} feed={feed}")
sm2=rpc(c,"searchmodels",[{"text":"repository maintenance","scope":"NETWORK"}])
n2=[str(h.get("name") or "") for h in (sm2.get("results") or [])]
if "ResearchCoder70B" not in n2:
    raise SystemExit(f"C campaign description miss: {n2}")
camp=next(h for h in (sm2.get("results") or []) if h.get("name")=="ResearchCoder70B")
rel=camp.get("release") or {}
if rel.get("hashlock_algorithm")!="SHA256":
    raise SystemExit(f"hashlock {rel}")
if rel.get("target_atoms") != 50000000000:
    raise SystemExit(f"target {rel}")
print("ECON-FEED-02 three-host NEWEST/search PASS", n1, n2, flush=True)

# Stop B. C must still have cached directory.
import os, signal, time
os.kill(pid_b, signal.SIGTERM)
for _ in range(50):
    try:
        os.kill(pid_b, 0)
        time.sleep(0.05)
    except ProcessLookupError:
        break
loc=rpc(c,"searchmodels",[{"text":"coding agent","scope":"LOCAL"}])
if not (loc.get("results") or []):
    raise SystemExit(f"C cache empty after B down: {loc}")
print("ECON three-host cache after index loss PASS", flush=True)
print("E2E_ECONOMY_THREE_HOST PASS", flush=True)
PY
echo "e2e-economy-three-host: PASS"
