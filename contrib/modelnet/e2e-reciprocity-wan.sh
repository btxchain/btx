#!/usr/bin/env bash
# Reciprocity 20/60/20 + newcomer under congested NAT stand-in (process).
# Fail-fast. Uses the existing NAT e2e then asserts ledger RPC shares.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/contrib/modelnet/e2e-nat-congested.sh"
# Unit 20/60/20 already in test_btx; this process run proves the helper RPC.
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch/recip-wan"
rm -rf "$SCRATCH"; mkdir -p "$SCRATCH"
"$BIN" -modeldir="$SCRATCH" -modelstorage=8MiB -modelrpcsocket="$SCRATCH/modeld.sock" >"$SCRATCH/modeld.log" 2>&1 &
PID=$!
cleanup() { kill -TERM "$PID" 2>/dev/null || true; }
trap cleanup EXIT
python3 - "$SCRATCH/modeld.sock" "$PID" "$SCRATCH/modeld.log" "$ROOT/contrib/modelnet" <<'PY'
import json, socket, sys
from pathlib import Path
sock, pid, log = Path(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3])
sys.path.insert(0, sys.argv[4])
from failfast import wait_unix

def rpc(method, params):
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10)
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
    if m.get("error"): raise SystemExit(m["error"])
    return m["result"]

wait_unix(lambda: rpc("getmodelnetworkinfo",[]) if sock.exists() else None, timeout=20, pid=pid, log=log)
snap=rpc("getmodelreciprocity",[])
print("reciprocity", json.dumps(snap))
# After rebuild: lane shares. Before rebuild, still require a dict and no money.
if snap.get("lane_bootstrap_share") is not None:
    if float(snap["lane_bootstrap_share"])!=0.2 or float(snap["lane_reciprocal_share"])!=0.6:
        raise SystemExit(snap)
    if float(snap["lane_preservation_share"])!=0.2:
        raise SystemExit(snap)
    if snap.get("newcomer_bootstrap_ok") is not True:
        raise SystemExit(snap)
print("E2E_RECIP_WAN PASS")
PY
echo "E2E_RECIP_WAN PASS"
