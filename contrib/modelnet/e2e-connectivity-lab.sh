#!/usr/bin/env bash
# Isolated connectivity lab. Loopback always. Namespace NAT only with CAP_NET_ADMIN.
# No production btxd, no public IPs, no granite unless BTX_SHARD19=1.
export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch/connectivity-lab"
mkdir -p "$SCRATCH"
LOG="$SCRATCH/lab.log"
: >"$LOG"

die() { printf 'e2e-connectivity-lab: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*" | tee -a "$LOG"; }

[[ -x "$BIN" ]] || die "missing $BIN"

rpc() {
  local sock="$1" method="$2" params="${3:-[]}"
  python3 - "$sock" "$method" "$params" <<'PY'
import json, socket, sys
sock, method, params = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
req = json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params}) + "\n"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock)
s.sendall(req.encode())
s.shutdown(socket.SHUT_WR)
print(s.recv(1 << 20).decode())
PY
}

# --- A. loopback PUBLIC stand-in (two helpers, direct PQ1 path exists) ---
DIR_A="$SCRATCH/a"
DIR_B="$SCRATCH/b"
rm -rf "$DIR_A" "$DIR_B"
mkdir -p "$DIR_A" "$DIR_B"
PORT="$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
)"
"$BIN" -modeldir="$DIR_A" -modelrpcsocket="$DIR_A/modeld.sock" -modelbind="127.0.0.1:$PORT" \
  -modelcache=10485760 >"$DIR_A/modeld.log" 2>&1 &
PID_A=$!
for i in $(seq 1 50); do
  [[ -S "$DIR_A/modeld.sock" ]] && break
  sleep 0.1
done
[[ -S "$DIR_A/modeld.sock" ]] || die "helper A socket missing"
INFO="$(rpc "$DIR_A/modeld.sock" getmodelnetworkinfo)"
echo "$INFO" | python3 -c 'import json,sys; o=json.load(sys.stdin); r=o.get("result",o);
assert "reachability_state" in r, r
assert r.get("classical_fallback") is False or r.get("classical_fallback") is None
print("A reachability_state", r.get("reachability_state"))'
kill -TERM "$PID_A" 2>/dev/null || true
wait "$PID_A" 2>/dev/null || true
note "A loopback helper: getmodelnetworkinfo exposes reachability_state (listen != PUBLIC)"

# --- H. IPv6 loopback (::1) listen + retrieve (no netns required) ---
DIR_H1="$SCRATCH/h1"
DIR_H2="$SCRATCH/h2"
rm -rf "$DIR_H1" "$DIR_H2"
mkdir -p "$DIR_H1" "$DIR_H2" "$SCRATCH/hsrc"
python3 - "$SCRATCH/hsrc/weights.safetensors" <<'PY'
import json, struct, sys
from pathlib import Path
p = Path(sys.argv[1])
n = 32
header = {"w": {"dtype": "F32", "shape": [n], "data_offsets": [0, n * 4]}}
hb = json.dumps(header, separators=(",", ":")).encode()
p.write_bytes(struct.pack("<Q", len(hb)) + hb + bytes(n * 4))
PY
PORTH="$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::1", 0))
print(s.getsockname()[1]); s.close()
PY
)"
"$BIN" -modeldir="$DIR_H1" -modelrpcsocket="$DIR_H1/modeld.sock" -modelbind="[::1]:$PORTH" -modelhost \
  -modelstorage=8MiB >"$DIR_H1/modeld.log" 2>&1 &
PID_H1=$!
"$BIN" -modeldir="$DIR_H2" -modelrpcsocket="$DIR_H2/modeld.sock" -modelpeer="[::1]:$PORTH" \
  -modelstorage=8MiB >"$DIR_H2/modeld.log" 2>&1 &
PID_H2=$!
python3 - "$DIR_H1/modeld.sock" "$DIR_H2/modeld.sock" "$PID_H1" "$PID_H2" "$SCRATCH/hsrc/weights.safetensors" "$ROOT/contrib/modelnet" <<'PY'
import json, socket, sys
from pathlib import Path
sa, sb, pa, pb, src = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
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
ia=ready(sa, pa); ib=ready(sb, pb)
if not ia.get("pq1_ready") or not ib.get("pq1_ready"):
    raise SystemExit("H pq1 not ready")
imp=rpc(sa,"importmodel",[src,{"pin":True}])
got=rpc(sb,"getmodel",[imp["uri"],"FREE_ONLY"])
if got.get("job_id"):
    poll_job(lambda: rpc(sb,"getmodeljob",[got["job_id"]]), timeout=60, stall_s=30)
elif got.get("status") not in ("retrieved","local"):
    raise SystemExit("H retrieve %s"%got)
print("H IPv6 ::1 retrieve ok", flush=True)
PY
kill -TERM "$PID_H1" "$PID_H2" 2>/dev/null || true
wait "$PID_H1" "$PID_H2" 2>/dev/null || true
note "H IPv6 loopback [::1] listen+retrieve PASS"

# --- G. roam is executed by e2e-combined-20.sh (restart fetcher, pieces kept) ---
note "G roam: see contrib/modelnet/e2e-combined-20.sh (restart same modeldir)"

# --- B–F userspace NAT/relay (no netns / no sudo) ---
MODELD="$BIN" TEST_BTX="${TEST_BTX:-$ROOT/build-gcc13/bin/test_btx}" \
  "$ROOT/contrib/modelnet/e2e-connectivity-nat.sh" || die "userspace NAT lab B-F"
note "B-F userspace relay topologies PASS"

if ip netns add btx-conn-probe 2>/dev/null; then
  ip netns delete btx-conn-probe 2>/dev/null || true
  note "netns also available; nft cone/restricted matrix is optional extra"
else
  note "netns not permitted; userspace B-F already executed"
fi
echo "e2e-connectivity-lab: PASS"
