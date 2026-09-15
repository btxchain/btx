#!/usr/bin/env bash
# SEARCH-NET-07 slow-peer timeout + SEARCH-NET-12 live PQ1 search fanout.
export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CONTRIB="$ROOT/contrib/modelnet"
SCRATCH="$ROOT/e2e-scratch/search-net"
HANG_PID=""
PIDS=()

die() { printf 'e2e-search-net: %s\n' "$*" >&2; exit 1; }
cleanup() {
  local rc=$?
  for p in "${PIDS[@]:-}"; do kill -TERM "$p" 2>/dev/null || true; done
  [[ -n "${HANG_PID:-}" ]] && kill -TERM "$HANG_PID" 2>/dev/null || true
  sleep 0.2
  for p in "${PIDS[@]:-}"; do kill -KILL "$p" 2>/dev/null || true; done
  [[ -n "${HANG_PID:-}" ]] && kill -KILL "$HANG_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$SCRATCH"
  exit "$rc"
}
trap cleanup EXIT

[[ -x "$BIN" ]] || die "missing $BIN"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/idx" "$SCRATCH/client" "$SCRATCH/hang"

python3 - "$SCRATCH/hang/port" <<'PY' &
import socket, sys, time
from pathlib import Path
out = Path(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(8)
out.write_text(str(s.getsockname()[1]))
while True:
    try:
        c, _ = s.accept()
        time.sleep(60)
        try:
            c.close()
        except Exception:
            pass
    except Exception:
        time.sleep(0.2)
PY
HANG_PID=$!
for i in $(seq 1 50); do
  [[ -s "$SCRATCH/hang/port" ]] && break
  sleep 0.05
done
[[ -s "$SCRATCH/hang/port" ]] || die "hang listener port missing"
PORT_HANG="$(cat "$SCRATCH/hang/port")"

pick() {
  python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}
PORT_IDX="$(pick)"

"$BIN" -modeldir="$SCRATCH/idx" -modelstorage=8MiB -modelbind="127.0.0.1:${PORT_IDX}" \
  -modelrpcsocket="$SCRATCH/idx/modeld.sock" >"$SCRATCH/idx/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$SCRATCH/client" -modelstorage=8MiB \
  -modelrpcsocket="$SCRATCH/client/modeld.sock" >"$SCRATCH/client/modeld.log" 2>&1 &
PIDS+=($!)

python3 - "$SCRATCH" "$PORT_IDX" "$PORT_HANG" "$CONTRIB" "${PIDS[0]}" "${PIDS[1]}" <<'PY'
import json, socket, sys, time
from pathlib import Path
root = Path(sys.argv[1])
port_idx, port_hang = int(sys.argv[2]), int(sys.argv[3])
sys.path.insert(0, sys.argv[4])
from failfast import wait_unix
pid_idx, pid_client = int(sys.argv[5]), int(sys.argv[6])

def rpc(sock, method, params=None, timeout=20):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall((json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params or []})+"\n").encode())
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        c = s.recv(1 << 20)
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

idx = root / "idx" / "modeld.sock"
client = root / "client" / "modeld.sock"
ready(idx, pid_idx)
ready(client, pid_client)

mid = "aa" + "00" * 47
rpc(idx, "publishmodelsearchrecord", [mid, {
    "type": "btx-model-search-v1",
    "canonical_name": "Live Pex Search Target",
    "display_name": "Live Pex Search Target",
    "expires_at": 0,
}])

rpc(client, "addmodelindex", [f"127.0.0.1:{port_idx}"])
t0 = time.time()
sm = rpc(client, "searchmodels", [{"text": "pex search", "scope": "NETWORK", "limit": 20}])
elapsed = time.time() - t0
names = [str(h.get("name") or h.get("display_name") or "") for h in (sm.get("results") or []) if isinstance(h, dict)]
if not any("Live Pex" in n for n in names):
    raise SystemExit(f"SEARCH-NET-12 expected live PQ1 hit, got {names} cov={sm.get('coverage')}")
print("SEARCH-NET-12 PASS live PQ1 hit", names[:3], "elapsed", round(elapsed, 3), flush=True)

rpc(client, "addmodelindex", [f"127.0.0.1:{port_hang}"])
t1 = time.time()
sm2 = rpc(client, "searchmodels", [{"text": "pex search", "scope": "NETWORK", "limit": 20}], timeout=20)
elapsed2 = time.time() - t1
cov = sm2.get("coverage") or {}
if int(cov.get("timed_out") or 0) < 1:
    raise SystemExit(f"SEARCH-NET-07 expected timed_out>=1: {cov} elapsed={elapsed2}")
if elapsed2 > 8:
    raise SystemExit(f"SEARCH-NET-07 hung {elapsed2}s; timeout should be ~1.5s")
print("SEARCH-NET-07 PASS timed_out", cov.get("timed_out"), "elapsed", round(elapsed2, 3), flush=True)
print("E2E_SEARCH_NET PASS")
PY

echo "e2e-search-net: PASS"
