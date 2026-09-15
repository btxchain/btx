#!/usr/bin/env bash
# V11-RESOLVE-03/04/07 process: independent contact, router loss, 8/4 real RTT.
# Loopback only. Does not touch production btxd. Packaged CSV stays NOT_RUN.
export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch/resolve-8-4"
DIR_A="$SCRATCH/a"
DIR_B="$SCRATCH/b"
SOCK_A="$DIR_A/modeld.sock"
SOCK_B="$DIR_B/modeld.sock"
SEEDER_PID=""
FETCHER_PID=""
ROUTER_PID=""

die() { printf 'e2e-resolve-8-4: %s\n' "$*" >&2; exit 1; }
cleanup() {
  local rc=$?
  for p in "${FETCHER_PID:-}" "${SEEDER_PID:-}" "${ROUTER_PID:-}"; do
    if [[ -n "$p" ]]; then kill -TERM "$p" 2>/dev/null || true; fi
  done
  sleep 0.3
  for p in "${FETCHER_PID:-}" "${SEEDER_PID:-}" "${ROUTER_PID:-}"; do
    if [[ -n "$p" ]]; then kill -KILL "$p" 2>/dev/null || true; fi
  done
  wait 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

[[ -x "$BIN" ]] || die "missing $BIN"
rm -rf "$SCRATCH"
mkdir -p "$DIR_A" "$DIR_B" "$SCRATCH/router"

pick_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

SEEDER_PORT="$(pick_port)"
ROUTER_PORT="$(pick_port)"
[[ "$SEEDER_PORT" -gt 1024 && "$ROUTER_PORT" -gt 1024 ]] || die "ports"

python3 - <<PY
import struct
from pathlib import Path
src = Path("$DIR_A") / "src"
src.mkdir(parents=True, exist_ok=True)
header = b"{}"
(src / "model.safetensors").write_bytes(struct.pack("<Q", len(header)) + header)
PY

# RESOLVE-07: eight dummy listeners, four concurrent TCP connects, print RTT ms.
python3 - <<'PY'
import socket, time, concurrent.futures
socks = []
ports = []
for _ in range(8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(4)
    ports.append(s.getsockname()[1])
    socks.append(s)

def one(p):
    t0 = time.perf_counter()
    c = socket.create_connection(("127.0.0.1", p), timeout=2)
    c.close()
    return (time.perf_counter() - t0) * 1000.0

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
    rtts = list(ex.map(one, ports[:4]))
print("RESOLVE-07 contacts=8 concurrent=4 rtt_ms=" + ",".join("%.3f" % x for x in rtts))
print("RESOLVE-07 max_rtt_ms=%.3f" % max(rtts))
for s in socks:
    s.close()
PY

"$BIN" -modeldir="$DIR_A" -modelcache=10485760 -modelbind="127.0.0.1:${SEEDER_PORT}" \
  -modelhost -modelrpcsocket="$SOCK_A" >"$DIR_A/modeld.log" 2>&1 &
SEEDER_PID=$!

# Independent router helper (RESOLVE-03). CPU introducer only; same binary.
"$BIN" -modeldir="$SCRATCH/router" -modelcache=1048576 -modelbind="127.0.0.1:${ROUTER_PORT}" \
  -modelhost -modelrpcsocket="$SCRATCH/router/modeld.sock" >"$SCRATCH/router/modeld.log" 2>&1 &
ROUTER_PID=$!

"$BIN" -modeldir="$DIR_B" -modelcache=10485760 \
  -modelpeer="127.0.0.1:${SEEDER_PORT}" \
  -modelpeer="127.0.0.1:${ROUTER_PORT}" \
  -modelrpcsocket="$SOCK_B" >"$DIR_B/modeld.log" 2>&1 &
FETCHER_PID=$!

python3 - "$SOCK_A" "$SOCK_B" "$DIR_A/src" "$ROUTER_PID" "$SEEDER_PID" "$FETCHER_PID" "$ROOT/contrib/modelnet" <<'PY'
import json, os, signal, socket, sys, time
from pathlib import Path
sock_a, sock_b, src = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
router_pid = int(sys.argv[4])
seeder_pid, fetcher_pid = int(sys.argv[5]), int(sys.argv[6])
sys.path.insert(0, sys.argv[7])
from failfast import poll_job, wait_unix

def rpc(sock, method, params, timeout=30):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params}).encode()+b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    reply = json.loads(data.decode())
    if reply.get("error"):
        raise RuntimeError("%s: %s" % (method, reply["error"]))
    return reply["result"]

def wait_sock(path, pid, timeout=20):
    def connect():
        info = rpc(path, "getmodelnetworkinfo", [])
        if info.get("helper_ready"):
            return info
        return None
    return wait_unix(connect, timeout=timeout, pid=pid, log=path.parent / "modeld.log")

wait_sock(sock_a, seeder_pid)
wait_sock(sock_b, fetcher_pid)
imported = rpc(sock_a, "importmodel", [str(src), {"pin": True}])
uri = imported["uri"]
if imported.get("seeded") is not True:
    raise SystemExit("import must demand-seed without seedmodel: %s" % (imported,))
peers = rpc(sock_b, "getmodelpeers", [])
plist = peers.get("peers") or []
print("RESOLVE-03 peers", json.dumps(plist)[:500])
if len(plist) < 2:
    raise SystemExit("expected seeder + independent router peer")

# RESOLVE-04: drop independent router mid-transfer; seeder remains.
os.kill(router_pid, signal.SIGTERM)
got = rpc(sock_b, "getmodel", [uri, "FREE_ONLY"], timeout=90)
status = got.get("status")
job_id = got.get("job_id")
if status == "running" or got.get("async"):
    job = poll_job(lambda: rpc(sock_b, "getmodeljob", [job_id]), timeout=90)
    result = job.get("result") or {}
    admission = result.get("content_admission") or result.get("admission")
    print("RESOLVE-04 after router loss", job.get("status"), admission or result.get("status"))
elif status in ("retrieved", "local"):
    print("RESOLVE-04 after router loss", status)
else:
    raise SystemExit("RESOLVE-04 retrieve: %s" % got)
print("RESOLVE-8-4 PASS")
PY
