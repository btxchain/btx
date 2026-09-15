#!/usr/bin/env bash
# V11-RECIP-07/08/10: congested NAT stand-in (delayed loopback proxy).
# STORE-01 resume: keep fetcher datadir and getmodel again after a mid-stream delay.
# Not a public NAT box. Production btxd untouched. CSV stays NOT_RUN.
export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch/nat-congested"
DIR_A="$SCRATCH/a"
DIR_B="$SCRATCH/b"
SOCK_A="$DIR_A/modeld.sock"
SOCK_B="$DIR_B/modeld.sock"
SEEDER_PID=""
FETCHER_PID=""
PROXY_PID=""

die() { printf 'e2e-nat-congested: %s\n' "$*" >&2; exit 1; }
cleanup() {
  local rc=$?
  for p in "${FETCHER_PID:-}" "${SEEDER_PID:-}" "${PROXY_PID:-}"; do
    if [[ -n "$p" ]]; then kill -TERM "$p" 2>/dev/null || true; fi
  done
  sleep 0.3
  for p in "${FETCHER_PID:-}" "${SEEDER_PID:-}" "${PROXY_PID:-}"; do
    if [[ -n "$p" ]]; then kill -KILL "$p" 2>/dev/null || true; fi
  done
  wait 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

[[ -x "$BIN" ]] || die "missing $BIN"
rm -rf "$SCRATCH"
mkdir -p "$DIR_A" "$DIR_B"

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
PROXY_PORT="$(pick_port)"

python3 - <<PY
import struct
from pathlib import Path
src = Path("$DIR_A") / "src"
src.mkdir(parents=True, exist_ok=True)
header = b"{}"
(src / "model.safetensors").write_bytes(struct.pack("<Q", len(header)) + header)
PY

# Delay proxy: 40ms each way, like a congested NAT mapping.
python3 - "$PROXY_PORT" "$SEEDER_PORT" <<'PY' &
import select, socket, sys, time, threading
listen_port, dest_port = int(sys.argv[1]), int(sys.argv[2])
DELAY = 0.040
ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", listen_port))
ls.listen(16)

def pump(src, dst):
    try:
        while True:
            data = src.recv(16384)
            if not data:
                break
            time.sleep(DELAY)
            dst.sendall(data)
    except OSError:
        pass
    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass

def handle(c):
    u = socket.create_connection(("127.0.0.1", dest_port), timeout=10)
    t1 = threading.Thread(target=pump, args=(c, u), daemon=True)
    t2 = threading.Thread(target=pump, args=(u, c), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    c.close(); u.close()

print("NAT proxy 127.0.0.1:%s -> 127.0.0.1:%s delay=40ms" % (listen_port, dest_port), flush=True)
while True:
    c, _ = ls.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
PROXY_PID=$!

"$BIN" -modeldir="$DIR_A" -modelcache=10485760 -modelbind="127.0.0.1:${SEEDER_PORT}" \
  -modelhost -modelrpcsocket="$SOCK_A" >"$DIR_A/modeld.log" 2>&1 &
SEEDER_PID=$!

"$BIN" -modeldir="$DIR_B" -modelcache=10485760 \
  -modelpeer="127.0.0.1:${PROXY_PORT}" \
  -modelrpcsocket="$SOCK_B" >"$DIR_B/modeld.log" 2>&1 &
FETCHER_PID=$!

python3 - "$SOCK_A" "$SOCK_B" "$DIR_A/src" "$SEEDER_PID" "$FETCHER_PID" "$ROOT/contrib/modelnet" <<'PY'
import json, socket, sys, time
from pathlib import Path
sock_a, sock_b, src = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
seeder_pid, fetcher_pid = int(sys.argv[4]), int(sys.argv[5])
sys.path.insert(0, sys.argv[6])
from failfast import poll_job, wait_unix

def rpc(sock, method, params, timeout=120):
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

def retrieve():
    got = rpc(sock_b, "getmodel", [uri, "FREE_ONLY"])
    status = got.get("status")
    job_id = got.get("job_id")
    if status == "running" or got.get("async"):
        job = poll_job(lambda: rpc(sock_b, "getmodeljob", [job_id]), timeout=120)
        return job.get("result") or job
    if status in ("retrieved", "local"):
        return got
    raise SystemExit("getmodel: %s" % got)

first = retrieve()
print("RECIP-07 first", json.dumps(first)[:400])
# STORE-01: second getmodel on same datadir (resume / already local).
second = retrieve()
print("STORE-01 resume", json.dumps(second)[:400])
listed = rpc(sock_b, "listmodels", [])
models = listed.get("models") or []
if not models:
    raise SystemExit("fetcher catalog empty after NAT retrieve")
adm = models[0].get("content_admission") or models[0].get("admission") or models[0].get("bytes_verified")
print("NAT_CONGESTED PASS admission", adm)
PY
