#!/usr/bin/env bash
# Two-helper WAN retrieve. Does not touch production btxd.
#
# Usage:
#   SEEDER=host:29447 contrib/modelnet/e2e-wan-two-helper.sh
#
# Default: skip unless BTX_WAN_E2E=1. Loopback two-helper remains e2e-two-helper-pq1.sh.
# Never SIGKILL production btxd. Never preserve_rare on the signer.
set -euo pipefail
export LC_ALL=C
if [[ "${BTX_WAN_E2E:-0}" != "1" ]]; then
  echo "e2e-wan-two-helper: skip (set BTX_WAN_E2E=1 SEEDER=host:port)"
  exit 0
fi
SEEDER="${SEEDER:?set SEEDER=host:port of a non-production helper}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CLI="${CLI:-$ROOT/build-gcc13/bin/btx-cli}"
SCRATCH="${WAN_SCRATCH:-$ROOT/e2e-scratch/wan}"
mkdir -p "$SCRATCH"
cleanup() {
  if [[ -n "${PID:-}" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  # Keep scratch on failure so STORE-01 can resume. Success path may leave it too.
}
trap cleanup EXIT
SOCK="$SCRATCH/modeld.sock"
"$BIN" -modeldir="$SCRATCH" -modelstorage=20GiB -modelrpcsocket="$SOCK" \
  -modelpeer="$SEEDER" >"$SCRATCH/modeld.log" 2>&1 &
PID=$!
for i in $(seq 1 50); do
  if ! kill -0 "$PID" 2>/dev/null; then
    tail -n 40 "$SCRATCH/modeld.log" >&2 || true
    echo "e2e-wan-two-helper: helper died before socket" >&2
    exit 1
  fi
  [[ -S "$SOCK" ]] && break
  sleep 0.2
done
if [[ ! -S "$SOCK" ]]; then
  tail -n 40 "$SCRATCH/modeld.log" >&2 || true
  echo "e2e-wan-two-helper: socket not ready" >&2
  exit 1
fi
URI="${URI:-btx://pqc0whmrlv2emtc8eknxja6l6ffdj5mta0nj9msfsdkrz6qg0de448gm0a3kcctd92p9ekje2c97wd5glyrdl}"
WAN_TIMEOUT_S="${WAN_TIMEOUT_S:-7200}"
python3 - <<PY
import json, socket, sys, time
sock = "$SOCK"
uri = "$URI"
timeout = float("$WAN_TIMEOUT_S")
def rpc(method, params):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(600)
    s.connect(sock)
    s.sendall((json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params})+"\n").encode())
    buf = b""
    while True:
        c = s.recv(1 << 20)
        if not c: break
        buf += c
        if b"\n" in buf: break
    msg = json.loads(buf.decode())
    if msg.get("error"):
        raise SystemExit("rpc %s: %s" % (method, msg["error"]))
    return msg.get("result") or {}
info = rpc("getmodelnetworkinfo", [])
print("helper", info.get("helper_ready"), info.get("openssl"))
got = rpc("getmodel", [uri, "FREE_ONLY"])
print("getmodel", json.dumps(got)[:4000])
job_id = got.get("job_id")
status = got.get("status")
if status == "running" or got.get("async"):
    if not job_id:
        raise SystemExit("async getmodel missing job_id")
    t0 = time.time()
    job = {}
    while time.time() - t0 < timeout:
        jobs = rpc("getmodeljob", [job_id])
        arr = jobs.get("jobs") or []
        if arr:
            job = arr[0]
            st = job.get("status")
            print("job", st, "elapsed", int(time.time()-t0), flush=True)
            if st == "failed":
                raise SystemExit("retrieve failed: %s" % (job,))
            if st == "cancelled":
                raise SystemExit("retrieve cancelled: %s" % (job,))
            if st == "done":
                break
        time.sleep(0.5)
    else:
        raise SystemExit("getmodeljob timeout: %s" % (job,))
    print("job_final", json.dumps(job)[:4000])
    if job.get("status") != "done":
        raise SystemExit("retrieve failed: %s" % (job,))
listed = rpc("listmodels", [])
print(json.dumps(listed)[:4000])
models = listed.get("models") if isinstance(listed, dict) else []
if not models:
    sys.exit("WAN getmodel produced no catalog models")
m = models[0]
adm = m.get("content_admission") or m.get("admission")
print("admission", adm, "bytes", m.get("bytes"))
if m.get("bytes", 0) < 1:
    sys.exit("WAN retrieve did not record bytes")
print("WAN_TWO_HELPER PASS")
PY
