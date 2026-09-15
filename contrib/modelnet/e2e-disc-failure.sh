#!/usr/bin/env bash
# DISC-04: official names never configured; independent seeder is a catalog peer.
# DISC-05: introducer dies mid-retrieve; same job fails over to the seeder and
# finishes (committed pieces resume). Fail-fast.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch/disc-failure"
BYTES=$((32 * 1024 * 1024))
die() { echo "E2E_DISC_FAIL: $*" >&2; exit 1; }
[[ -x "$BIN" ]] || die "missing $BIN"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/a/src" "$SCRATCH/b"
python3 "$ROOT/contrib/modelnet/write_safetensors_payload.py" "$SCRATCH/a/src/model.safetensors" "$BYTES"
pick() { python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
SEEDER="$(pick)"; PROXY="$(pick)"
PA=""; PB=""; PP=""
cleanup() {
  for p in "$PB" "$PA"; do [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true; done
  [[ -n "$PP" ]] && kill -TERM "$PP" 2>/dev/null || true
}
trap cleanup EXIT
python3 - "$PROXY" "$SEEDER" <<'PY' &
import socket, sys, threading, time
listen_port, dest = int(sys.argv[1]), int(sys.argv[2])
ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", listen_port)); ls.listen(32)
# Shared ceiling so 8 inflight PQ1 sessions cannot finish the payload
# on loopback before the introducer is killed (DISC-05).
rate_lock = threading.Lock()
sent = [0]
t0 = [time.time()]
RATE = 1.5 * 1024 * 1024
def pump(a, b):
    try:
        while True:
            d = a.recv(16384)
            if not d:
                break
            b.sendall(d)
            with rate_lock:
                sent[0] += len(d)
                want = sent[0] / RATE
                lag = want - (time.time() - t0[0])
            if lag > 0:
                time.sleep(min(lag, 0.25))
    except OSError:
        pass
while True:
    c, _ = ls.accept()
    d = socket.create_connection(("127.0.0.1", dest), timeout=10)
    threading.Thread(target=pump, args=(c, d), daemon=True).start()
    threading.Thread(target=pump, args=(d, c), daemon=True).start()
PY
PP=$!
"$BIN" -modeldir="$SCRATCH/a" -modelstorage=80MiB -modelbind="127.0.0.1:${SEEDER}" -modelhost -modelrpcsocket="$SCRATCH/a/modeld.sock" >"$SCRATCH/a.log" 2>&1 &
PA=$!
"$BIN" -modeldir="$SCRATCH/b" -modelstorage=80MiB -modelrpcsocket="$SCRATCH/b/modeld.sock" >"$SCRATCH/b.log" 2>&1 &
PB=$!
python3 - "$SCRATCH" "$SEEDER" "$PROXY" "$PA" "$PB" "$PP" "$ROOT/contrib/modelnet" <<'PY'
import json, os, signal, socket, sys, time
from pathlib import Path
root = Path(sys.argv[1])
seeder, proxy = sys.argv[2], sys.argv[3]
pa, pb, pp = int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
sys.path.insert(0, sys.argv[7])
from failfast import wait_unix, poll_job

def rpc(sock, method, params, timeout=90):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
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
        raise SystemExit("%s: %s" % (method, m["error"]))
    return m["result"]

def used():
    return sum(p.stat().st_size for p in (root / "b").rglob("*") if p.is_file())

sa, sb = root / "a/modeld.sock", root / "b/modeld.sock"
wait_unix(lambda: rpc(sa, "getmodelnetworkinfo", []) if sa.exists() else None, timeout=20, pid=pa, log=root / "a.log")
wait_unix(lambda: rpc(sb, "getmodelnetworkinfo", []) if sb.exists() else None, timeout=20, pid=pb, log=root / "b.log")
imp = rpc(sa, "importmodel", [str(root / "a/src"), {"pin": True}])
uri = imp["uri"]
# DISC-04: no official names. Introducer is the only contact at getmodel time.
rpc(sb, "addmodelnode", ["127.0.0.1:" + proxy])
got = rpc(sb, "getmodel", [uri, "FREE_ONLY"])
jid = got.get("job_id")
if not jid:
    raise SystemExit("expected async job: " + json.dumps(got))
t0 = time.time()
while used() < 4 * 1024 * 1024:
    if time.time() - t0 > 45:
        raise SystemExit("no first piece via introducer used=%s" % used())
    jobs = rpc(sb, "getmodeljob", [jid])
    arr = jobs.get("jobs") or []
    if arr and arr[0].get("status") == "failed":
        raise SystemExit("retrieve failed before introducer kill: " + json.dumps(arr[0]))
    if arr and arr[0].get("status") == "done":
        raise SystemExit("retrieve finished before introducer kill; increase payload")
    time.sleep(0.1)
print("DISC-04 first piece via introducer used_bytes", used(), flush=True)
rpc(sb, "addmodelnode", ["127.0.0.1:" + seeder])
os.kill(pp, signal.SIGKILL)
print("DISC-05 introducer killed; independent seeder is now a peer", flush=True)
try:
    os.kill(pb, 0)
    print("fetcher helper alive after introducer kill", flush=True)
except OSError:
    raise SystemExit("fetcher helper died after introducer kill\n" + (root / "b.log").read_text(errors="replace")[-4000:])
time.sleep(0.3)

def rpc_retry(sock, method, params, timeout=90):
    last = None
    for _ in range(20):
        try:
            return rpc(sock, method, params, timeout=timeout)
        except OSError as e:
            last = e
            try:
                os.kill(pb, 0)
            except OSError:
                raise SystemExit("fetcher helper died: %s\n%s" % (e, (root / "b.log").read_text(errors="replace")[-4000:]))
            time.sleep(0.2)
    raise SystemExit("rpc after introducer kill: %s" % last)

job = poll_job(lambda: rpc_retry(sb, "getmodeljob", [jid]), timeout=180)
result = job.get("result") or {}
listed = rpc(sb, "listmodels", [])
m = (listed.get("models") or [{}])[0]
if int(m.get("bytes") or 0) < 1024:
    raise SystemExit(listed)
if m.get("seeded") is not True:
    raise SystemExit("not demand-seeded: " + json.dumps(listed))
if int(result.get("failed_contacts") or 0) < 1:
    raise SystemExit("expected failover after introducer death: " + json.dumps(result))
print("E2E_DISC_FAILURE PASS", json.dumps({
    "bytes": m.get("bytes"),
    "seeded": m.get("seeded"),
    "failed_contacts": result.get("failed_contacts"),
    "last_peer": result.get("last_peer"),
}))
PY
echo "E2E_DISC_FAILURE PASS"
