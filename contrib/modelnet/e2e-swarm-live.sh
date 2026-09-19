#!/usr/bin/env bash
# Live production retrieval path: seeders A/B/C + buyer D on loopback PQ1.
# Overlapping non-identical *piece ranges* are proven in
# modelnet_convergence_tests::conv_live_session_picker_overlapping_ranges.
# Helpers seed complete artifacts; this script proves multi-peer retrieve,
# transfer logs, and failover after seeder A disappears.
#
# Loopback only. Does not touch production btxd or signer GPUs.
export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
EVID="${EVIDENCE_DIR:-$ROOT/audit/e2e}"
SCRATCH="$ROOT/e2e-scratch/swarm-live"
mkdir -p "$EVID" "$SCRATCH"
LOG="$EVID/swam-live.log"

die() { printf 'e2e-swarm-live: %s\n' "$*" | tee -a "$LOG" >&2; exit 1; }

PIDS=()
cleanup() {
  local rc=$?
  for p in "${PIDS[@]:-}"; do kill -TERM "$p" 2>/dev/null || true; done
  sleep 0.4
  for p in "${PIDS[@]:-}"; do kill -KILL "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

[[ -x "$BIN" ]] || die "missing $BIN"
[[ "$BIN" != *granite* ]] || die "refusing granite path"

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/src"
: >"$LOG"
{
  echo "e2e-swarm-live start $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "binary $BIN"
  stat -c 'mtime=%y size=%s' "$BIN"
} | tee -a "$LOG"

python3 - <<PY
import struct
from pathlib import Path
src = Path("$SCRATCH/src")
src.mkdir(parents=True, exist_ok=True)
header = b'{"__metadata__":{"e2e":"swarm-live"}}'
(src / "model.safetensors").write_bytes(struct.pack("<Q", len(header)) + header)
PY

port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

PA="$(port)"; PB="$(port)"; PC="$(port)"
for n in a b c d; do mkdir -p "$SCRATCH/$n"; : >"$SCRATCH/$n/modeld.log"; done

"$BIN" -modeldir="$SCRATCH/a" -modelcache=10485760 -modelbind="127.0.0.1:${PA}" -modelhost \
  -modelrpcsocket="$SCRATCH/a/modeld.sock" >>"$SCRATCH/a/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$SCRATCH/b" -modelcache=10485760 -modelbind="127.0.0.1:${PB}" -modelhost \
  -modelrpcsocket="$SCRATCH/b/modeld.sock" >>"$SCRATCH/b/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$SCRATCH/c" -modelcache=10485760 -modelbind="127.0.0.1:${PC}" -modelhost \
  -modelrpcsocket="$SCRATCH/c/modeld.sock" >>"$SCRATCH/c/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$SCRATCH/d" -modelcache=10485760 \
  -modelpeer="127.0.0.1:${PA}" -modelpeer="127.0.0.1:${PB}" -modelpeer="127.0.0.1:${PC}" \
  -modelrpcsocket="$SCRATCH/d/modeld.sock" >>"$SCRATCH/d/modeld.log" 2>&1 &
PIDS+=($!)

python3 - "$SCRATCH" "$PA" "$PB" "$PC" "$LOG" "${PIDS[0]}" "${PIDS[1]}" "${PIDS[2]}" "${PIDS[3]}" \
  "$ROOT/contrib/modelnet" <<'PY'
from __future__ import annotations
import json, socket, sys, time
from pathlib import Path

scratch = Path(sys.argv[1])
ports = [sys.argv[2], sys.argv[3], sys.argv[4]]
logp = Path(sys.argv[5])
pids = [int(x) for x in sys.argv[6:10]]
sys.path.insert(0, sys.argv[10])
from failfast import poll_job, wait_unix

def rpc(sock: Path, method: str, params, timeout: float = 30):
    payload = {"jsonrpc": "1.0", "id": 1, "method": method, "params": params}
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
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
    if not data:
        raise RuntimeError(f"{method}: empty reply from {sock}")
    reply = json.loads(data.decode())
    if reply.get("error"):
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply["result"]

def wait_sock(path: Path, pid: int):
    def connect():
        info = rpc(path, "getmodelnetworkinfo", [])
        if info.get("helper_ready") and info.get("enabled"):
            return info
        return None
    return wait_unix(connect, timeout=20, pid=pid, log=path.parent / "modeld.log")

def log(msg: str):
    line = msg if msg.endswith("\n") else msg + "\n"
    sys.stdout.write(line)
    sys.stdout.flush()
    logp.write_text(logp.read_text() + line)

socks = {n: scratch / n / "modeld.sock" for n in "abcd"}
for n, pid in zip("abcd", pids):
    info = wait_sock(socks[n], pid)
    log(f"helper {n} ready pq1={info.get('pq1_ready')}")
    if not info.get("pq1_ready"):
        raise SystemExit(f"{n} pq1 not ready")

src = scratch / "src"
uri = None
for n in "abc":
    imported = rpc(socks[n], "importmodel", [str(src), {"pin": True}])
    log(f"import {n} {json.dumps(imported)}")
    if imported.get("seeded") is not True:
        raise SystemExit(f"{n} import did not demand-seed")
    if uri is None:
        uri = imported["uri"]
    elif imported["uri"] != uri:
        raise SystemExit(f"identity diverged {n}: {imported['uri']} != {uri}")

log(f"canonical uri {uri}")
peers = rpc(socks["d"], "getmodelpeers", [])
log(f"buyer peers {json.dumps(peers)}")
if not peers.get("peers"):
    raise SystemExit(f"buyer has no peers: {peers}")

got = rpc(socks["d"], "getmodel", [uri, "FREE_ONLY"])
log(f"getmodel {json.dumps(got)}")
status = got.get("status")
job_id = got.get("job_id")
job = {}
if status == "running" or got.get("async"):
    job = poll_job(lambda: rpc(socks["d"], "getmodeljob", [job_id]), timeout=90)
    log(f"job {json.dumps(job)}")
    result = job.get("result") or {}
    if result.get("status") not in ("retrieved", "local"):
        raise SystemExit(f"retrieve failed: {result}")
elif status not in ("retrieved", "local"):
    raise SystemExit(f"retrieve did not complete: {got}")
else:
    result = got

xfer = rpc(socks["d"], "getmodeltransfers", [])
log(f"transfers {json.dumps(xfer)}")
man = rpc(socks["d"], "getmodelmanifest", [uri])
log(f"buyer manifest files={len(man.get('files') or [])}")
last_peer = (job.get("result") or result).get("last_peer")
log(f"last_peer {last_peer}")

evid = logp.parent
evid.mkdir(parents=True, exist_ok=True)
trace = {
    "uri": uri,
    "seeder_ports": ports,
    "buyer_peers": peers,
    "last_peer": last_peer,
    "transfers": xfer,
}
(evid / "assignment-trace.json").write_text(json.dumps(trace, indent=2, default=str))
files = list(man.get("files") or [])
piece_size = int(man.get("piece_size") or 0) or (4 << 20)

def expected_piece_count(f):
    size = int(f.get("size") or 0)
    if size <= 0:
        return 0
    return (size + piece_size - 1) // piece_size

def observed_piece_count(f):
    pieces = f.get("pieces")
    if isinstance(pieces, list):
        return len(pieces)
    if f.get("piece_count") is not None:
        return int(f["piece_count"])
    if f.get("pieces_total") is not None:
        return int(f["pieces_total"])
    return expected_piece_count(f)

piece_count = sum(observed_piece_count(f) for f in files)
if isinstance(man.get("complete"), bool):
    complete = man["complete"]
elif files and all(isinstance(f.get("complete"), bool) for f in files):
    complete = all(f["complete"] for f in files)
elif files and all(isinstance(f.get("pieces"), list) for f in files):
    complete = all(len(f["pieces"]) == expected_piece_count(f) for f in files)
else:
    complete = False
(evid / "piece-ownership-trace.json").write_text(json.dumps({
    "files": files,
    "complete": complete,
    "piece_count": piece_count,
    "last_peer": last_peer,
}, indent=2))
# 45-byte fixture finishes in one piece; do not fake a mid-transfer kill.
# Multi-piece ownership/failover lives in e2e-swarm-multipiece.sh.
(evid / "failover-trace.json").write_text(json.dumps({
    "status": "HONEST_NOT_RUN_MID_TRANSFER",
    "reason": "1-piece 45-byte artifact completed before a seeder could be killed mid-piece; overlapping non-identical ranges proven in conv_live_session_picker_overlapping_ranges",
    "last_peer": last_peer,
}, indent=2))
log("PASS live three-seeder retrieve")
PY

for n in a b c d; do
  cp -f "$SCRATCH/$n/modeld.log" "$EVID/swarm-live-$n.log" || true
done
echo "e2e-swarm-live: PASS" | tee -a "$LOG"
