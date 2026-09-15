#!/usr/bin/env bash
# Two isolated btx-modeld helpers, loopback PQ1 FREE_ONLY retrieve.
#
# Seeder:  -modelhost -modelbind=127.0.0.1:<free-high-port>
# Fetcher: -modelpeer=127.0.0.1:PORT  (no -modelhost)
#
# Unix JSON-RPC is one line, same shape as CallUnixRpc / DispatchHelperRpc:
#   {"jsonrpc":"1.0","id":1,"method":"<name>","params":[...]}
#
# Piece GET returns 403 without a complete FreeGrant (X-BTX-Grant-Payload,
# X-BTX-Grant-Sig, X-BTX-Grant-Pubkey). getmodel still POSTs
# /btx-model/2/ext/free/grant and attaches those headers when the seeder
# returns 200. There is no unix RPC for grant.
#
# Loopback only. No granite, no production sockets, no cmake/ninja.
export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch"
DIR_A="$SCRATCH/pq1-a"
DIR_B="$SCRATCH/pq1-b"
SOCK_A="$DIR_A/modeld.sock"
SOCK_B="$DIR_B/modeld.sock"

SEEDER_PID=""
FETCHER_PID=""

die() { printf 'e2e-two-helper-pq1: %s\n' "$*" >&2; exit 1; }

dump_logs() {
  local f
  for f in "$DIR_A/modeld.log" "$DIR_B/modeld.log"; do
    if [[ -f "$f" ]]; then
      printf '\n----- %s -----\n' "$f" >&2
      tail -n 80 "$f" >&2 || true
    fi
  done
}

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then dump_logs; fi
  if [[ -n "${SEEDER_PID}" ]]; then kill -TERM "$SEEDER_PID" 2>/dev/null || true; fi
  if [[ -n "${FETCHER_PID}" ]]; then kill -TERM "$FETCHER_PID" 2>/dev/null || true; fi
  sleep 0.4
  if [[ -n "${SEEDER_PID}" ]]; then kill -KILL "$SEEDER_PID" 2>/dev/null || true; fi
  if [[ -n "${FETCHER_PID}" ]]; then kill -KILL "$FETCHER_PID" 2>/dev/null || true; fi
  wait 2>/dev/null || true
  rm -rf "$SCRATCH"/pq1-*
  exit "$rc"
}
trap cleanup EXIT

[[ -x "$BIN" ]] || die "missing $BIN"
[[ "$BIN" != *granite* ]] || die "refusing granite path"

mkdir -p "$DIR_A" "$DIR_B"

# SplitHostPort rejects port 0, so pick a free high loopback port.
PORT="$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
port = s.getsockname()[1]
s.close()
if port < 1024:
    raise SystemExit("refusing privileged port")
print(port)
PY
)"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "failed to pick a free port"
(( PORT > 1024 && PORT <= 65535 )) || die "port out of range: $PORT"

python3 - <<PY
import struct
from pathlib import Path
src = Path("$DIR_A") / "src"
src.mkdir(parents=True, exist_ok=True)
header = b"{}"
(src / "model.safetensors").write_bytes(struct.pack("<Q", len(header)) + header)
PY

: >"$DIR_A/modeld.log"
: >"$DIR_B/modeld.log"

"$BIN" \
  -modeldir="$DIR_A" \
  -modelcache=10485760 \
  -modelbind="127.0.0.1:${PORT}" \
  -modelhost \
  -modelrpcsocket="$SOCK_A" \
  >>"$DIR_A/modeld.log" 2>&1 &
SEEDER_PID=$!

"$BIN" \
  -modeldir="$DIR_B" \
  -modelcache=10485760 \
  -modelpeer="127.0.0.1:${PORT}" \
  -modelrpcsocket="$SOCK_B" \
  >>"$DIR_B/modeld.log" 2>&1 &
FETCHER_PID=$!

python3 - "$SOCK_A" "$SOCK_B" "$DIR_A/src" "$SEEDER_PID" "$FETCHER_PID" "$ROOT/contrib/modelnet" <<'PY'
"""Unix AF_UNIX JSON-RPC driver. Shape matches helper.cpp CallUnixRpc / DispatchHelperRpc."""
from __future__ import annotations

import hashlib
import json
import socket
import sys
import time
from pathlib import Path

sock_a, sock_b, src = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
seeder_pid, fetcher_pid = int(sys.argv[4]), int(sys.argv[5])
sys.path.insert(0, sys.argv[6])
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


def wait_sock(path: Path, pid: int, timeout: float = 20):
    def connect():
        info = rpc(path, "getmodelnetworkinfo", [])
        if info.get("helper_ready") and info.get("enabled"):
            return info
        return None

    return wait_unix(connect, timeout=timeout, pid=pid, log=path.parent / "modeld.log")


print("RPC sequence:", flush=True)
print("  1. seeder  getmodelnetworkinfo []", flush=True)
info_a = wait_sock(sock_a, seeder_pid)
print("  2. fetcher getmodelnetworkinfo []", flush=True)
info_b = wait_sock(sock_b, fetcher_pid)
if not info_a.get("pq1_ready") or not info_b.get("pq1_ready"):
    raise SystemExit(f"pq1 not ready seeder={info_a} fetcher={info_b}")

print("  3. seeder  importmodel [src, {pin:true}]  (no seedmodel; default demand-seed)", flush=True)
prop = info_a.get("propagation") or {}
if not prop.get("demand_propagation"):
    raise SystemExit(f"default demand_propagation false: {prop}")
if prop.get("seed_upon_download_opt_in"):
    raise SystemExit(f"seed_upon_download still opt-in: {prop}")
imported = rpc(sock_a, "importmodel", [str(src), {"pin": True}])
uri = imported["uri"]
if not uri:
    raise SystemExit(f"importmodel missing uri: {imported}")
print("     uri", uri, "seeded", imported.get("seeded"), flush=True)
if imported.get("seeded") is not True:
    raise SystemExit(f"import must demand-seed without seedmodel: {imported}")

print("  5. seeder  getmodelmanifest [uri]  (sha384 baseline)", flush=True)
man_a = rpc(sock_a, "getmodelmanifest", [uri])
files_a = man_a.get("files") or []
if not files_a or not files_a[0].get("sha384"):
    raise SystemExit(f"seeder manifest missing sha384: {man_a}")
sha_a = files_a[0]["sha384"]
if len(sha_a) != 96:
    raise SystemExit(f"seeder sha384 length: {sha_a!r}")

src_bytes = (src / "model.safetensors").read_bytes()
src_sha = hashlib.sha384(src_bytes).hexdigest()
if sha_a.lower() != src_sha:
    raise SystemExit(f"seeder sha384 != file digest {sha_a} != {src_sha}")

print("  6. fetcher getmodelpeers []", flush=True)
peers = rpc(sock_b, "getmodelpeers", [])
if not peers.get("peers"):
    raise SystemExit(f"fetcher has no -modelpeer: {peers}")

print("  7. fetcher getmodel [uri, FREE_ONLY]", flush=True)
print("     (helper POSTs /ext/free/grant then GET pieces over PQ1)", flush=True)
got = rpc(sock_b, "getmodel", [uri, "FREE_ONLY"])
status = got.get("status")
job_id = got.get("job_id")
print("     getmodel", json.dumps(got), flush=True)

if status == "running" or got.get("async"):
    if not job_id:
        raise SystemExit(f"async getmodel missing job_id: {got}")
    print("  8. fetcher getmodeljob [job_id]  (poll, fail-fast on failed)", flush=True)
    job = poll_job(lambda: rpc(sock_b, "getmodeljob", [job_id]), timeout=90)
    print("     job", json.dumps(job), flush=True)
    result = job.get("result") or {}
    if result.get("status") not in ("retrieved", "local"):
        raise SystemExit(f"job result not retrieved: {result}")
    step_list = 9
elif status in ("retrieved", "local"):
    step_list = 8
else:
    raise SystemExit(f"retrieve did not complete: {got}")

print(f"  {step_list}. fetcher listmodels []", flush=True)
listed = rpc(sock_b, "listmodels", [])
print("     listmodels", json.dumps(listed), flush=True)
if int(listed.get("local_count") or 0) < 1:
    raise SystemExit(f"fetcher local_count < 1: {listed}")

print(f"  {step_list + 1}. fetcher getmodelmanifest [uri]  (VerifyFileDigest sha384)", flush=True)
man_b = rpc(sock_b, "getmodelmanifest", [uri])
files_b = man_b.get("files") or []
if not files_b or not files_b[0].get("sha384"):
    raise SystemExit(f"fetcher manifest missing sha384: {man_b}")
sha_b = files_b[0]["sha384"]
if sha_b.lower() != sha_a.lower():
    raise SystemExit(f"sha384 mismatch seeder={sha_a} fetcher={sha_b}")
print("     sha384", sha_b, flush=True)
print("E2E_TWO_HELPER_PQ1 PASS", flush=True)
PY
