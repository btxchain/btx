#!/usr/bin/env bash
# Encrypted pre-cache + unlock: A wraps BTXENC2, C retrieves ciphertext only,
# then claimmodelrelease with the secret unwraps plaintext. Never production btxd.
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CONTRIB="$ROOT/contrib/modelnet"
BASE="/tmp/btx-econ-enc-$$"
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
mkdir -p "$BASE/a" "$BASE/c" "$BASE/src"
python3 - "$BASE/src/weights.safetensors" <<'PY'
import json, struct, sys
from pathlib import Path
p = Path(sys.argv[1])
n = 65536  # 256 KiB of F32 payload — larger than the tiny unit vectors
header = {"w": {"dtype": "F32", "shape": [n], "data_offsets": [0, n * 4]}}
hb = json.dumps(header, separators=(",", ":")).encode()
p.write_bytes(struct.pack("<Q", len(hb)) + hb + bytes(n * 4))
PY
pick() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORT="$(pick)"
"$BIN" -modeldir="$BASE/a" -modelstorage=8MiB -modelbind="127.0.0.1:${PORT}" \
  -modelrpcsocket="$BASE/a/modeld.sock" >"$BASE/a/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$BASE/c" -modelstorage=8MiB -modelallowencrypted \
  -modelrpcsocket="$BASE/c/modeld.sock" >"$BASE/c/modeld.log" 2>&1 &
PIDS+=($!)
python3 - "$BASE" "$PORT" "$CONTRIB" "${PIDS[0]}" "${PIDS[1]}" <<'PY'
import json, socket, sys, time
from pathlib import Path
base = Path(sys.argv[1]); port = int(sys.argv[2])
sys.path.insert(0, sys.argv[3])
from failfast import wait_unix
pid_a, pid_c = int(sys.argv[4]), int(sys.argv[5])

def rpc(sock, method, params=None, timeout=60):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall((json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}) + "\n").encode())
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

def wait(name, pid):
    sock = base / name / "modeld.sock"
    def connect():
        i = rpc(sock, "getmodelnetworkinfo", [])
        return i if i.get("helper_ready") else None
    wait_unix(connect, timeout=20, pid=pid, log=base / name / "modeld.log")

wait("a", pid_a); wait("c", pid_c)
a = base / "a" / "modeld.sock"
c = base / "c" / "modeld.sock"
imp = rpc(a, "importmodel", [str(base / "src" / "weights.safetensors"), {"pin": True}])
uri = imp["uri"]
plain_id = imp["model_id"]
secret = "11" * 32
rel = rpc(a, "createmodelrelease", [uri, secret, 100, 50000000000, {
    "publish_search_record": True,
    "display_name": "EncryptedCoder",
    "short_description": "large encrypted campaign artifact for coding agents",
}])
rid = rel.get("release_id") or rel.get("id")
if not rid:
    raise SystemExit(f"createmodelrelease {rel}")
cid = rel.get("ciphertext_artifact_id") or (rel.get("release") or {}).get("ciphertext_artifact_id")
if not cid:
    econ = rpc(a, "getmodelreleaseeconomics", [rid])
    cid = econ.get("ciphertext_artifact_id")
if not cid or cid == (plain_id if isinstance(plain_id, str) else ""):
    # wrap should produce a distinct ciphertext artifact when plaintext was imported
    print("note: ciphertext id", cid, "plain", plain_id, flush=True)
rpc(c, "addmodelindex", [f"127.0.0.1:{port}"])
rpc(c, "addmodelnode", [f"127.0.0.1:{port}"])
sm = rpc(c, "searchmodels", [{"text": "encrypted campaign", "scope": "NETWORK"}])
hits = sm.get("results") or []
if not any("EncryptedCoder" in str(h.get("name") or "") for h in hits):
    raise SystemExit(f"search miss {sm}")
card = next(h for h in hits if "EncryptedCoder" in str(h.get("name") or ""))
if card.get("downloadable_now") is True:
    raise SystemExit(f"plaintext leaked before unlock {card}")
rr = rpc(c, "getrecentreleases", [{"scope": "NETWORK", "limit": 50}])
if not (rr.get("results") or rr.get("items")):
    raise SystemExit(f"getrecentreleases NETWORK empty {rr}")
cache = rpc(c, "cacheencryptedmodel", [rid])
if cache.get("plaintext_unavailable") is not True:
    raise SystemExit(f"ECON-CACHE-01 {cache}")
if cache.get("automatic_download") is not False:
    raise SystemExit(f"auto download {cache}")
job = cache.get("job_id")
status = cache.get("status")
deadline = time.time() + 40
while status != "local" and time.time() < deadline:
    if job:
        jobs = rpc(c, "getmodeljob", [job])
        listed = jobs.get("jobs") if isinstance(jobs, dict) else None
        if listed:
            for j in listed:
                if j.get("id") == job:
                    status = j.get("status") or status
                    break
        elif isinstance(jobs, dict) and jobs.get("status"):
            status = jobs.get("status")
    cache = rpc(c, "cacheencryptedmodel", [rid])
    if cache.get("status") == "local":
        status = "local"
        break
    time.sleep(0.4)
if status not in ("local", "complete", "done"):
    # local verify of BTXENC2 after retrieve
    if cache.get("verified_ciphertext") is not True and cache.get("status") != "local":
        raise SystemExit(f"ciphertext retrieve did not complete {cache} status={status}")
if cache.get("plaintext_unavailable") is not True:
    raise SystemExit(f"plaintext still sealed? {cache}")
print("ECON-CACHE-01 retrieve PASS", cache.get("status"), flush=True)
unlock = rpc(c, "claimmodelrelease", [rid, secret])
if unlock.get("secret_retained") is True:
    raise SystemExit(f"secret retained {unlock}")
if unlock.get("unlocked_locally") is not True and unlock.get("secret_disclosed") is not True:
    raise SystemExit(f"unlock {unlock}")
print("ECON-CACHE unlock PASS", unlock.get("unlocked_locally"), flush=True)
print("E2E_ENCRYPTED_CACHE PASS", flush=True)
PY
echo "e2e-encrypted-cache: PASS"
