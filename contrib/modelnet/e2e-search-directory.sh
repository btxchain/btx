#!/usr/bin/env bash
# Isolated unix-RPC search directory lab: N helpers, publish search records, NETWORK then LOCAL.
# Scratch on tmpfs (/tmp). One runner; TIMEOUT_FACTOR=1 (default short polls).
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${BIN_DIR:-$ROOT/build-gcc13/bin}"
MODELD="${MODELD:-$BIN/btx-modeld}"
CONTRIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="/tmp/btx-search-e2e-$$"
export TIMEOUT_FACTOR="${TIMEOUT_FACTOR:-1}"

PIDS=()

cleanup() {
  local rc=$?
  for p in "${PIDS[@]:-}"; do
    kill -TERM "$p" 2>/dev/null || true
  done
  sleep 0.2
  for p in "${PIDS[@]:-}"; do
    kill -KILL "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  rm -rf "$BASE"
  rm -rf /tmp/test_runner_*
  rm -rf /tmp/btx-search-e2e-*
  exit "$rc"
}
trap cleanup EXIT

if [[ ! -x "$MODELD" ]]; then
  echo "NOT_RUN: btx-modeld missing at $MODELD (build-gcc13/bin/btx-modeld)" >&2
  exit 2
fi

rm -rf "$BASE"
mkdir -p "$BASE"

pick_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

NAMES=(idx-a idx-b client-e spare)
for n in "${NAMES[@]}"; do
  mkdir -p "$BASE/$n"
  extra=()
  if [[ "$n" != client-e ]]; then
    port="$(pick_port)"
    extra=(-modelbind="127.0.0.1:$port")
  fi
  "$MODELD" \
    -modeldir="$BASE/$n" \
    -modelstorage=8MiB \
    -modelrpcsocket="$BASE/$n/modeld.sock" \
    "${extra[@]}" \
    >"$BASE/$n/modeld.log" 2>&1 &
  echo $! >"$BASE/$n/pid"
  PIDS+=($!)
done

python3 - "$BASE" "$CONTRIB" <<'PY'
import json
import os
import signal
import socket
import sys
import time
from pathlib import Path

base = Path(sys.argv[1])
contrib = Path(sys.argv[2])
sys.path.insert(0, str(contrib))
from failfast import wait_unix

poll = max(0.05, 0.1 * float(os.environ.get("TIMEOUT_FACTOR", "1")))


def rpc(sock: Path, method, params=None, timeout=30):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(
        (json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}) + "\n").encode()
    )
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(1 << 20)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    reply = json.loads(data.decode())
    if reply.get("error"):
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply["result"]


def wait_helper(name: str):
    sock = base / name / "modeld.sock"
    log = base / name / "modeld.log"
    pid = int((base / name / "pid").read_text().strip())

    def connect():
        if not sock.exists():
            return None
        info = rpc(sock, "getmodelnetworkinfo", [])
        return info if info.get("helper_ready") else None

    return wait_unix(connect, timeout=20, pid=pid, log=log)


def model_id(tag: int) -> str:
    return f"{tag:02x}" + "00" * 47


def publish(sock: Path, mid: str, body: dict):
    rec = dict(body)
    rec.setdefault("type", "btx-model-search-v1")
    rec.setdefault("expires_at", 0)
    rpc(sock, "publishmodelsearchrecord", [mid, rec])


for name in ("idx-a", "idx-b", "client-e", "spare"):
    wait_helper(name)

probe = base / "idx-a" / "modeld.sock"
try:
    rpc(probe, "listmodelsearchrecords", [{"limit": 1}])
except RuntimeError as e:
    if "METHOD_NOT_FOUND" in str(e) or "NOT_ENABLED" in str(e):
        print("NOT_RUN: helper lacks search RPCs (rebuild btx-modeld from this tree)", file=sys.stderr)
        raise SystemExit(2)
    raise

records = [
    ("idx-a", model_id(0x0A), "Qwen Coder Test A", {"tags": ["coding"], "aliases": ["qwen-coder-a"]}),
    ("idx-b", model_id(0x0B), "Qwen Coder Test B", {"tags": ["coding"], "aliases": ["qwen-coder-b"]}),
    ("idx-a", model_id(0x0C), "Vision Sidecar C", {"family": "vision"}),
    ("spare", model_id(0x0D), "Vision Sidecar D", {"family": "vision"}),
]

for host, mid, title, extra in records:
    body = {
        "canonical_name": title,
        "display_name": title,
        "publisher_display_name": "e2e-lab",
        **extra,
    }
    publish(base / host / "modeld.sock", mid, body)

client = base / "client-e" / "modeld.sock"
merged = []
for idx in ("idx-a", "idx-b", "spare"):
    snap = rpc(base / idx / "modeld.sock", "listmodelsearchrecords", [{"limit": 100}])
    for rec in snap.get("records") or []:
        if isinstance(rec, dict):
            merged.append(rec)
imp = rpc(client, "importmodelindex", [{"records": merged}])
if int(imp.get("imported", 0)) < 2:
    raise SystemExit(f"importmodelindex expected >=2 records: {imp}")

net = rpc(client, "searchmodels", [{"text": "qwen coder", "scope": "NETWORK", "limit": 50}])
cov = net.get("coverage") or {}
if cov.get("complete") is not False:
    raise SystemExit(f"coverage.complete must be false: {cov}")
print("coverage.complete=false")

names = []
for hit in net.get("results") or net.get("models") or []:
    if isinstance(hit, dict):
        names.append(str(hit.get("name") or hit.get("display_name") or ""))

for want in ("Qwen Coder Test A", "Qwen Coder Test B"):
    if want in names:
        print("found", want)
    else:
        print("note: missing", want)

if not any("Qwen Coder Test" in n for n in names):
    raise SystemExit(f"expected qwen coder hits, got: {names}")

for idx in ("idx-a", "idx-b", "spare"):
    pid = int((base / idx / "pid").read_text().strip())
    os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(poll)
    else:
        raise SystemExit(f"indexer {idx} pid {pid} still running")

loc = rpc(client, "searchmodels", [{"text": "qwen", "scope": "LOCAL", "limit": 50}])
hits = loc.get("results") or loc.get("models") or []
if not hits:
    raise SystemExit(f"LOCAL search empty after indexer shutdown: {loc}")
print("LOCAL search ok", len(hits), "hit(s)")
print("E2E_SEARCH_DIRECTORY PASS")
PY

echo "e2e-search-directory: PASS"
