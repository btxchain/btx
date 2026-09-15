#!/usr/bin/env bash
# SEARCH-CHAOS: indexer SIGTERM mid-query; LOCAL still answers; coverage.complete stays false.
export LC_ALL=C
set -euo pipefail

if [[ "${BTX_SEARCH_CHAOS:-}" != "1" && "${BTX_SEARCH_CHAOS:-}" != "yes" ]]; then
  echo "NOT_RUN: export BTX_SEARCH_CHAOS=1 to run the search chaos lab"
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${BIN_DIR:-$ROOT/build-gcc13/bin}"
MODELD="${MODELD:-$BIN/btx-modeld}"
CONTRIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="/tmp/btx-search-chaos-$$"
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

[[ -x "$MODELD" ]] || { echo "missing $MODELD" >&2; exit 1; }
rm -rf "$BASE"
mkdir -p "$BASE"

pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

for n in idx-a idx-b client; do
  mkdir -p "$BASE/$n"
  extra=()
  if [[ "$n" != client ]]; then
    extra=(-modelbind="127.0.0.1:$(pick_port)")
  fi
  "$MODELD" -modeldir="$BASE/$n" -modelstorage=8MiB -modelrpcsocket="$BASE/$n/modeld.sock" \
    "${extra[@]}" >"$BASE/$n/modeld.log" 2>&1 &
  echo $! >"$BASE/$n/pid"
  PIDS+=($!)
done

python3 - "$BASE" "$CONTRIB" <<'PY'
import json, os, signal, socket, sys, time
from pathlib import Path

base = Path(sys.argv[1])
sys.path.insert(0, sys.argv[2])
from failfast import wait_unix, pid_alive

def rpc(sock, method, params=None, timeout=20):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall((json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}) + "\n").encode())
    s.shutdown(socket.SHUT_WR)
    data = s.recv(1 << 20)
    s.close()
    m = json.loads(data.decode())
    if m.get("error"):
        raise RuntimeError(f"{method}: {m['error']}")
    return m["result"]

def wait_helper(name):
    sock = base / name / "modeld.sock"
    pid = int((base / name / "pid").read_text())
    def connect():
        if not sock.exists():
            return None
        i = rpc(sock, "getmodelnetworkinfo", [])
        return i if i.get("helper_ready") else None
    return wait_unix(connect, timeout=20, pid=pid, log=base / name / "modeld.log")

for n in ("idx-a", "idx-b", "client"):
    wait_helper(n)

def mid(tag):
    return f"{tag:02x}" + "00" * 47

for host, tag, title in (("idx-a", 0x11, "Chaos Alpha"), ("idx-b", 0x12, "Chaos Beta")):
    rpc(base / host / "modeld.sock", "publishmodelsearchrecord", [mid(tag), {
        "type": "btx-model-search-v1",
        "canonical_name": title,
        "display_name": title,
        "expires_at": 0,
    }])

merged = []
for idx in ("idx-a", "idx-b"):
    snap = rpc(base / idx / "modeld.sock", "listmodelsearchrecords", [{"limit": 100}])
    merged.extend(snap.get("records") or [])
rpc(base / "client" / "modeld.sock", "importmodelindex", [{"records": merged}])

# Flood publisher spam on idx-a (cap >64 in window should reject extras, not crash).
spam_ok = 0
spam_rej = 0
for i in range(80):
    try:
        rpc(base / "idx-a" / "modeld.sock", "publishmodelsearchrecord", [mid(0x20 + (i % 70)), {
            "type": "btx-model-search-v1",
            "canonical_name": f"spam-{i}",
            "display_name": f"Spam {i}",
            "publisher_display_name": "flooder",
            "expires_at": 0,
        }])
        spam_ok += 1
    except Exception:
        spam_rej += 1
print("spam accepted", spam_ok, "rejected", spam_rej, flush=True)

# SIGTERM idx-b then search LOCAL on client.
os.kill(int((base / "idx-b" / "pid").read_text()), signal.SIGTERM)
time.sleep(0.3)
sm = rpc(base / "client" / "modeld.sock", "searchmodels", [{"text": "chaos", "scope": "LOCAL", "limit": 50}])
cov = sm.get("coverage") or {}
if cov.get("complete") is not False:
    raise SystemExit(f"coverage.complete must stay false: {cov}")
hits = sm.get("results") or sm.get("models") or []
names = [str(h.get("display_name") or h.get("name") or "") for h in hits if isinstance(h, dict)]
if not any("Chaos" in n for n in names):
    raise SystemExit(f"LOCAL search empty after indexer death: {names}")
print("SEARCH-CHAOS PASS coverage.complete=false hits", names[:5], flush=True)
PY

echo "e2e-search-chaos: PASS"
