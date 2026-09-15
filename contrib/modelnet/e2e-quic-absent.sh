#!/usr/bin/env bash
# CONN-QUIC: 0.34.7 defers QUIC. Transport stays pq1; classical_fallback is false.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
TEST="${TEST_BTX:-$ROOT/build-gcc13/bin/test_btx}"
die() { echo "e2e-quic-absent: $*" >&2; exit 1; }
[[ -x "$TEST" ]] || die "missing $TEST"
[[ -x "$BIN" ]] || die "missing $BIN"

if grep -RIn --include='*.cpp' --include='*.h' -E 'quic_connect|libquic|#include <quiche|#include <ngtcp2|QUIC handshake' \
     "$ROOT/src/modelnet" "$ROOT/src/node/resource_governor.cpp"; then
  die "QUIC implementation leaked into model-plane sources"
fi
"$TEST" --run_test=modelnet_conn_tests/conn_quic_deferred_pq1_only

SCRATCH="$ROOT/e2e-scratch/quic-absent"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/a"
"$BIN" -modeldir="$SCRATCH/a" -modelstorage=8MiB -modelrpcsocket="$SCRATCH/a/modeld.sock" \
  >"$SCRATCH/a/modeld.log" 2>&1 &
PA=$!
cleanup() { kill -TERM "$PA" 2>/dev/null || true; wait "$PA" 2>/dev/null || true; rm -rf "$SCRATCH"; }
trap cleanup EXIT
python3 - "$SCRATCH/a/modeld.sock" "$PA" "$ROOT/contrib/modelnet" <<'PY'
import json, socket, sys
from pathlib import Path
sock, pid = Path(sys.argv[1]), int(sys.argv[2])
sys.path.insert(0, sys.argv[3])
from failfast import wait_unix

def rpc():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(15)
    s.connect(str(sock))
    s.sendall(b'{"jsonrpc":"1.0","id":1,"method":"getmodelnetworkinfo","params":[]}\n')
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        data += c
        if b"\n" in data:
            break
    s.close()
    m = json.loads(data.decode())
    if m.get("error"):
        raise SystemExit(m["error"])
    return m["result"]

def connect():
    if not sock.exists():
        return None
    i = rpc()
    return i if i.get("helper_ready") else None

i = wait_unix(connect, timeout=20, pid=pid, log=sock.parent / "modeld.log")
assert i.get("transport") == "pq1", i
assert i.get("quic") is False, i
assert i.get("classical_fallback") is False, i
print("CONN-QUIC deferred: transport=pq1 quic=false classical_fallback=false")
PY
echo "CONN-QUIC PASS (deferred; PQ1 only)"
