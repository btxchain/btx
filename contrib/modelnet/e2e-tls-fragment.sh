#!/usr/bin/env bash
# Prove PQ1 max_send_fragment is 512 in source and on a live helper.
# Fail-fast. After helper.cpp rebuild, also asserts getmodelcryptoinfo.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
die() { echo "E2E_TLS_512 FAIL: $*" >&2; exit 1; }
grep -n 'SSL_set_max_send_fragment(ssl, 512)' "$ROOT/src/modelnet/pq1_runtime.cpp" >/dev/null || die "pq1_runtime missing 512"
grep -n 'SSL_CTX_set_max_send_fragment(ctx, 512)' "$ROOT/src/modelnet/transport_pq.cpp" >/dev/null || die "transport_pq missing 512"
[[ -x "$BIN" ]] || die "missing $BIN"
SCRATCH="$ROOT/e2e-scratch/tls-512"
rm -rf "$SCRATCH"; mkdir -p "$SCRATCH"
"$BIN" -modeldir="$SCRATCH" -modelstorage=8MiB -modelrpcsocket="$SCRATCH/modeld.sock" >"$SCRATCH/modeld.log" 2>&1 &
PID=$!
cleanup() { kill -TERM "$PID" 2>/dev/null || true; }
trap cleanup EXIT
python3 - "$SCRATCH/modeld.sock" "$PID" "$SCRATCH/modeld.log" "$ROOT/contrib/modelnet" <<'PY'
import json, socket, sys
from pathlib import Path
sock, pid, log = Path(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3])
sys.path.insert(0, sys.argv[4])
from failfast import wait_unix

def rpc(method, params):
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params}).encode()+b"\n")
    s.shutdown(socket.SHUT_WR)
    data=b""
    while True:
        c=s.recv(65536)
        if not c: break
        data+=c
        if b"\n" in data: break
    s.close()
    m=json.loads(data.decode())
    if m.get("error"): raise SystemExit(m["error"])
    return m["result"]

info=wait_unix(lambda: rpc("getmodelcryptoinfo",[]) if sock.exists() else None, timeout=20, pid=pid, log=log)
if info.get("group")!="MLKEM768" or info.get("cipher")!="TLS_AES_256_GCM_SHA384":
    raise SystemExit(info)
frag=info.get("max_send_fragment")
if frag is None:
    print("max_send_fragment not in RPC yet (pre-rebuild); source 512 asserted")
elif int(frag)!=512:
    raise SystemExit("max_send_fragment %s"%frag)
else:
    print("getmodelcryptoinfo max_send_fragment=512")
print("E2E_TLS_512 PASS", json.dumps({"group": info.get("group"), "max_send_fragment": frag}))
PY
echo "E2E_TLS_512 PASS"
