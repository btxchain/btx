#!/usr/bin/env bash
# CONN-NAT-01: AttemptModelPortMap good-weather via a local PCP/NAT-PMP mock.
# Never talks to the real default gateway (BTX_MODEL_PCP_GATEWAY=127.0.0.1).
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
TEST="${TEST_BTX:-$ROOT/build-gcc13/bin/test_btx}"
SCRATCH="$ROOT/e2e-scratch/conn-pcp"
PIDS=()
die() { printf 'e2e-conn-nat-pcp: %s\n' "$*" >&2; exit 1; }
cleanup() {
  local rc=$?
  for p in "${PIDS[@]:-}"; do kill -TERM "$p" 2>/dev/null || true; done
  sleep 0.2
  for p in "${PIDS[@]:-}"; do kill -KILL "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$SCRATCH"
  exit "$rc"
}
trap cleanup EXIT
[[ -x "$BIN" ]] || die "missing $BIN"
[[ -x "$TEST" ]] || die "missing $TEST"

echo "== unit PCP/NAT-PMP good-weather =="
"$TEST" --run_test=pcp_tests

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/h"

python3 - "$SCRATCH/pcp.log" <<'PY' &
import socket, struct, sys, time
from pathlib import Path
log = Path(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 5351))
s.settimeout(0.5)
log.write_text("listening 127.0.0.1:5351\n")
end = time.time() + 25
while time.time() < end:
    try:
        data, addr = s.recvfrom(2048)
    except socket.timeout:
        continue
    if not data:
        continue
    log.write_text(log.read_text() + f"pkt {len(data)} from {addr}\n")
    if data[0] == 2 and len(data) >= 60:
        resp = bytearray(60)
        resp[0] = 2
        resp[1] = 0x81
        resp[3] = 0
        struct.pack_into(">I", resp, 4, 500)
        resp[24:36] = data[24:36]
        resp[36] = data[36]
        resp[40:44] = data[40:44]
        resp[44:48] = bytes([0, 0, 0xFF, 0xFF]) + bytes([198, 51, 100, 8])
        # assigned external IPv4-mapped at offset 44 (PCP_HDR 24 + MAP_EXTERNAL_IP 20)
        resp[24 + 20 : 24 + 36] = bytes.fromhex("00000000000000000000ffffc6336408")
        s.sendto(bytes(resp), addr)
    elif data[0] == 0:
        if len(data) >= 2 and data[1] == 0:
            # NAT-PMP get external
            resp = bytes([0, 0x80, 0, 0, 0, 0, 0, 1, 198, 51, 100, 8])
            s.sendto(resp, addr)
        elif len(data) >= 2 and data[1] == 2:
            iport = data[4:6] if len(data) >= 6 else b"\x00\x00"
            eport = data[6:8] if len(data) >= 8 else iport
            resp = bytes([0, 0x82, 0, 0, 0, 0, 0, 1]) + iport + eport + b"\x00\x00\x01\xf4"
            s.sendto(resp, addr)
s.close()
PY
PIDS+=($!)
sleep 0.2

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
export BTX_MODEL_PCP_LAB=1
export BTX_MODEL_PCP_GATEWAY=127.0.0.1
"$BIN" -modeldir="$SCRATCH/h" -modelstorage=8MiB -modelbind="127.0.0.1:${PORT}" \
  -modelrpcsocket="$SCRATCH/h/modeld.sock" >"$SCRATCH/h/modeld.log" 2>&1 &
PIDS+=($!)
HPID=$!

python3 - "$SCRATCH/h/modeld.sock" "$HPID" "$ROOT/contrib/modelnet" <<'PY'
import json, socket, sys
from pathlib import Path
sock, pid = Path(sys.argv[1]), int(sys.argv[2])
sys.path.insert(0, sys.argv[3])
from failfast import wait_unix

def rpc(method, params=None, timeout=20):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}).encode() + b"\n")
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
    i = rpc("getmodelnetworkinfo")
    return i if i.get("helper_ready") else None

info = wait_unix(connect, timeout=20, pid=pid, log=sock.parent / "modeld.log")
print("nat_status", info.get("nat_status"), "external", info.get("mapped_endpoint") or info.get("nat_status"))
if info.get("nat_status") != "mapped":
    raise SystemExit("expected nat_status=mapped, got %s (log tail in modeld.log)" % info.get("nat_status"))
print("CONN-NAT-01 mapped PASS")
PY
echo "CONN-NAT-01 PASS"
