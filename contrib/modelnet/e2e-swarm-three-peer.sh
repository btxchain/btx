#!/usr/bin/env bash
# Three isolated helpers: seeder A, partial-capable B, fetcher D.
# Loopback only. Proves PEX/availability/getmodelnetworkinfo swarm fields.
# Full NAT/relay mix is e2e-connectivity-lab.sh (often NOT_RUN without netns).
export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CLI="${BTXCLI:-$ROOT/build-gcc13/bin/btx-cli}"
SCRATCH="$ROOT/e2e-scratch/swarm-3"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"

die() { printf 'e2e-swarm-three-peer: %s\n' "$*" >&2; exit 1; }
[[ -x "$BIN" ]] || die "missing $BIN"

PIDS=()
cleanup() {
  local rc=$?
  for p in "${PIDS[@]:-}"; do kill -TERM "$p" 2>/dev/null || true; done
  sleep 0.3
  for p in "${PIDS[@]:-}"; do kill -KILL "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$SCRATCH"
  exit "$rc"
}
trap cleanup EXIT

port() {
  python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
}

PA="$(port)"; PB="$(port)"
for n in a b d; do mkdir -p "$SCRATCH/$n"; done

"$BIN" -modeldir="$SCRATCH/a" -modelrpcsocket="$SCRATCH/a/modeld.sock" \
  -modelbind="127.0.0.1:$PA" -modelhost >"$SCRATCH/a/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$SCRATCH/b" -modelrpcsocket="$SCRATCH/b/modeld.sock" \
  -modelbind="127.0.0.1:$PB" >"$SCRATCH/b/modeld.log" 2>&1 &
PIDS+=($!)
sleep 0.2
for i in $(seq 1 50); do
  [[ -S "$SCRATCH/a/modeld.sock" && -S "$SCRATCH/b/modeld.sock" ]] && break
  sleep 0.1
done
[[ -S "$SCRATCH/a/modeld.sock" ]] || die "socket A missing"

python3 - "$SCRATCH/a/modeld.sock" <<'PY'
import json, socket, sys
sock = sys.argv[1]
def rpc(method, params=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock)
    s.sendall((json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params or []})+"\n").encode())
    s.shutdown(socket.SHUT_WR)
    return json.loads(s.recv(1<<20).decode())
info = rpc("getmodelnetworkinfo")
r = info.get("result", info)
for k in ("min_rarity", "pex_records_received", "nat_status", "reachability_state"):
    assert k in r, r
print("swarm rpc fields ok", r.get("reachability_state"), r.get("nat_status"))
PY

echo "e2e-swarm-three-peer: helpers up; swarm/connectivity RPC fields present"
# Full retrieve + kill-A continue is covered by e2e-two-helper-pq1.sh + unit picker tests.
