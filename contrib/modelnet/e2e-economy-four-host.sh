#!/usr/bin/env bash
# ECON four-host: A creator, B index, C relay, D fresh. D never talks to A or B.
# Topology: A -- B -- C -- D
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CONTRIB="$ROOT/contrib/modelnet"
BASE="/tmp/btx-econ-4h-$$"
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
mkdir -p "$BASE/a" "$BASE/b" "$BASE/c" "$BASE/d"
pick() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORT_A="$(pick)"
PORT_B="$(pick)"
PORT_C="$(pick)"
"$BIN" -modeldir="$BASE/a" -modelstorage=8MiB -modelbind="127.0.0.1:${PORT_A}" \
  -modelrpcsocket="$BASE/a/modeld.sock" >"$BASE/a/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$BASE/b" -modelstorage=8MiB -modelbind="127.0.0.1:${PORT_B}" \
  -modelrpcsocket="$BASE/b/modeld.sock" >"$BASE/b/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$BASE/c" -modelstorage=8MiB -modelbind="127.0.0.1:${PORT_C}" \
  -modelrpcsocket="$BASE/c/modeld.sock" >"$BASE/c/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$BASE/d" -modelstorage=8MiB \
  -modelrpcsocket="$BASE/d/modeld.sock" >"$BASE/d/modeld.log" 2>&1 &
PIDS+=($!)
python3 - "$BASE" "$PORT_A" "$PORT_B" "$PORT_C" "$CONTRIB" "${PIDS[0]}" "${PIDS[1]}" "${PIDS[2]}" "${PIDS[3]}" <<'PY'
import json, socket, sys
from pathlib import Path
base = Path(sys.argv[1]); port_a = int(sys.argv[2]); port_b = int(sys.argv[3]); port_c = int(sys.argv[4])
sys.path.insert(0, sys.argv[5])
from failfast import wait_unix
pid_a, pid_b, pid_c, pid_d = int(sys.argv[6]), int(sys.argv[7]), int(sys.argv[8]), int(sys.argv[9])

def rpc(sock, method, params=None, timeout=40):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall((json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}) + "\n").encode())
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        ch = s.recv(1 << 20)
        if not ch:
            break
        data += ch
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

wait("a", pid_a); wait("b", pid_b); wait("c", pid_c); wait("d", pid_d)
a = base / "a" / "modeld.sock"
b = base / "b" / "modeld.sock"
c = base / "c" / "modeld.sock"
d = base / "d" / "modeld.sock"

def mid(tag):
    return f"{tag:02x}" + "00" * 47

rpc(a, "publishmodelsearchrecord", [mid(0x60), {
    "type": "btx-model-search-v1",
    "canonical_name": "FourHostCoder",
    "display_name": "FourHostCoder",
    "short_description": "specialized coding agent model",
    "expires_at": 0,
}])
rpc(a, "publishmodelsearchrecord", [mid(0x61), {
    "type": "btx-model-search-v1",
    "canonical_name": "FourHostCampaign",
    "display_name": "FourHostCampaign",
    "short_description": "advanced repository maintenance and autonomous coding campaign",
    "release_id": "dd" * 48,
    "release_state": "FUNDING",
    "release_target_atoms": 50000000000,
    "key_hash": "cd" + "00" * 31,
    "refund_height": 200,
    "expires_at": 0,
}])

rpc(b, "addmodelindex", [f"127.0.0.1:{port_a}"])
rpc(b, "addmodelnode", [f"127.0.0.1:{port_a}"])
if not (rpc(b, "searchmodels", [{"text": "coding", "scope": "NETWORK"}]).get("results") or []):
    raise SystemExit("B did not learn from A")
rpc(b, "getmodelfeed", [{"scope": "NETWORK", "mode": "NEWEST", "limit": 50}])
rpc(c, "addmodelindex", [f"127.0.0.1:{port_b}"])
rpc(c, "addmodelnode", [f"127.0.0.1:{port_b}"])
if not (rpc(c, "searchmodels", [{"text": "coding agent", "scope": "NETWORK"}]).get("results") or []):
    raise SystemExit("C did not learn from B")
rpc(c, "getmodelfeed", [{"scope": "NETWORK", "mode": "NEW_RELEASE_CAMPAIGNS", "limit": 50}])
rpc(d, "addmodelindex", [f"127.0.0.1:{port_c}"])
rpc(d, "addmodelnode", [f"127.0.0.1:{port_c}"])

sm = rpc(d, "searchmodels", [{"text": "coding agent", "scope": "NETWORK"}])
names = [str(h.get("name") or "") for h in (sm.get("results") or [])]
if "FourHostCoder" not in names:
    raise SystemExit(f"D miss public {names} {sm}")
sm2 = rpc(d, "searchmodels", [{"text": "repository maintenance", "scope": "NETWORK"}])
names2 = [str(h.get("name") or "") for h in (sm2.get("results") or [])]
if "FourHostCampaign" not in names2:
    raise SystemExit(f"D miss campaign {names2}")
feed = rpc(d, "getmodelfeed", [{"scope": "NETWORK", "mode": "NEWEST", "limit": 50}])
rr = rpc(d, "getrecentreleases", [{"scope": "NETWORK", "limit": 50}])
if not (rr.get("results") or rr.get("items") or feed.get("items")):
    raise SystemExit(f"D feed/releases empty feed={feed} rr={rr}")
print("ECON four-host D discovery PASS", names, names2, flush=True)
print("E2E_ECONOMY_FOUR_HOST PASS", flush=True)
PY
echo "e2e-economy-four-host: PASS"
