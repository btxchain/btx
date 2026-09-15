#!/usr/bin/env bash
# ECON-SEARCH-01/02/03: description-only local + WAN search; public+funding mix.
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
CONTRIB="$ROOT/contrib/modelnet"
BASE="/tmp/btx-econ-search-$$"
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
mkdir -p "$BASE/pub" "$BASE/searcher"
pick() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORT="$(pick)"
"$BIN" -modeldir="$BASE/pub" -modelstorage=8MiB -modelbind="127.0.0.1:${PORT}" \
  -modelrpcsocket="$BASE/pub/modeld.sock" >"$BASE/pub/modeld.log" 2>&1 &
PIDS+=($!)
"$BIN" -modeldir="$BASE/searcher" -modelstorage=8MiB \
  -modelrpcsocket="$BASE/searcher/modeld.sock" >"$BASE/searcher/modeld.log" 2>&1 &
PIDS+=($!)
python3 - "$BASE" "$PORT" "$CONTRIB" "${PIDS[0]}" "${PIDS[1]}" <<'PY'
import json, socket, sys
from pathlib import Path
base = Path(sys.argv[1])
port = int(sys.argv[2])
sys.path.insert(0, sys.argv[3])
from failfast import wait_unix
pid_pub, pid_s = int(sys.argv[4]), int(sys.argv[5])

def rpc(sock, method, params=None, timeout=30):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall((json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params or []})+"\n").encode())
    s.shutdown(socket.SHUT_WR)
    data=b""
    while True:
        c=s.recv(1<<20)
        if not c: break
        data+=c
        if b"\n" in data: break
    s.close()
    m=json.loads(data.decode())
    if m.get("error"): raise SystemExit(f"{method}: {m['error']}")
    return m["result"]

def wait(name, pid):
    sock = base/name/"modeld.sock"
    def connect():
        i=rpc(sock,"getmodelnetworkinfo",[])
        return i if i.get("helper_ready") else None
    return wait_unix(connect, timeout=20, pid=pid, log=base/name/"modeld.log")

wait("pub", pid_pub)
wait("searcher", pid_s)
pub = base/"pub"/"modeld.sock"
cli = base/"searcher"/"modeld.sock"

def mid(tag):
    return f"{tag:02x}" + "00"*47

# ECON-SEARCH-01: name A17, phrase only in description
rpc(pub, "publishmodelsearchrecord", [mid(0xA1), {
    "type":"btx-model-search-v1",
    "canonical_name":"A17",
    "display_name":"A17",
    "short_description":"A specialized model for coding agents and repository tool use.",
    "expires_at":0,
}])
# ECON-SEARCH-03 mix
rpc(pub, "publishmodelsearchrecord", [mid(0xA3), {
    "type":"btx-model-search-v1",
    "canonical_name":"PubCoder",
    "display_name":"PubCoder",
    "short_description":"coding",
    "release_state":"PUBLIC",
    "expires_at":0,
}])
rpc(pub, "publishmodelsearchrecord", [mid(0xA4), {
    "type":"btx-model-search-v1",
    "canonical_name":"FundCoder",
    "display_name":"FundCoder",
    "short_description":"coding",
    "release_id": "bb"*48,
    "release_state":"FUNDING",
    "release_target_atoms": 50000000000,
    "expires_at":0,
}])

loc = rpc(pub, "searchmodels", [{"text":"coding agent","scope":"LOCAL"}])
names=[str(h.get("name") or "") for h in (loc.get("results") or [])]
if "A17" not in names:
    raise SystemExit(f"ECON-SEARCH-01 local miss: {names}")
print("ECON-SEARCH-01 PASS", flush=True)

rpc(cli, "addmodelindex", [f"127.0.0.1:{port}"])
rpc(cli, "addmodelnode", [f"127.0.0.1:{port}"])
net = rpc(cli, "searchmodels", [{"text":"coding agent","scope":"NETWORK"}])
n2=[str(h.get("name") or "") for h in (net.get("results") or [])]
if "A17" not in n2:
    raise SystemExit(f"ECON-SEARCH-02 WAN miss: {n2} {net}")
print("ECON-SEARCH-02 PASS", n2, flush=True)

mix = rpc(cli, "searchmodels", [{"text":"coding","scope":"NETWORK"}])
types=set()
for h in mix.get("results") or []:
    types.add(str(h.get("result_type") or ""))
    acts=h.get("actions") or []
    rt=str(h.get("result_type") or "")
    if rt=="PUBLIC_MODEL" and "DOWNLOAD" not in acts:
        raise SystemExit(f"ECON-ACTION-01 missing DOWNLOAD: {h}")
    if rt=="RELEASE_CAMPAIGN" and "FUND_RELEASE" not in acts:
        raise SystemExit(f"ECON-ACTION-02 missing FUND_RELEASE: {h}")
if "PUBLIC_MODEL" not in types or "RELEASE_CAMPAIGN" not in types:
    raise SystemExit(f"ECON-SEARCH-03 mix: {types} {mix}")
print("ECON-SEARCH-03 PASS", types, flush=True)
print("E2E_ECONOMY_SEARCH PASS", flush=True)
PY
echo "e2e-economy-search: PASS"
