#!/usr/bin/env bash
# Remote side of e2e-two-wan.sh. Args: port1 port2
set -euo pipefail
PORT="$1"
PORT2="$2"
rm -rf /tmp/btx-twowan-a /tmp/btx-twowan-b /tmp/btx-twowan-f
mkdir -p /tmp/btx-twowan-a/src /tmp/btx-twowan-b /tmp/btx-twowan-f
cp /tmp/btx-twowan-model.safetensors /tmp/btx-twowan-a/src/model.safetensors
export LD_LIBRARY_PATH="${BTX_MODELD_LIB:+$BTX_MODELD_LIB:}${LD_LIBRARY_PATH:-}"
MODELD="${MODELD:-btx-modeld}"
if [[ -x "${BTX_MODELD_WRAPPER:-}" ]]; then MODELD="$BTX_MODELD_WRAPPER"; fi
if [[ -x /opt/btx-0347-rc/bin/run-modeld.sh ]]; then MODELD=/opt/btx-0347-rc/bin/run-modeld.sh
elif [[ -x /opt/btx-0347-rc/bin/btx-modeld ]]; then MODELD=/opt/btx-0347-rc/bin/btx-modeld
fi
nohup "$MODELD" -modeldir=/tmp/btx-twowan-a -modelstorage=80MiB -modelbind="127.0.0.1:${PORT}" -modelhost -modelrpcsocket=/tmp/btx-twowan-a/modeld.sock >/tmp/btx-twowan-a/modeld.log 2>&1 &
echo $! >/tmp/btx-twowan-a/modeld.pid
nohup "$MODELD" -modeldir=/tmp/btx-twowan-b -modelstorage=80MiB -modelbind="127.0.0.1:${PORT2}" -modelhost -modelrpcsocket=/tmp/btx-twowan-b/modeld.sock >/tmp/btx-twowan-b/modeld.log 2>&1 &
echo $! >/tmp/btx-twowan-b/modeld.pid
for i in $(seq 1 50); do
  [[ -S /tmp/btx-twowan-a/modeld.sock && -S /tmp/btx-twowan-b/modeld.sock ]] && break
  sleep 0.15
done
python3 -s <<'PY'
import json, socket
from pathlib import Path

def rpc(sock, method, params):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(30)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
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
        raise SystemExit(m["error"])
    return m["result"]

src = "/tmp/btx-twowan-a/src"
imp = rpc(Path("/tmp/btx-twowan-a/modeld.sock"), "importmodel", [src, {"pin": True}])
rpc(Path("/tmp/btx-twowan-b/modeld.sock"), "importmodel", [src, {"pin": True}])
Path("/tmp/btx-twowan-uri.txt").write_text(imp["uri"] + "\n")
print("imported", imp["uri"])
PY
nohup "$MODELD" -modeldir=/tmp/btx-twowan-f -modelstorage=80MiB -modelrpcsocket=/tmp/btx-twowan-f/modeld.sock >/tmp/btx-twowan-f/modeld.log 2>&1 &
echo $! >/tmp/btx-twowan-f/modeld.pid
for i in $(seq 1 40); do [[ -S /tmp/btx-twowan-f/modeld.sock ]] && break; sleep 0.15; done
python3 -s <<PY
import json, socket, time
from pathlib import Path
port, port2 = "$PORT", "$PORT2"

def rpc(sock, method, params, timeout=90):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
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
        raise SystemExit("%s: %s" % (method, m["error"]))
    return m["result"]

sf = Path("/tmp/btx-twowan-f/modeld.sock")
uri = Path("/tmp/btx-twowan-uri.txt").read_text().strip()
t1 = time.time()
while time.time() - t1 < 20:
    try:
        if rpc(sf, "getmodelnetworkinfo", []).get("helper_ready"):
            break
    except Exception:
        time.sleep(0.15)
else:
    raise SystemExit("fetcher helper not ready")
rpc(sf, "addmodelnode", ["127.0.0.1:" + port])
rpc(sf, "addmodelnode", ["127.0.0.1:" + port2])
peers = rpc(sf, "getmodelpeers", [])
got = rpc(sf, "getmodel", [uri, "FREE_ONLY"])
t0 = time.time()
while time.time() - t0 < 120:
    if got.get("status") in ("retrieved", "local"):
        break
    jid = got.get("job_id")
    if not jid:
        raise SystemExit(got)
    jobs = rpc(sf, "getmodeljob", [jid])
    arr = jobs.get("jobs") or []
    if arr:
        st = arr[0].get("status")
        if st == "failed":
            raise SystemExit("retrieve failed: " + json.dumps(arr[0]))
        if st == "done":
            break
    time.sleep(0.2)
listed = rpc(sf, "listmodels", [])
m = (listed.get("models") or [{}])[0]
got2 = rpc(sf, "getmodel", [uri, "FREE_ONLY"])
Path("/tmp/btx-twowan-result.json").write_text(json.dumps({
    "bytes": m.get("bytes"), "seeded": m.get("seeded"),
    "resume": got2.get("status"), "peer_count": len(peers.get("peers") or []),
}))
print("E2E_TWO_WAN_REMOTE PASS", Path("/tmp/btx-twowan-result.json").read_text())
PY
