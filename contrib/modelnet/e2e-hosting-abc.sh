#!/usr/bin/env bash
# §28: A full seeder, B partial, C stock btxd (no model CLI flags) retrieves, pins, restarts.
# Isolated datadirs. Never production btxd.
set -euo pipefail
ROOT="${ROOT:-/home/administrator/btx-0.34.7-private}"
BIN="${BIN:-$ROOT/build-gcc13/bin}"
WORKDIR="${WORKDIR:-$ROOT/tmp-e2e-abc}"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
BTXD="$BIN/btxd"
CLI="$BIN/btx-cli"
MODELD="$BIN/btx-modeld"
test -x "$BTXD" && test -x "$CLI" && test -x "$MODELD"
PA="" PB="" PC=""
cleanup() {
  if [[ -n "${PC:-}" ]]; then
    "$CLI" -regtest -datadir="$WORKDIR/c" -rpcuser=u -rpcpassword=p stop >/dev/null 2>&1 || true
    sleep 0.5
    kill -TERM "$PC" 2>/dev/null || true
  fi
  for p in "$PA" "$PB"; do [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true; done
  sleep 0.3
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

pick() { python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORTA="$(pick)"; PORTB="$(pick)"
mkdir -p "$WORKDIR/src" "$WORKDIR/a" "$WORKDIR/b" "$WORKDIR/c"
python3 - <<PY
import struct
from pathlib import Path
p=Path("$WORKDIR/src")
p.mkdir(parents=True, exist_ok=True)
hdr=b'{"__metadata__":{"t":"abc"}}'
(p/"model.safetensors").write_bytes(struct.pack("<Q", len(hdr))+hdr)
PY
"$MODELD" -modeldir="$WORKDIR/a" -modelstorage=16MiB -modelbind="127.0.0.1:${PORTA}" -modelhost \
  -modelrpcsocket="$WORKDIR/a/modeld.sock" >"$WORKDIR/a.log" 2>&1 &
PA=$!
"$MODELD" -modeldir="$WORKDIR/b" -modelstorage=16MiB -modelbind="127.0.0.1:${PORTB}" -modelhost \
  -modelrpcsocket="$WORKDIR/b/modeld.sock" >"$WORKDIR/b.log" 2>&1 &
PB=$!
python3 - "$WORKDIR" "$PA" "$PB" "$ROOT/contrib/modelnet" <<'PY'
import json, socket, sys
from pathlib import Path
root=Path(sys.argv[1]); pa,pb=int(sys.argv[2]),int(sys.argv[3])
sys.path.insert(0, sys.argv[4])
from failfast import wait_unix
def rpc(sock, method, params, timeout=20):
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(timeout)
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
    if m.get("error"): raise SystemExit("%s: %s"%(method,m["error"]))
    return m["result"]
def ready(path, pid, log):
    def c():
        i=rpc(path,"getmodelnetworkinfo",[])
        return i if i.get("helper_ready") else None
    return wait_unix(c, timeout=20, pid=pid, log=log)
sa, sb = root/"a/modeld.sock", root/"b/modeld.sock"
ready(sa, pa, root/"a.log")
ready(sb, pb, root/"b.log")
imp=rpc(sa,"importmodel",[str(root/"src"),{"pin":True}])
uri=imp["uri"]
rpc(sb,"importmodel",[str(root/"src"),{"pin":True}])
Path(root/"uri.txt").write_text(uri)
print(uri)
PY

URI="$(cat "$WORKDIR/uri.txt")"
# C: stock btxd, no model flags except isolated regtest
"$BTXD" -regtest -datadir="$WORKDIR/c" -listen=0 -server=1 -rpcuser=u -rpcpassword=p \
  -daemon=0 >"$WORKDIR/c-btxd.log" 2>&1 &
PC=$!
ok=0
for i in $(seq 1 80); do
  if "$CLI" -regtest -datadir="$WORKDIR/c" -rpcuser=u -rpcpassword=p getblockchaininfo >/dev/null 2>&1; then
    ok=1; break
  fi
  sleep 0.25
done
test "$ok" = 1
ready=0
for i in $(seq 1 80); do
  cinfo="$("$CLI" -regtest -datadir="$WORKDIR/c" -rpcuser=u -rpcpassword=p getmodelnetworkinfo)"
  echo "$cinfo" | grep -q '"helper_state": "READY"' && ready=1 && break
  sleep 0.25
done
test "$ready" = 1
echo "$cinfo"
echo "$cinfo" | grep -q '"helper_managed_by_btxd": true'
echo "$cinfo" | grep -q '"storage_mode": "AUTO"'
echo "$cinfo" | grep -q '"automatic_spend_atoms": 0'
"$CLI" -regtest -datadir="$WORKDIR/c" -rpcuser=u -rpcpassword=p addmodelnode "127.0.0.1:${PORTA}" >/dev/null
"$CLI" -regtest -datadir="$WORKDIR/c" -rpcuser=u -rpcpassword=p addmodelnode "127.0.0.1:${PORTB}" >/dev/null
got="$("$CLI" -regtest -datadir="$WORKDIR/c" -rpcuser=u -rpcpassword=p getmodel "$URI" FREE_ONLY)"
echo "$got"
python3 - "$got" "$CLI" "$WORKDIR/c" "$URI" <<'PY'
import json,sys,subprocess,time
got=json.loads(sys.argv[1])
cli, datadir, uri = sys.argv[2], sys.argv[3], sys.argv[4]
def rpc(*args):
    out=subprocess.check_output([cli,"-regtest","-datadir="+datadir,"-rpcuser=u","-rpcpassword=p",*args], text=True)
    return json.loads(out)
if got.get("job_id"):
    for _ in range(60):
        j=rpc("getmodeljob", got["job_id"])
        job=j
        if isinstance(j, dict) and j.get("jobs"):
            arr=j["jobs"]
            job=arr[-1]
            for e in arr:
                if str(e.get("job_id"))==str(got["job_id"]):
                    job=e
                    break
        st=job.get("status")
        if st in ("done","retrieved","local"):
            break
        if st=="failed":
            raise SystemExit(job)
        time.sleep(0.5)
    else:
        raise SystemExit("job timeout %s"%j)
listed=rpc("listmodels")
assert int(listed.get("local_count") or 0)>=1, listed
rpc("pinmodel", uri)
print("pin ok")
PY
"$CLI" -regtest -datadir="$WORKDIR/c" -rpcuser=u -rpcpassword=p stop >/dev/null
sleep 2
PC=""
"$BTXD" -regtest -datadir="$WORKDIR/c" -listen=0 -server=1 -rpcuser=u -rpcpassword=p \
  -daemon=0 >"$WORKDIR/c-btxd-2.log" 2>&1 &
PC=$!
ok=0
for i in $(seq 1 80); do
  if "$CLI" -regtest -datadir="$WORKDIR/c" -rpcuser=u -rpcpassword=p getblockchaininfo >/dev/null 2>&1; then
    ok=1; break
  fi
  sleep 0.25
done
test "$ok" = 1
listed="$("$CLI" -regtest -datadir="$WORKDIR/c" -rpcuser=u -rpcpassword=p listmodels)"
echo "$listed"
echo "$listed" | grep -q '"pinned": true'
"$CLI" -regtest -datadir="$WORKDIR/c" -rpcuser=u -rpcpassword=p stop >/dev/null
sleep 1
PC=""
echo "e2e-hosting-abc: PASS"
