#!/usr/bin/env bash
# LOCAL-04/05: quota 0 stores no payload; positive -modelstorage enables import.
# Fail-fast. Not production.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch/firstrun"
die() { echo "e2e-firstrun: $*" >&2; exit 1; }
PID=""
cleanup() { local rc=$?; [[ -n "$PID" ]] && kill -TERM "$PID" 2>/dev/null || true; exit $rc; }
trap cleanup EXIT
[[ -x "$BIN" ]] || die "missing $BIN"
rm -rf "$SCRATCH"; mkdir -p "$SCRATCH/zero" "$SCRATCH/pos" "$SCRATCH/src"
python3 -c 'import struct; from pathlib import Path; Path("'"$SCRATCH"'/src/model.safetensors").write_bytes(struct.pack("<Q",2)+b"{}")'
# quota 0: explicit -modelstorage=0 (omitting the flag is AUTO on standalone modeld)
"$BIN" -modeldir="$SCRATCH/zero" -modelstorage=0 -modelrpcsocket="$SCRATCH/zero/modeld.sock" >"$SCRATCH/zero.log" 2>&1 &
PID=$!
python3 - "$SCRATCH/zero/modeld.sock" "$SCRATCH/src" "$PID" "$SCRATCH/zero.log" "$ROOT/contrib/modelnet" <<'PY'
import json,socket,sys
from pathlib import Path
sock,src,pid,log=Path(sys.argv[1]),Path(sys.argv[2]),int(sys.argv[3]),Path(sys.argv[4])
sys.path.insert(0, sys.argv[5])
from failfast import wait_unix
def raw(method, params):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(10)
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
    return json.loads(data.decode())
def connect():
    r=raw("getmodelnetworkinfo",[])
    if r.get("error"): raise RuntimeError(r["error"])
    info=r.get("result") or {}
    return info if info.get("helper_ready") else None
info=wait_unix(connect, timeout=20, pid=pid, log=log)
quota=int(info.get("quota_bytes") or 0)
if quota!=0:
    raise SystemExit("quota0 expected 0 got %s"%quota)
r=raw("importmodel",[str(src)])
if not r.get("error"):
    raise SystemExit("import with quota 0 must fail: %s"%r)
print("FIRSTRUN quota0 import refused", r["error"])
PY
kill -TERM "$PID" 2>/dev/null || true
for _ in $(seq 1 20); do kill -0 "$PID" 2>/dev/null || break; sleep 0.05; done
PID=""
"$BIN" -modeldir="$SCRATCH/pos" -modelstorage=8MiB -modelrpcsocket="$SCRATCH/pos/modeld.sock" >"$SCRATCH/pos.log" 2>&1 &
PID=$!
python3 - "$SCRATCH/pos/modeld.sock" "$SCRATCH/src" "$PID" "$SCRATCH/pos.log" "$ROOT/contrib/modelnet" <<'PY'
import json,socket,sys
from pathlib import Path
sock,src,pid,log=Path(sys.argv[1]),Path(sys.argv[2]),int(sys.argv[3]),Path(sys.argv[4])
sys.path.insert(0, sys.argv[5])
from failfast import wait_unix
def rpc(method, params):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(15)
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
    msg=json.loads(data.decode())
    if msg.get("error"): raise SystemExit("%s: %s"%(method,msg["error"]))
    return msg["result"]
def connect():
    i=rpc("getmodelnetworkinfo",[])
    return i if i.get("helper_ready") else None
wait_unix(connect, timeout=20, pid=pid, log=log)
imp=rpc("importmodel",[str(src)])
if imp.get("seeded") is not True: raise SystemExit(imp)
print("FIRSTRUN positive-budget import PASS", imp.get("uri"))
PY

# User-local OS handler into scratch XDG_DATA_HOME. No real sudo/pkexec.
OPEN="${BIN%/*}/btx-open"
[[ -x "$OPEN" ]] || die "missing $OPEN"
XDG_SCRATCH="$SCRATCH/xdg-data"
CFG_SCRATCH="$SCRATCH/xdg-config"
FAKEBIN="$SCRATCH/fakebin"
rm -rf "$XDG_SCRATCH" "$CFG_SCRATCH" "$FAKEBIN"
mkdir -p "$XDG_SCRATCH" "$CFG_SCRATCH" "$FAKEBIN"
cat >"$FAKEBIN/sudo" <<'EOF'
#!/bin/sh
echo "e2e-firstrun: sudo must not run" >&2
exit 1
EOF
cat >"$FAKEBIN/pkexec" <<'EOF'
#!/bin/sh
echo "e2e-firstrun: pkexec must not run" >&2
exit 1
EOF
chmod +x "$FAKEBIN/sudo" "$FAKEBIN/pkexec"
XDG_DATA_HOME="$XDG_SCRATCH" XDG_CONFIG_HOME="$CFG_SCRATCH" \
  BTX_OPEN="$OPEN" INSTALL_SYSTEM=0 PATH="$FAKEBIN:$PATH" \
  "$ROOT/contrib/modelnet/install-os-handler.sh"
DESK="$XDG_SCRATCH/applications/btx-open.desktop"
[[ -f "$DESK" ]] || die "os-handler desktop missing"
grep -q 'MimeType=x-scheme-handler/btx;' "$DESK" || die "os-handler mime"
exec_line="$(grep -E '^Exec=' "$DESK")"
[[ "$exec_line" == "Exec=$OPEN %u" || "$exec_line" == "Exec=\"$OPEN\" %u" ]] || \
  die "os-handler Exec=$exec_line"
if printf '%s\n' "$exec_line" | grep -Eq '^Exec=(sh|bash|dash|zsh)( |$)'; then
  die "os-handler Exec must not be a shell"
fi
echo "E2E_FIRSTRUN PASS"
