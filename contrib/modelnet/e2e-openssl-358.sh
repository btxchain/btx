#!/usr/bin/env bash
# Second-process OpenSSL 3.5.8 PQ1. Never swaps production btxd.real.
# PQ-19: hostile OPENSSL_CONF cannot weaken PQ1. Fail-fast.
# Completeness: wrapped btx-modeld -version (or ldd) + getmodelnetworkinfo on a
# scratch unix socket proving libssl 3.5.8. Wrapped btxd -version only (no node).
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ -z "${OPENSSL358_PREFIX:-}" && -d "$HOME/.local/opt/openssl-3.5.8" ]]; then
  OPENSSL358_PREFIX="$HOME/.local/opt/openssl-3.5.8"
fi
PREFIX="${OPENSSL358_PREFIX:-$HOME/.local/opt/openssl-3.5.8}"
export OPENSSL358_PREFIX="$PREFIX"
export DEST="${DEST:-$ROOT/build-gcc13/openssl358-second}"
PROD_REAL="$HOME/.local/opt/btx-0.34.7-b094c6ba420f/libexec/btxd.real"
die() { echo "E2E_OPENSSL358 FAIL: $*" >&2; exit 1; }
[[ -x "$PREFIX/bin/openssl" ]] || die "missing $PREFIX"
if [[ "$(realpath -m "$DEST")" == "$(realpath -m "$(dirname "$PROD_REAL")")" ]]; then
  die "DEST must not be production libexec"
fi
bash "$ROOT/contrib/modelnet/relink-openssl-358.sh"
WRAP="$DEST"
[[ -x "$WRAP/btx-modeld" ]] || die "missing wrapped btx-modeld in $WRAP"
rm -rf "$ROOT/e2e-scratch/openssl358"
SCRATCH="$ROOT/e2e-scratch/openssl358"
mkdir -p "$SCRATCH"
export LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}"
ver="$("$PREFIX/bin/openssl" version)"
echo "$ver" | grep -q '3.5.8' || die "openssl not 3.5.8: $ver"
echo "$ver" | grep -q 'Library: OpenSSL 3.5.8' || die "library not 3.5.8: $ver"

ssl_map="$(ldd "$WRAP/btx-modeld.real" | grep libssl || true)"
echo "ldd btx-modeld.real libssl: $ssl_map"
echo "$ssl_map" | grep -q 'openssl-3.5.8' || die "btx-modeld.real not resolving libssl from 3.5.8: $ssl_map"

set +e
ver_modeld="$("$WRAP/btx-modeld" -version 2>&1)"
rc_ver=$?
set -e
echo "wrapped btx-modeld -version rc=$rc_ver"
echo "$ver_modeld"
if [[ "$rc_ver" -eq 0 ]]; then
  echo "$ver_modeld" | grep -q '3.5.8' || die "wrapped btx-modeld -version not 3.5.8"
else
  echo "btx-modeld -version not in this binary; proving 3.5.8 via ldd + getmodelnetworkinfo"
fi

if [[ -x "$WRAP/btxd" ]]; then
  if [[ -e "$PROD_REAL" ]]; then
    wrap_id="$(stat -c '%d:%i' "$WRAP/btxd.real" 2>/dev/null || true)"
    prod_id="$(stat -c '%d:%i' "$PROD_REAL" 2>/dev/null || true)"
    [[ "$wrap_id" != "$prod_id" ]] || die "wrapped btxd.real is production; abort"
  fi
  echo "wrapped btxd -version (second process; not a node start):"
  "$WRAP/btxd" -version 2>&1 | head -5
  btxd_ssl="$(ldd "$WRAP/btxd.real" | grep libssl || true)"
  echo "ldd btxd.real libssl: $btxd_ssl"
  echo "$btxd_ssl" | grep -q 'openssl-3.5.8' || die "btxd.real not resolving libssl from 3.5.8: $btxd_ssl"
fi

# PQ-19 hostile conf (X25519 + AES-128). Helper must still report MLKEM768.
cat >"$SCRATCH/hostile.cnf" <<'EOF'
openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_sect
[ssl_sect]
system_default = sys
[sys]
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=1
Groups = X25519
EOF
export OPENSSL_CONF="$SCRATCH/hostile.cnf"
export OPENSSL_MODULES="/nonexistent-pq19-modules"
export BTX_OPENSSL="$PREFIX/bin/openssl"

pick() { python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORT="$(pick)"
mkdir -p "$SCRATCH/a/src" "$SCRATCH/b"
python3 -c 'import struct; from pathlib import Path; Path("'"$SCRATCH"'/a/src/model.safetensors").write_bytes(struct.pack("<Q",2)+b"{}")'
PA=""; PB=""
cleanup() { for p in "$PB" "$PA"; do [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
"$WRAP/btx-modeld" -modeldir="$SCRATCH/a" -modelstorage=8MiB -modelbind="127.0.0.1:${PORT}" -modelhost -modelrpcsocket="$SCRATCH/a/modeld.sock" >"$SCRATCH/a.log" 2>&1 &
PA=$!
"$WRAP/btx-modeld" -modeldir="$SCRATCH/b" -modelstorage=8MiB -modelrpcsocket="$SCRATCH/b/modeld.sock" >"$SCRATCH/b.log" 2>&1 &
PB=$!
python3 - "$SCRATCH" "$PORT" "$PA" "$PB" "$ROOT/contrib/modelnet" <<'PY'
import json, os, socket, sys
from pathlib import Path
root, port, pa, pb = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
sys.path.insert(0, sys.argv[5])
from failfast import wait_unix, poll_job

def rpc(sock, method, params, timeout=20):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(timeout)
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
    if m.get("error"): raise SystemExit("%s: %s"%(method, m["error"]))
    return m["result"]

sa, sb = root/"a/modeld.sock", root/"b/modeld.sock"
wait_unix(lambda: rpc(sa,"getmodelnetworkinfo",[]) if (sa.exists()) else None, timeout=20, pid=pa, log=root/"a.log")
wait_unix(lambda: rpc(sb,"getmodelnetworkinfo",[]) if (sb.exists()) else None, timeout=20, pid=pb, log=root/"b.log")
info=rpc(sa,"getmodelnetworkinfo",[])
print("openssl", info.get("openssl"), "group", info.get("group"), "cipher", info.get("cipher"))
if "3.5.8" not in str(info.get("openssl")):
    raise SystemExit("helper not on 3.5.8: "+json.dumps(info))
if info.get("group")!="MLKEM768" or info.get("cipher")!="TLS_AES_256_GCM_SHA384":
    raise SystemExit("PQ-19 weakened: "+json.dumps(info))
if not info.get("pq1_ready"):
    raise SystemExit("pq1_ready false: "+json.dumps(info))
imp=rpc(sa,"importmodel",[str(root/"a/src"),{"pin":True}])
rpc(sb,"addmodelnode",[f"127.0.0.1:{port}"])
got=rpc(sb,"getmodel",[imp["uri"],"FREE_ONLY"])
if got.get("job_id"):
    poll_job(lambda: rpc(sb,"getmodeljob",[got["job_id"]]), timeout=30)
listed=rpc(sb,"listmodels",[])
if int(listed.get("local_count") or 0)<1:
    raise SystemExit(listed)
print("E2E_OPENSSL358 PASS", json.dumps({"openssl": info.get("openssl"), "group": info.get("group"), "uri": imp["uri"]}))
PY
echo "E2E_OPENSSL358 PASS (second-process wrap; production btxd.real untouched)"
