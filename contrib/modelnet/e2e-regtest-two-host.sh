#!/usr/bin/env bash
# Isolated regtest btxd + btx-modeld on two hosts. Fail-fast.
# Never production btxd. Never granite seeder port. Never SIGKILL.
#
# Coordinator expands env, then ssh. Override with:
#   SEEDER_HOST FETCHER_HOST REGTEST_MODELD_PORT (default 29449, never 29448)
#   SEEDER_PROD_PIDS FETCHER_PROD_PIDS (required)
#   SEEDER_DIR SEEDER_BTXD SEEDER_CLI SEEDER_MODELD SEEDER_LD_LIBRARY_PATH
#   FETCHER_DIR FETCHER_BTXD FETCHER_CLI FETCHER_MODELD FETCHER_LD_LIBRARY_PATH
#
# FETCHER_* defaults with $HOME expand on the remote fetcher (then the
# coordinator substitutes that HOME so later ssh uses absolute paths).
#
#   SEEDER_HOST=... FETCHER_HOST=... SEEDER_PROD_PIDS=... FETCHER_PROD_PIDS=... \
#     contrib/modelnet/e2e-regtest-two-host.sh
set -euo pipefail
export LC_ALL=C

SEEDER="${SEEDER_HOST:?set SEEDER_HOST to SSH alias of the seeder}"
FETCHER="${FETCHER_HOST:?set FETCHER_HOST to SSH alias of the fetcher}"
MODELD_PORT="${REGTEST_MODELD_PORT:-29449}"
SEEDER_DIR="${SEEDER_DIR:-/opt/btx-0347-rc/regtest-e2e}"
FETCHER_DIR="${FETCHER_DIR:-\$HOME/.local/opt/btx-0.34.7-rc-regtest}"
SEEDER_BTXD="${SEEDER_BTXD:-/opt/btx-node/bin/btxd}"
SEEDER_CLI="${SEEDER_CLI:-${SEEDER_BTXD%/*}/btx-cli}"
SEEDER_MODELD="${SEEDER_MODELD:-/opt/btx-0347-rc/bin/btx-modeld}"
SEEDER_LD_LIBRARY_PATH="${SEEDER_LD_LIBRARY_PATH:-/opt/btx-0347-rc/lib}"
FETCHER_BTXD="${FETCHER_BTXD:-\$HOME/.local/opt/btx-0.34.7-b094c6ba420f/bin/btxd}"
FETCHER_CLI="${FETCHER_CLI:-${FETCHER_BTXD%/*}/btx-cli}"
FETCHER_MODELD="${FETCHER_MODELD:-\$HOME/.local/opt/btx-0.34.7-rc-modeld/bin/btx-modeld}"
FETCHER_LD_LIBRARY_PATH="${FETCHER_LD_LIBRARY_PATH:-\$HOME/.local/opt/btx-0.34.7-rc-modeld/lib}"
# Dedicated ports: never share 18443/18444 with the lab /var/lib/btxd node.
SEEDER_P2P="${SEEDER_P2P:-38044}"
SEEDER_RPC="${SEEDER_RPC:-38043}"
FETCHER_P2P="${FETCHER_P2P:-38144}"
FETCHER_RPC="${FETCHER_RPC:-38143}"
PROD_SEEDER="${SEEDER_PROD_PIDS:?set SEEDER_PROD_PIDS}"
PROD_FETCHER="${FETCHER_PROD_PIDS:?set FETCHER_PROD_PIDS}"

die() { echo "E2E_REGTEST_TWO FAIL: $*" >&2; cleanup || true; exit 1; }
TUNNEL_S=""
TUNNEL_F=""
cleanup() {
  [[ -n "${TUNNEL_S}" ]] && kill -TERM "$TUNNEL_S" 2>/dev/null || true
  [[ -n "${TUNNEL_F}" ]] && kill -TERM "$TUNNEL_F" 2>/dev/null || true
  ssh -o BatchMode=yes "$SEEDER" "for f in ${SEEDER_DIR}/btxd.pid ${SEEDER_DIR}/modeld.pid; do [[ -f \$f ]] && kill -TERM \$(cat \$f) 2>/dev/null || true; done" || true
  ssh -o BatchMode=yes "$FETCHER" "for f in ${FETCHER_DIR}/btxd.pid ${FETCHER_DIR}/modeld.pid; do [[ -f \$f ]] && kill -TERM \$(cat \$f) 2>/dev/null || true; done" || true
}
trap 'rc=$?; cleanup; exit $rc' EXIT

if [[ "${MODELD_PORT}" == "29448" ]]; then
  die "REFUSE granite seeder port 29448; set REGTEST_MODELD_PORT (default 29449)"
fi

# Coordinator expands remote $HOME, then every later ssh uses absolute paths.
expand_dollar_home() {
  local host="$1"
  shift
  local need=0 n
  for n in "$@"; do
    if [[ "${!n}" == *'$HOME'* ]]; then
      need=1
      break
    fi
  done
  [[ "$need" -eq 1 ]] || return 0
  local rh
  rh="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" "printf '%s' \"\$HOME\"")" \
    || die "cannot read HOME on $host"
  [[ -n "$rh" ]] || die "empty HOME on $host"
  local v
  for n in "$@"; do
    v="${!n}"
    v="${v//\$HOME/$rh}"
    printf -v "$n" '%s' "$v"
  done
}
expand_dollar_home "$FETCHER" FETCHER_DIR FETCHER_BTXD FETCHER_CLI FETCHER_MODELD FETCHER_LD_LIBRARY_PATH

prod_up() {
  local host="$1" pids="$2"
  local have
  have="$(ssh -o BatchMode=yes "$host" "ps -p ${pids} -o pid=" || true)"
  local p
  IFS=',' read -r -a want <<<"$pids"
  for p in "${want[@]}"; do
    [[ -n "$p" ]] || continue
    echo "$have" | grep -q "$p" || die "$host production pid $p is gone"
  done
}

echo "== production PIDs must remain =="
prod_up "$SEEDER" "$PROD_SEEDER"
prod_up "$FETCHER" "$PROD_FETCHER"

echo "== start isolated regtest btxd + modeld =="
ssh -o BatchMode=yes "$SEEDER" "bash -s" <<EOF
set -euo pipefail
DIR="${SEEDER_DIR}"
BTXD="${SEEDER_BTXD}"
MODELD="${SEEDER_MODELD}"
LDLIB="${SEEDER_LD_LIBRARY_PATH}"
PORT="${MODELD_PORT}"
[[ -x "\$BTXD" ]] || { echo "missing btxd \$BTXD" >&2; exit 1; }
[[ -x "\$MODELD" ]] || { echo "missing modeld \$MODELD" >&2; exit 1; }
if [[ -n "\$LDLIB" ]]; then
  [[ -d "\$LDLIB" ]] || { echo "missing libdir \$LDLIB" >&2; exit 1; }
  export LD_LIBRARY_PATH="\$LDLIB\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
fi
rm -rf "\$DIR"
mkdir -p "\$DIR/btxd" "\$DIR/modeld" "\$DIR/src"
python3 -c "import struct; from pathlib import Path; Path('\$DIR/src/model.safetensors').write_bytes(struct.pack('<Q', 2)+b'{}')"
nohup "\$BTXD" -regtest -datadir="\$DIR/btxd" -server \\
  -listen=0 -port=${SEEDER_P2P} -rpcport=${SEEDER_RPC} -rpcuser=regtest -rpcpassword=regtest \\
  -fallbackfee=0.0002 -disablewallet \\
  -regtestmatmulbindingheight=2147483647 \\
  -regtestmatmulproductdigestheight=2147483647 \\
  -regtestmatmulv4height=2147483647 \\
  -regtestmatmulrequireproductpayload=0 \\
  >"\$DIR/btxd.log" 2>&1 &
echo \$! > "\$DIR/btxd.pid"
nohup "\$MODELD" \\
  -modeldir="\$DIR/modeld" \\
  -modelstorage=80MiB \\
  -modelbind=127.0.0.1:\$PORT \\
  -modelhost \\
  -modelrpcsocket="\$DIR/modeld/modeld.sock" \\
  >"\$DIR/modeld.log" 2>&1 &
echo \$! > "\$DIR/modeld.pid"
EOF

ssh -o BatchMode=yes "$FETCHER" "bash -s" <<EOF
set -euo pipefail
DIR="${FETCHER_DIR}"
BTXD="${FETCHER_BTXD}"
MODELD="${FETCHER_MODELD}"
LDLIB="${FETCHER_LD_LIBRARY_PATH}"
[[ -x "\$BTXD" ]] || { echo "missing btxd \$BTXD" >&2; exit 1; }
[[ -x "\$MODELD" ]] || { echo "missing modeld \$MODELD" >&2; exit 1; }
if [[ -n "\$LDLIB" ]]; then
  [[ -d "\$LDLIB" ]] || { echo "missing libdir \$LDLIB" >&2; exit 1; }
  export LD_LIBRARY_PATH="\$LDLIB\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
fi
rm -rf "\$DIR"
mkdir -p "\$DIR/btxd" "\$DIR/modeld"
nohup "\$BTXD" -regtest -datadir="\$DIR/btxd" -server \\
  -listen=0 -port=${FETCHER_P2P} -rpcport=${FETCHER_RPC} -rpcuser=regtest -rpcpassword=regtest \\
  -fallbackfee=0.0002 -disablewallet \\
  -regtestmatmulbindingheight=2147483647 \\
  -regtestmatmulproductdigestheight=2147483647 \\
  -regtestmatmulv4height=2147483647 \\
  -regtestmatmulrequireproductpayload=0 \\
  >"\$DIR/btxd.log" 2>&1 &
echo \$! > "\$DIR/btxd.pid"
# fetcher: no -modelseed=auto (prove default). OpenSSL 3.5 via FETCHER_LD_LIBRARY_PATH.
nohup "\$MODELD" \\
  -modeldir="\$DIR/modeld" \\
  -modelstorage=80MiB \\
  -modelrpcsocket="\$DIR/modeld/modeld.sock" \\
  >"\$DIR/modeld.log" 2>&1 &
echo \$! > "\$DIR/modeld.pid"
EOF

wait_sock() {
  local host="$1" path="$2" pidfile="$3" log="$4"
  local i out
  for i in $(seq 1 40); do
    out="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" \
      "if [ -f $pidfile ] && ! kill -0 \$(cat $pidfile) 2>/dev/null; then echo DEAD; tail -n 40 $log; elif [ -S $path ]; then echo READY; fi")" \
      || die "$host ssh failed waiting for $path"
    if printf '%s\n' "$out" | grep -q '^READY$'; then return 0; fi
    if printf '%s\n' "$out" | grep -q '^DEAD$'; then
      printf '%s\n' "$out" >&2
      die "$host helper died before socket: $path"
    fi
    sleep 0.15
  done
  ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" "tail -n 40 $log" >&2 || true
  die "$host socket not ready: $path"
}
wait_sock "$SEEDER" "${SEEDER_DIR}/modeld/modeld.sock" "${SEEDER_DIR}/modeld.pid" "${SEEDER_DIR}/modeld.log"
wait_sock "$FETCHER" "${FETCHER_DIR}/modeld/modeld.sock" "${FETCHER_DIR}/modeld.pid" "${FETCHER_DIR}/modeld.log"

wait_rpc() {
  local host="$1" cli="$2" datadir="$3" rpcport="$4" pidfile="$5" log="$6"
  local i out
  for i in $(seq 1 25); do
    out="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" \
      "if [ -f $pidfile ] && ! kill -0 \$(cat $pidfile) 2>/dev/null; then echo DEAD; tail -n 40 $log; exit 2; fi
       $cli -regtest -datadir=$datadir -rpcport=$rpcport -rpcuser=regtest -rpcpassword=regtest getblockchaininfo")" \
      && { printf '%s\n' "$out"; return 0; } || true
    if printf '%s\n' "$out" | grep -q '^DEAD$'; then
      printf '%s\n' "$out" >&2
      die "$host btxd died before RPC"
    fi
    sleep 0.2
  done
  ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" "tail -n 40 $log" >&2 || true
  die "$host btxd RPC :$rpcport not ready"
}

echo "== isolated monetary nodes =="
SEED_CHAIN="$(wait_rpc "$SEEDER" "${SEEDER_CLI}" "${SEEDER_DIR}/btxd" "$SEEDER_RPC" "${SEEDER_DIR}/btxd.pid" "${SEEDER_DIR}/btxd.log")"
echo "$SEED_CHAIN" | python3 -c 'import json,sys; i=json.load(sys.stdin); assert i.get("chain")=="regtest", i; print("seeder", i["chain"], "blocks", i.get("blocks"))' || die "seeder not regtest: $SEED_CHAIN"
FETCH_CHAIN="$(wait_rpc "$FETCHER" "${FETCHER_CLI}" "${FETCHER_DIR}/btxd" "$FETCHER_RPC" "${FETCHER_DIR}/btxd.pid" "${FETCHER_DIR}/btxd.log")"
echo "$FETCH_CHAIN" | python3 -c 'import json,sys; i=json.load(sys.stdin); assert i.get("chain")=="regtest", i; print("fetcher", i["chain"], "blocks", i.get("blocks"))' || die "fetcher not regtest: $FETCH_CHAIN"

echo "== SSH tunnel seeder:${MODELD_PORT} -> fetcher:127.0.0.1:${MODELD_PORT} =="
ssh -o BatchMode=yes -N -L "127.0.0.1:${MODELD_PORT}:127.0.0.1:${MODELD_PORT}" "$SEEDER" &
TUNNEL_S=$!
ssh -o BatchMode=yes -N -R "127.0.0.1:${MODELD_PORT}:127.0.0.1:${MODELD_PORT}" "$FETCHER" &
TUNNEL_F=$!
sleep 0.5
kill -0 "$TUNNEL_S" 2>/dev/null || die "seeder tunnel died"
kill -0 "$TUNNEL_F" 2>/dev/null || die "fetcher tunnel died"

echo "== import on seeder (demand-seed, no seedmodel) =="
URI="$(ssh -o BatchMode=yes "$SEEDER" "DIR=${SEEDER_DIR} python3 -s" <<'PY'
import json, os, socket, sys
from pathlib import Path
sock = Path(os.environ["DIR"]) / "modeld" / "modeld.sock"

def rpc(method, params):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(str(sock))
    s.sendall((json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}) + "\n").encode())
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
    msg = json.loads(data.decode())
    if msg.get("error"):
        sys.exit(str(msg["error"]))
    return msg.get("result") or {}

prop = (rpc("getmodelnetworkinfo", []) or {}).get("propagation") or {}
if not prop.get("demand_propagation"):
    sys.exit("demand_propagation false: " + json.dumps(prop))
if prop.get("seed_upon_download_opt_in"):
    sys.exit("seed_upon_download still opt-in")
imp = rpc("importmodel", [str(Path(os.environ["DIR"]) / "src"), {"pin": True}])
if imp.get("seeded") is not True:
    sys.exit("import not demand-seeded: " + json.dumps(imp))
print(imp["uri"])
PY
)"
[[ "$URI" == btx://* ]] || die "import uri: $URI"
echo "uri $URI"

echo "== getmodel on fetcher (15s fail-fast) =="
if ! ssh -o BatchMode=yes "$FETCHER" "DIR=${FETCHER_DIR} URI='$URI' PORT=${MODELD_PORT} python3 -s" <<'PY'
import json, os, socket, sys, time
from pathlib import Path
sock = Path(os.environ["DIR"]) / "modeld" / "modeld.sock"
uri = os.environ["URI"]
port = os.environ["PORT"]

def rpc(method, params, timeout=15):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall((json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}) + "\n").encode())
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
    msg = json.loads(data.decode())
    if msg.get("error"):
        sys.exit(str(msg["error"]))
    return msg.get("result") or {}

prop = (rpc("getmodelnetworkinfo", []) or {}).get("propagation") or {}
if not prop.get("demand_propagation"):
    sys.exit("fetcher demand_propagation false: " + json.dumps(prop))
rpc("addmodelnode", ["127.0.0.1:%s" % port])
got = rpc("getmodel", [uri, "FREE_ONLY"])
print("getmodel", json.dumps(got), flush=True)
if got.get("status") in ("retrieved", "local"):
    listed = rpc("listmodels", [])
    m = (listed.get("models") or [{}])[0]
    if m.get("seeded") is not True:
        sys.exit("downloader not demand-seeded: " + json.dumps(listed))
    print("E2E_REGTEST_TWO retrieve PASS", json.dumps({"bytes": m.get("bytes"), "seeded": m.get("seeded")}))
    raise SystemExit(0)
job_id = got.get("job_id")
if not job_id:
    sys.exit("no job: " + json.dumps(got))
t0 = time.time()
while time.time() - t0 < 15:
    jobs = rpc("getmodeljob", [job_id])
    arr = jobs.get("jobs") or []
    j = None
    for x in arr:
        if x.get("job_id") == job_id:
            j = x
            break
    if j is None and arr:
        running = [x for x in arr if x.get("status") == "running"]
        j = running[-1] if running else arr[-1]
    if j:
        print("job", j.get("status"), j.get("error"), flush=True)
        if j.get("status") == "failed":
            sys.exit("retrieve failed: " + json.dumps(j))
        if j.get("status") in ("done", "cancelled"):
            if j.get("status") != "done":
                sys.exit("retrieve not done: " + json.dumps(j))
            listed = rpc("listmodels", [])
            m = (listed.get("models") or [{}])[0]
            if m.get("seeded") is not True:
                sys.exit("downloader not demand-seeded: " + json.dumps(listed))
            print("E2E_REGTEST_TWO retrieve PASS", json.dumps({"bytes": m.get("bytes"), "seeded": m.get("seeded")}))
            raise SystemExit(0)
    time.sleep(0.25)
sys.exit("retrieve timeout 15s")
PY
then
  die "fetcher retrieve failed"
fi

echo "== production PIDs still up =="
prod_up "$SEEDER" "$PROD_SEEDER"
prod_up "$FETCHER" "$PROD_FETCHER"
echo "E2E_REGTEST_TWO PASS"
trap - EXIT
cleanup
exit 0
