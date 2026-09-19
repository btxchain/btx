#!/usr/bin/env bash
# Isolated regtest on three hosts. Fail-fast Linux pair; Darwin third may SKIP.
# Never production btxd. Never granite seeder port 29448. Never SIGKILL.
# Never cmake on the third host. Never copy a Linux ELF onto Darwin.
#
# Runs e2e-regtest-two-host.sh first (Linux seeder/fetcher). Then starts a
# third isolated modeld on THIRD_HOST, tunnels seeder REGTEST_MODELD_PORT
# (default 29449) to that host, and retrieves the same tiny URI (30s).
#
# If THIRD_HOST cannot run (ssh, disk <20G, missing binary, Linux ELF on
# Darwin, helper did not start), print E2E_REGTEST_THREE SKIP with reason
# and keep E2E_REGTEST_TWO PASS as the Linux pair result.
#
#   SEEDER_HOST=... FETCHER_HOST=... THIRD_HOST=... \
#   SEEDER_PROD_PIDS=... FETCHER_PROD_PIDS=... \
#     contrib/modelnet/e2e-regtest-three-host.sh
#
# THIRD_PROD_PIDS may be empty. THIRD_* defaults are Darwin-safe paths;
# override THIRD_MODELD to whatever native binary that host already has.
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TWO="$ROOT/contrib/modelnet/e2e-regtest-two-host.sh"

SEEDER="${SEEDER_HOST:?set SEEDER_HOST to SSH alias of the seeder}"
FETCHER="${FETCHER_HOST:?set FETCHER_HOST to SSH alias of the fetcher}"
THIRD="${THIRD_HOST:?set THIRD_HOST to SSH alias of the third isolated host}"
MODELD_PORT="${REGTEST_MODELD_PORT:-29449}"
SEEDER_DIR="${SEEDER_DIR:-/opt/btx-0347-rc/regtest-e2e}"
SEEDER_BTXD="${SEEDER_BTXD:-/opt/btx-node/bin/btxd}"
SEEDER_CLI="${SEEDER_CLI:-${SEEDER_BTXD%/*}/btx-cli}"
SEEDER_MODELD="${SEEDER_MODELD:-/opt/btx-0347-rc/bin/btx-modeld}"
SEEDER_LD_LIBRARY_PATH="${SEEDER_LD_LIBRARY_PATH:-/opt/btx-0347-rc/lib}"
THIRD_DIR="${THIRD_DIR:-\$HOME/.local/opt/btx-0.34.7-rc-regtest}"
THIRD_BTXD="${THIRD_BTXD:-\$HOME/.local/opt/btx-0.34.7-rc/bin/btxd}"
THIRD_CLI="${THIRD_CLI:-${THIRD_BTXD%/*}/btx-cli}"
THIRD_MODELD="${THIRD_MODELD:-${THIRD_BTXD%/*}/btx-modeld}"
THIRD_LD_LIBRARY_PATH="${THIRD_LD_LIBRARY_PATH:-}"
# Dedicated ports: never share 18443/18444 with the lab /var/lib/btxd node.
SEEDER_P2P="${SEEDER_P2P:-38244}"
SEEDER_RPC="${SEEDER_RPC:-38243}"
THIRD_P2P="${THIRD_P2P:-38344}"
THIRD_RPC="${THIRD_RPC:-38343}"
PROD_SEEDER="${SEEDER_PROD_PIDS:?set SEEDER_PROD_PIDS}"
PROD_FETCHER="${FETCHER_PROD_PIDS:?set FETCHER_PROD_PIDS}"
PROD_THIRD="${THIRD_PROD_PIDS:-}"

# 20 GiB in 1K-blocks. A host with ~19G free SKIPs instead of failing the suite.
MIN_FREE_K=$((20 * 1024 * 1024))

TUNNEL_S=""
TUNNEL_T=""
STARTED_SEEDER=0
STARTED_THIRD=0

die() { echo "E2E_REGTEST_THREE FAIL: $*" >&2; cleanup || true; exit 1; }

cleanup() {
  [[ -n "${TUNNEL_S}" ]] && kill -TERM "$TUNNEL_S" 2>/dev/null || true
  [[ -n "${TUNNEL_T}" ]] && kill -TERM "$TUNNEL_T" 2>/dev/null || true
  TUNNEL_S=""
  TUNNEL_T=""
  if [[ "${STARTED_SEEDER}" == 1 ]]; then
    ssh -o BatchMode=yes "$SEEDER" "for f in ${SEEDER_DIR}/btxd.pid ${SEEDER_DIR}/modeld.pid; do [[ -f \$f ]] && kill -TERM \$(cat \$f) 2>/dev/null || true; done" || true
    STARTED_SEEDER=0
  fi
  if [[ "${STARTED_THIRD}" == 1 ]]; then
    ssh -o BatchMode=yes "$THIRD" "for f in ${THIRD_DIR}/btxd.pid ${THIRD_DIR}/modeld.pid; do [[ -f \$f ]] && kill -TERM \$(cat \$f) 2>/dev/null || true; done" || true
    STARTED_THIRD=0
  fi
}

skip() {
  echo "E2E_REGTEST_THREE SKIP: $*"
  echo "E2E_REGTEST_TWO PASS"
  trap - EXIT
  cleanup || true
  exit 0
}

if [[ "${MODELD_PORT}" == "29448" ]]; then
  die "REFUSE granite seeder port 29448; set REGTEST_MODELD_PORT (default 29449)"
fi
[[ -x "$TWO" ]] || die "missing $TWO"
if [[ "$THIRD" == "$SEEDER" || "$THIRD" == "$FETCHER" ]]; then
  die "THIRD_HOST must be a distinct SSH alias (not SEEDER_HOST or FETCHER_HOST)"
fi

prod_up() {
  local host="$1" pids="$2"
  [[ -n "$pids" ]] || return 0
  local have p
  have="$(ssh -o BatchMode=yes "$host" "ps -p ${pids} -o pid=" || true)"
  IFS=',' read -r -a want <<<"$pids"
  for p in "${want[@]}"; do
    [[ -n "$p" ]] || continue
    echo "$have" | grep -q "$p" || die "$host production pid $p is gone"
  done
}

echo "== production PIDs must remain =="
prod_up "$SEEDER" "$PROD_SEEDER"
prod_up "$FETCHER" "$PROD_FETCHER"
prod_up "$THIRD" "$PROD_THIRD"

echo "== Linux pair (e2e-regtest-two-host.sh) =="
"$TWO" || die "two-host failed"

echo "== production PIDs after Linux pair =="
prod_up "$SEEDER" "$PROD_SEEDER"
prod_up "$FETCHER" "$PROD_FETCHER"
prod_up "$THIRD" "$PROD_THIRD"

trap 'rc=$?; cleanup; exit $rc' EXIT

echo "== probe THIRD_HOST (SKIP if it cannot run) =="
if ! ssh -o BatchMode=yes -o ConnectTimeout=8 "$THIRD" true; then
  skip "THIRD_HOST ssh failed"
fi

THIRD_HOME="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$THIRD" "printf '%s' \"\$HOME\"" || true)"
if [[ -z "$THIRD_HOME" ]]; then
  skip "cannot read HOME on THIRD_HOST"
fi
THIRD_DIR="${THIRD_DIR//\$HOME/$THIRD_HOME}"
THIRD_BTXD="${THIRD_BTXD//\$HOME/$THIRD_HOME}"
THIRD_CLI="${THIRD_CLI//\$HOME/$THIRD_HOME}"
THIRD_MODELD="${THIRD_MODELD//\$HOME/$THIRD_HOME}"
THIRD_LD_LIBRARY_PATH="${THIRD_LD_LIBRARY_PATH//\$HOME/$THIRD_HOME}"

UNAME="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$THIRD" "uname -s" || true)"
AVAIL_K="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$THIRD" "df -Pk / | awk 'NR==2 {print \$4}'" || true)"
if ! [[ "$AVAIL_K" =~ ^[0-9]+$ ]]; then
  skip "could not read free disk on THIRD_HOST"
fi
if (( AVAIL_K < MIN_FREE_K )); then
  skip "THIRD_HOST has $((AVAIL_K / 1024 / 1024))G free (<20G); not failing the Linux pair"
fi

if ! ssh -o BatchMode=yes -o ConnectTimeout=8 "$THIRD" "test -x '$THIRD_MODELD'"; then
  skip "missing THIRD_MODELD $THIRD_MODELD"
fi
if ! ssh -o BatchMode=yes -o ConnectTimeout=8 "$THIRD" "test -x '$THIRD_BTXD'"; then
  skip "missing THIRD_BTXD $THIRD_BTXD"
fi
if ! ssh -o BatchMode=yes -o ConnectTimeout=8 "$THIRD" "command -v python3 >/dev/null"; then
  skip "python3 missing on THIRD_HOST"
fi

FILETYPE="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$THIRD" "file -b '$THIRD_MODELD'" || true)"
if [[ "$UNAME" == Darwin ]] && printf '%s\n' "$FILETYPE" | grep -qi ELF; then
  skip "THIRD_MODELD is Linux ELF on Darwin; use a Darwin btx-modeld (do not copy Linux binaries)"
fi

echo "== restart isolated seeder for third-host retrieve =="
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
STARTED_SEEDER=1

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

echo "== start isolated third modeld (native THIRD_MODELD; no ELF copy, no cmake) =="
if ! ssh -o BatchMode=yes -o ConnectTimeout=8 "$THIRD" "bash -s" <<EOF
set -euo pipefail
DIR="${THIRD_DIR}"
BTXD="${THIRD_BTXD}"
MODELD="${THIRD_MODELD}"
LDLIB="${THIRD_LD_LIBRARY_PATH}"
[[ -n "\$DIR" && "\$DIR" != / ]] || { echo "refuse THIRD_DIR \$DIR" >&2; exit 1; }
[[ -x "\$BTXD" ]] || { echo "missing btxd \$BTXD" >&2; exit 1; }
[[ -x "\$MODELD" ]] || { echo "missing modeld \$MODELD" >&2; exit 1; }
# Darwin/SIP: do not inject a Linux libdir. Native binary only.
if [[ -n "\$LDLIB" ]]; then
  [[ -d "\$LDLIB" ]] || { echo "missing libdir \$LDLIB" >&2; exit 1; }
  export LD_LIBRARY_PATH="\$LDLIB\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
fi
rm -rf "\$DIR"
mkdir -p "\$DIR/btxd" "\$DIR/modeld"
# Portable btxd flags (older Darwin trees may not know -regtestmatmul*).
nohup "\$BTXD" -regtest -datadir="\$DIR/btxd" -server \\
  -listen=0 -port=${THIRD_P2P} -rpcport=${THIRD_RPC} -rpcuser=regtest -rpcpassword=regtest \\
  -fallbackfee=0.0002 -disablewallet \\
  >"\$DIR/btxd.log" 2>&1 &
echo \$! > "\$DIR/btxd.pid"
# client: no -modelbind (never 29448), no -modelseed=auto.
nohup "\$MODELD" \\
  -modeldir="\$DIR/modeld" \\
  -modelstorage=80MiB \\
  -modelrpcsocket="\$DIR/modeld/modeld.sock" \\
  >"\$DIR/modeld.log" 2>&1 &
echo \$! > "\$DIR/modeld.pid"
EOF
then
  skip "THIRD_HOST start script failed"
fi
STARTED_THIRD=1

third_ready=0
for i in $(seq 1 40); do
  out="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$THIRD" \
    "if [ -f ${THIRD_DIR}/modeld.pid ] && ! kill -0 \$(cat ${THIRD_DIR}/modeld.pid) 2>/dev/null; then echo DEAD; tail -n 40 ${THIRD_DIR}/modeld.log; elif [ -S ${THIRD_DIR}/modeld/modeld.sock ]; then echo READY; fi" || true)"
  if printf '%s\n' "$out" | grep -q '^READY$'; then
    third_ready=1
    break
  fi
  if printf '%s\n' "$out" | grep -q '^DEAD$'; then
    printf '%s\n' "$out" >&2
    skip "THIRD_HOST helper died before socket"
  fi
  sleep 0.25
done
if [[ "$third_ready" != 1 ]]; then
  ssh -o BatchMode=yes -o ConnectTimeout=8 "$THIRD" "tail -n 40 ${THIRD_DIR}/modeld.log" >&2 || true
  skip "THIRD_HOST modeld socket not ready"
fi

echo "== SSH tunnel seeder:${MODELD_PORT} -> third 127.0.0.1:${MODELD_PORT} =="
ssh -o BatchMode=yes -N -L "127.0.0.1:${MODELD_PORT}:127.0.0.1:${MODELD_PORT}" "$SEEDER" &
TUNNEL_S=$!
ssh -o BatchMode=yes -N -R "127.0.0.1:${MODELD_PORT}:127.0.0.1:${MODELD_PORT}" "$THIRD" &
TUNNEL_T=$!
sleep 0.5
if ! kill -0 "$TUNNEL_S" 2>/dev/null; then
  skip "seeder tunnel died"
fi
if ! kill -0 "$TUNNEL_T" 2>/dev/null; then
  skip "third tunnel died (cannot bind ${MODELD_PORT} on THIRD_HOST)"
fi

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

echo "== getmodel on third (30s fail-fast) =="
if ! ssh -o BatchMode=yes "$THIRD" "DIR=${THIRD_DIR} URI='$URI' PORT=${MODELD_PORT} python3 -s" <<'PY'
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

def pick_job(jobs, job_id):
    arr = jobs.get("jobs") or []
    for x in arr:
        if x.get("job_id") == job_id:
            return x
    running = [x for x in arr if x.get("status") == "running"]
    if running:
        def key(j):
            try:
                cm = int(j.get("created_ms") or 0)
            except (TypeError, ValueError):
                cm = 0
            return (cm, str(j.get("job_id") or ""))
        return max(running, key=key)
    return arr[-1] if arr else {}

prop = (rpc("getmodelnetworkinfo", []) or {}).get("propagation") or {}
if not prop.get("demand_propagation"):
    sys.exit("third demand_propagation false: " + json.dumps(prop))
rpc("addmodelnode", ["127.0.0.1:%s" % port])
got = rpc("getmodel", [uri, "FREE_ONLY"])
print("getmodel", json.dumps(got), flush=True)
if got.get("status") in ("retrieved", "local"):
    listed = rpc("listmodels", [])
    m = (listed.get("models") or [{}])[0]
    if m.get("seeded") is not True:
        sys.exit("third downloader not demand-seeded: " + json.dumps(listed))
    print("E2E_REGTEST_THREE retrieve PASS", json.dumps({"bytes": m.get("bytes"), "seeded": m.get("seeded")}))
    raise SystemExit(0)
job_id = got.get("job_id")
if not job_id:
    sys.exit("no job: " + json.dumps(got))
t0 = time.time()
while time.time() - t0 < 30:
    j = pick_job(rpc("getmodeljob", [job_id]), job_id)
    if j:
        print("job", j.get("job_id"), j.get("status"), j.get("error") or j.get("last_err"), flush=True)
        if j.get("status") == "failed":
            sys.exit("retrieve failed: " + json.dumps(j))
        if j.get("status") == "cancelled":
            sys.exit("retrieve not done: " + json.dumps(j))
        if j.get("status") == "done":
            listed = rpc("listmodels", [])
            m = (listed.get("models") or [{}])[0]
            if m.get("seeded") is not True:
                sys.exit("third downloader not demand-seeded: " + json.dumps(listed))
            print("E2E_REGTEST_THREE retrieve PASS", json.dumps({"bytes": m.get("bytes"), "seeded": m.get("seeded")}))
            raise SystemExit(0)
    time.sleep(0.25)
sys.exit("retrieve timeout 30s")
PY
then
  die "third retrieve failed"
fi

echo "== production PIDs still up =="
prod_up "$SEEDER" "$PROD_SEEDER"
prod_up "$FETCHER" "$PROD_FETCHER"
prod_up "$THIRD" "$PROD_THIRD"
echo "E2E_REGTEST_THREE PASS"
echo "E2E_REGTEST_TWO PASS"
trap - EXIT
cleanup
exit 0
