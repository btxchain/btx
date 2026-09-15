#!/usr/bin/env bash
# START-06/08/09/14/15. Isolated datadir. Never production btxd.
set -euo pipefail
ROOT="${ROOT:-/home/administrator/btx-0.34.7-private}"
BIN="${BIN:-$ROOT/build-gcc13/bin}"
WORKDIR="${WORKDIR:-$ROOT/tmp-e2e-lifecycle}"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
BTXD="$BIN/btxd"
CLI="$BIN/btx-cli"
MODELD="$BIN/btx-modeld"
test -x "$BTXD" && test -x "$CLI" && test -x "$MODELD"

PID=""
cleanup() {
  if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
    "$CLI" -regtest -datadir="${DATADIR:-$WORKDIR/x}" -rpcuser=u -rpcpassword=p stop >/dev/null 2>&1 || true
    sleep 0.5
    kill -TERM "$PID" 2>/dev/null || true
  fi
  if [[ -n "${EXT_PID:-}" ]]; then
    kill -TERM "$EXT_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

wait_rpc() {
  local dd="$1"
  local i
  for i in $(seq 1 80); do
    if "$CLI" -regtest -datadir="$dd" -rpcuser=u -rpcpassword=p getblockchaininfo >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "rpc wait failed $dd" >&2
  return 1
}

# START-06: /bin/false helper, money stays up, state FAILED_RETRYING
DATADIR="$WORKDIR/crash"
mkdir -p "$DATADIR"
"$BTXD" -regtest -datadir="$DATADIR" -listen=0 -server=1 -rpcuser=u -rpcpassword=p \
  -modelhelper=/bin/false -modelbind=off -daemon=0 >"$WORKDIR/crash.log" 2>&1 &
PID=$!
wait_rpc "$DATADIR"
"$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p getblockchaininfo >/dev/null
info="$("$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p getmodelnetworkinfo || true)"
echo "START-06 $info"
echo "$info" | grep -q '"helper_ready": true' && { echo "START-06 FAIL ready"; exit 1; }
"$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p stop >/dev/null 2>&1 || true
sleep 1
PID=""
echo "START-06 PASS"

# START-08: owned helper PID dies with btxd
DATADIR="$WORKDIR/owned"
mkdir -p "$DATADIR"
"$BTXD" -regtest -datadir="$DATADIR" -listen=0 -server=1 -rpcuser=u -rpcpassword=p \
  -modelbind=127.0.0.1:0 -daemon=0 >"$WORKDIR/owned.log" 2>&1 &
PID=$!
wait_rpc "$DATADIR"
info="$("$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p getmodelnetworkinfo)"
echo "START-08 $info"
hpid="$(python3 -c 'import json,sys; j=json.loads(sys.argv[1]); print(j.get("owner_helper_pid") or j.get("helper_pid") or 0)' "$info")"
test "$hpid" -gt 1
"$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p stop >/dev/null 2>&1 || true
sleep 2
if kill -0 "$hpid" 2>/dev/null; then
  echo "START-08 FAIL helper $hpid still alive" >&2
  kill -TERM "$hpid" 2>/dev/null || true
  exit 1
fi
PID=""
echo "START-08 PASS"

# START-09: external socket is not killed
DATADIR="$WORKDIR/ext"
mkdir -p "$DATADIR/ext-helper" "$DATADIR/node"
"$MODELD" -modeldir="$DATADIR/ext-helper" -modelstorage=16MiB \
  -modelrpcsocket="$DATADIR/ext-helper/modeld.sock" >"$WORKDIR/ext-modeld.log" 2>&1 &
EXT_PID=$!
for i in $(seq 1 50); do
  if grep -q "PQ1 ready" "$WORKDIR/ext-modeld.log" 2>/dev/null; then break; fi
  sleep 0.1
done
kill -0 "$EXT_PID"
"$BTXD" -regtest -datadir="$DATADIR/node" -listen=0 -server=1 -rpcuser=u -rpcpassword=p \
  -modelrpcsocket="$DATADIR/ext-helper/modeld.sock" -modelbind=off -daemon=0 \
  >"$WORKDIR/ext-btxd.log" 2>&1 &
PID=$!
wait_rpc "$DATADIR/node"
info="$("$CLI" -regtest -datadir="$DATADIR/node" -rpcuser=u -rpcpassword=p getmodelnetworkinfo)"
echo "START-09 $info"
echo "$info" | grep -q '"helper_managed_by_btxd": false'
"$CLI" -regtest -datadir="$DATADIR/node" -rpcuser=u -rpcpassword=p stop >/dev/null 2>&1 || true
sleep 1
PID=""
kill -0 "$EXT_PID"
kill -TERM "$EXT_PID"
wait "$EXT_PID" 2>/dev/null || true
EXT_PID=""
echo "START-09 PASS"

# START-14: restart does not leave two helpers
DATADIR="$WORKDIR/dup"
mkdir -p "$DATADIR"
"$BTXD" -regtest -datadir="$DATADIR" -listen=0 -server=1 -rpcuser=u -rpcpassword=p \
  -modelbind=off -daemon=0 >"$WORKDIR/dup1.log" 2>&1 &
PID=$!
wait_rpc "$DATADIR"
"$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p stop >/dev/null 2>&1 || true
sleep 2
PID=""
"$BTXD" -regtest -datadir="$DATADIR" -listen=0 -server=1 -rpcuser=u -rpcpassword=p \
  -modelbind=off -daemon=0 >"$WORKDIR/dup2.log" 2>&1 &
PID=$!
wait_rpc "$DATADIR"
count="$(pgrep -af "btx-modeld" | grep -c "$DATADIR" || true)"
test "$count" -le 1
"$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p stop >/dev/null 2>&1 || true
sleep 1
PID=""
echo "START-14 PASS"

# START-15: stale unix socket recovered
DATADIR="$WORKDIR/stale"
mkdir -p "$DATADIR/regtest/modelnet"
python3 -c 'import socket,sys; p=sys.argv[1]; s=socket.socket(socket.AF_UNIX); s.bind(p); s.close()' \
  "$DATADIR/regtest/modelnet/modeld.sock"
"$BTXD" -regtest -datadir="$DATADIR" -listen=0 -server=1 -rpcuser=u -rpcpassword=p \
  -modelbind=off -daemon=0 >"$WORKDIR/stale.log" 2>&1 &
PID=$!
wait_rpc "$DATADIR"
info=""
ready=0
for i in $(seq 1 80); do
  info="$("$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p getmodelnetworkinfo)"
  if echo "$info" | grep -E -q '"helper_ready": true|"helper_state": "READY"'; then
    ready=1
    break
  fi
  sleep 0.25
done
echo "START-15 $info"
test "$ready" = 1
"$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p stop >/dev/null 2>&1 || true
sleep 1
PID=""
echo "START-15 PASS"
echo "e2e-hosting-lifecycle: PASS"
