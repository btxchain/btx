#!/usr/bin/env bash
# START-01 / stock btxd auto-starts btx-modeld. Isolated datadir. Never touches
# production btxd. Cleans its own tree on exit.
set -euo pipefail
ROOT="${ROOT:-/home/administrator/btx-0.34.7-private}"
# Inherited BIN may be a binary (btx-hcpd). Only honor a directory that contains btxd.
if [[ -n "${BIN:-}" && -d "${BIN}" && -x "${BIN}/btxd" ]]; then
  :
else
  BIN="$ROOT/build-gcc13/bin"
fi
WORKDIR="${WORKDIR:-$ROOT/tmp-e2e-hosting}"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

BTXD="$BIN/btxd"
CLI="$BIN/btx-cli"
MODELD="$BIN/btx-modeld"
[[ -x "$BTXD" ]] || { echo "e2e-hosting-default: missing executable $BTXD (BIN=$BIN)" >&2; exit 1; }
[[ -x "$CLI" ]] || { echo "e2e-hosting-default: missing executable $CLI (BIN=$BIN)" >&2; exit 1; }
[[ -x "$MODELD" ]] || { echo "e2e-hosting-default: missing executable $MODELD (BIN=$BIN)" >&2; exit 1; }
# Dedicated ports: never share 18443/18444 with the lab /var/lib/btxd node.
PORT=37544
RPC=37543
CURRENT_DATADIR=""
cli() {
  "$CLI" -regtest -datadir="$CURRENT_DATADIR" -rpcport="$RPC" -rpcuser=u -rpcpassword=p "$@"
}

DATADIR="$WORKDIR/node"
mkdir -p "$DATADIR"
CURRENT_DATADIR="$DATADIR"
# Stock flags: no -model* except isolation ports.
"$BTXD" -regtest -datadir="$DATADIR" -listen=0 -server=1 \
  -port="$PORT" -rpcport="$RPC" \
  -rpcuser=u -rpcpassword=p -fallbackfee=0.0001 -daemon=0 \
  >"$WORKDIR/btxd.log" 2>&1 &
PID=$!
kill_node() {
  if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
    cli stop >/dev/null 2>&1 || true
    for i in $(seq 1 50); do
      if ! kill -0 "$PID" 2>/dev/null; then break; fi
      sleep 0.1
    done
    if kill -0 "$PID" 2>/dev/null; then
      kill -TERM "$PID" 2>/dev/null || true
      sleep 1
    fi
  fi
  PID=""
}
trap 'kill_node; cleanup' EXIT

ok=0
for i in $(seq 1 80); do
  if cli getblockchaininfo >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.25
done
test "$ok" = 1

ready=0
for i in $(seq 1 480); do
  if cli getmodelnetworkinfo 2>/dev/null | grep -q '"helper_ready": true'; then
    ready=1
    break
  fi
  sleep 0.25
done
test "$ready" = 1

info="$(cli getmodelnetworkinfo)"
echo "$info"
echo "$info" | grep -q '"enabled": true'
echo "$info" | grep -E -q '"helper_ready": true|"helper_state": "READY"'
echo "$info" | grep -q '"automatic_spend_atoms": 0'
# AUTO must keep 10% / 32GiB reserve. Effective quota is positive only when
# available > reserve; a 90% root disk correctly reports 0.
python3 -c '
import json,sys
raw=sys.stdin.read()
j=json.loads(raw)
assert j.get("storage_mode") == "AUTO", raw
assert j.get("automatic_spend_atoms",1)==0
quota=int(j.get("storage_effective_quota_bytes") or 0)
avail=int(j.get("filesystem_available_bytes") or 0)
reserve=int(j.get("filesystem_reserve_bytes") or 0)
assert reserve > 0, raw
if avail > reserve:
    assert quota > 0, raw
else:
    assert quota == 0, raw
' <<<"$info"

# START-02: -modelnet=0 never starts helper
kill_node
DATADIR2="$WORKDIR/off"
mkdir -p "$DATADIR2"
CURRENT_DATADIR="$DATADIR2"
"$BTXD" -regtest -datadir="$DATADIR2" -listen=0 -server=1 \
  -port="$PORT" -rpcport="$RPC" \
  -rpcuser=u -rpcpassword=p -nomodelnet -daemon=0 \
  >"$WORKDIR/btxd-off.log" 2>&1 &
PID=$!
trap 'kill_node; cleanup' EXIT
ok=0
for i in $(seq 1 80); do
  if cli getblockchaininfo >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.25
done
test "$ok" = 1
info2="$(cli getmodelnetworkinfo)"
echo "$info2"
python3 -c '
import json,sys
j=json.loads(sys.argv[1])
assert j.get("enabled") is False or j.get("helper_ready") is False, j
' "$info2"
# monetary RPC still works
cli getblockchaininfo >/dev/null
kill_node

# START-03: explicit missing helper leaves money up and must not spawn packaged modeld
DATADIR3="$WORKDIR/missing"
mkdir -p "$DATADIR3"
CURRENT_DATADIR="$DATADIR3"
"$BTXD" -regtest -datadir="$DATADIR3" -listen=0 -server=1 \
  -port="$PORT" -rpcport="$RPC" \
  -rpcuser=u -rpcpassword=p -modelhelper=/no/such/btx-modeld -daemon=0 \
  >"$WORKDIR/btxd-missing.log" 2>&1 &
PID=$!
trap 'kill_node; cleanup' EXIT
ok=0
for i in $(seq 1 80); do
  if cli getblockchaininfo >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.25
done
test "$ok" = 1
info3="$(cli getmodelnetworkinfo)"
echo "$info3"
python3 -c '
import json,sys
j=json.loads(sys.argv[1])
assert j.get("helper_ready") is not True, j
assert j.get("helper_state") in ("FAILED_RETRYING","DISABLED","DEGRADED", None) or j.get("helper_ready") is False, j
' "$info3"
grep -E "not exist|not found" "$DATADIR3/regtest/debug.log" >/dev/null
# packaged helper must not have been spawned for this datadir
if grep -q "PQ1 ready" "$WORKDIR/btxd-missing.log"; then
  echo "START-03 FAIL: packaged helper spawned" >&2
  exit 1
fi
cli getblockchaininfo >/dev/null
kill_node
echo "e2e-hosting-default: PASS"
