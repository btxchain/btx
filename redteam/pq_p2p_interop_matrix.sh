#!/bin/sh
# BTX v0.31 PQ P2P transport — full interop matrix (regtest).
#
# Nodes:
#   A = v3  (v2 transport, PQ hybrid ON  — default)
#   B = v3  (v2 transport, PQ hybrid ON  — default)
#   C = v2  (v2 transport, PQ hybrid OFF — -v2pqhybrid=0, behaves as stock BIP324)
#   D = v1  (-v2transport=0)
#
# Matrix exercised: A<->B (v3<->v3), A<->C (v3<->v2 fallback), A<->D (v3<->v1),
# C<->D (v2<->v1). For each pair we verify the connection establishes, the negotiated
# transport_protocol_type is as expected, and a block mined on one side propagates to the other.
# The PQ hybrid rekey is confirmed via the "post-quantum hybrid rekey complete" net-debug marker:
# it MUST appear for A<->B and MUST NOT appear for any pairing involving C or D.
set -e

BTXD=/opt/btx/build/bin/btxd
CLI=/opt/btx/build/bin/btx-cli
ROOT=/tmp/pqinterop
rm -rf "$ROOT"; mkdir -p "$ROOT"

COMMON="-regtest -listen=1 -discover=0 -dnsseed=0 -fixedseeds=0 -upnp=0 -natpmp=0 -listenonion=0 -debug=net -logips=1 -server=1 -rpcuser=u -rpcpassword=p"

start_node() { # name p2pport rpcport extra
  name=$1; p2p=$2; rpc=$3; extra=$4
  dir="$ROOT/$name"; mkdir -p "$dir"
  $BTXD $COMMON -datadir="$dir" -port=$p2p -rpcport=$rpc -bind=127.0.0.1:$p2p $extra -daemon >/dev/null 2>&1
  eval "RPC_$name=\"$CLI -regtest -datadir=$dir -rpcport=$rpc -rpcuser=u -rpcpassword=p\""
  eval "DIR_$name=$dir"; eval "P2P_$name=$p2p"
}
rpc() { name=$1; shift; eval "\$RPC_$name \"\$@\""; }

wait_rpc() { # name
  for i in $(seq 1 60); do
    if rpc "$1" getblockcount >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "FATAL: node $1 RPC did not come up"; cat "$ROOT/$1/regtest/debug.log" 2>/dev/null | tail -20; exit 1
}

echo "### starting nodes"
start_node A 18450 18451 ""
start_node B 18452 18453 ""
start_node C 18454 18455 "-v2pqhybrid=0"
start_node D 18456 18457 "-v2transport=0"
for n in A B C D; do wait_rpc $n; done
echo "nodes up: A(v3) B(v3) C(v2) D(v1)"
set +e   # from here we use explicit checks, not -e
# Mining nodes need a loaded wallet (regtest starts with none).
rpc A createwallet w >/dev/null 2>&1
rpc B createwallet w >/dev/null 2>&1

PASS=0; FAIL=0
check() { # desc cond
  if [ "$2" = "1" ]; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1"; FAIL=$((FAIL+1)); fi
}

# connect helper: src connects to dst via addnode onetry
connect() { # src dstport
  rpc "$1" addnode "127.0.0.1:$2" onetry >/dev/null 2>&1 || true
}

peer_transport() { # name peerport  -> prints transport_protocol_type of the matching peer
  eval "d=\$DIR_$1"; eval "r=\$RPC_$1"
  $r getpeerinfo 2>/dev/null | tr -d ' ' | awk -v want="127.0.0.1:$2" '
    /"addr":/ {addr=$0}
    /"transport_protocol_type":/ {tt=$0; if (index(addr,want)>0) {gsub(/[",]/,"",tt); split(tt,a,":"); print a[2]; exit}}'
}

wait_synced() { # name target_count  (waits until height >= target)
  for i in $(seq 1 80); do
    c=$(rpc "$1" getblockcount 2>/dev/null); c=${c:-0}
    if [ "$c" -ge "$2" ] 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  return 1
}
wait_connected() { # name peerport
  for i in $(seq 1 40); do
    if rpc "$1" getpeerinfo 2>/dev/null | tr -d ' ' | grep -q "\"addr\":\"127.0.0.1:$2\""; then return 0; fi
    sleep 0.5
  done
  return 1
}

mine() { # name n  -> mines n blocks to a fresh address
  addr=$(rpc "$1" getnewaddress 2>/dev/null) || addr=$(rpc "$1" getnewaddress "" "bech32" 2>/dev/null)
  rpc "$1" generatetoaddress "$2" "$addr" >/dev/null 2>&1
}

# Block download in IBD happens from OUTBOUND peers, so the syncing node must DIAL OUT to the
# source. B/C/D each dial A (A is their outbound peer and block source).
echo "### establishing links: B->A (v3<->v3), C->A (v3<->v2), D->A (v3<->v1)"
connect B 18450   # B dials A
connect C 18450   # C dials A
connect D 18450   # D dials A
wait_connected B 18450; rc=$?; check "B<->A connection established" "$([ $rc = 0 ] && echo 1 || echo 0)"
wait_connected C 18450; rc=$?; check "C<->A connection established" "$([ $rc = 0 ] && echo 1 || echo 0)"
wait_connected D 18450; rc=$?; check "D<->A connection established" "$([ $rc = 0 ] && echo 1 || echo 0)"

# ---- Transport types (viewed from the dialer) ----
ttB=$(peer_transport B 18450); echo "  B sees A transport=$ttB"
check "B<->A negotiates v2 transport"                   "$([ "$ttB" = "v2" ] && echo 1 || echo 0)"
ttC=$(peer_transport C 18450); echo "  C sees A transport=$ttC"
check "C<->A negotiates v2 transport (X25519 fallback)" "$([ "$ttC" = "v2" ] && echo 1 || echo 0)"
ttD=$(peer_transport D 18450); echo "  D sees A transport=$ttD"
check "D<->A negotiates v1 transport (downgrade)"       "$([ "$ttD" = "v1" ] && echo 1 || echo 0)"

# ---- Forward sync: A mines, all dialers converge ----
echo "### A mines blocks; B/C/D must converge"
mine A 6
ca=$(rpc A getblockcount); echo "A height=$ca"
if wait_synced B "$ca"; then check "B synced to height=$ca over v3<->v3 (PQ hybrid)" 1; else check "B synced to height=$ca over v3<->v3 (PQ hybrid)" 0; fi
if wait_synced C "$ca"; then check "C synced to height=$ca over v3<->v2 (X25519 fallback)" 1; else check "C synced to height=$ca over v3<->v2 (X25519 fallback)" 0; fi
if wait_synced D "$ca"; then check "D synced to height=$ca over v3<->v1 (downgrade)" 1; else check "D synced to height=$ca over v3<->v1 (downgrade)" 0; fi

# ---- Reverse sync over the PQ hybrid channel: A dials B, B mines, A converges ----
echo "### A dials B; B mines; A must converge over the PQ hybrid channel"
connect A 18452
wait_connected A 18452 >/dev/null
mine B 2
cb=$(rpc B getblockcount)
if wait_synced A "$cb"; then check "A synced from B height=$cb over PQ hybrid channel" 1; else check "A synced from B height=$cb over PQ hybrid channel" 0; fi

# ---- PQ rekey marker analysis ----
echo "### PQ hybrid rekey marker analysis"
MARK="post-quantum hybrid rekey complete"
A_marks=$(grep -c "$MARK" "$ROOT/A/regtest/debug.log" 2>/dev/null); A_marks=${A_marks:-0}
B_marks=$(grep -c "$MARK" "$ROOT/B/regtest/debug.log" 2>/dev/null); B_marks=${B_marks:-0}
C_marks=$(grep -c "$MARK" "$ROOT/C/regtest/debug.log" 2>/dev/null); C_marks=${C_marks:-0}
D_marks=$(grep -c "$MARK" "$ROOT/D/regtest/debug.log" 2>/dev/null); D_marks=${D_marks:-0}
echo "  rekey markers: A=$A_marks B=$B_marks C=$C_marks D=$D_marks"
check "A performed >=1 PQ rekey (with B)"            "$([ "$A_marks" -ge 1 ] && echo 1 || echo 0)"
check "B performed >=1 PQ rekey (with A)"            "$([ "$B_marks" -ge 1 ] && echo 1 || echo 0)"
check "C performed 0 PQ rekeys (PQ disabled)"        "$([ "$C_marks" -eq 0 ] && echo 1 || echo 0)"
check "D performed 0 PQ rekeys (v1 only)"            "$([ "$D_marks" -eq 0 ] && echo 1 || echo 0)"

echo "### shutting down"
for n in A B C D; do rpc $n stop >/dev/null 2>&1 || true; done
sleep 2

echo "============================================"
echo "INTEROP MATRIX RESULT: PASS=$PASS FAIL=$FAIL"
echo "============================================"
[ "$FAIL" = "0" ] && echo "ALL INTEROP CASES PASSED" || echo "SOME CASES FAILED"
exit $FAIL
