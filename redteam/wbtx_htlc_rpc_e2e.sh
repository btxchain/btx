#!/bin/sh
# End-to-end smoke test for the buildhtlcclaim / buildhtlcrefund wallet RPCs.
#
# Builds a general P2MR HTLC descriptor mr(<internal>,{htlc(H160,claimerPk),refund(locktime,senderPk)}),
# funds the derived address, then:
#   (a) buildhtlcclaim with the correct preimage -> sendrawtransaction -> confirms; dest receives funds.
#   (b) a second funded output, after mining past the locktime, buildhtlcrefund -> sendrawtransaction -> confirms.
#
# Throwaway regtest node under /tmp; cleaned up at the end. Designed to run inside the rtX1-orig container.
set -u

B=/opt/btx/build/bin/btxd
ROOT=/tmp/wbtx_htlc_rpc_e2e
PORT=19564
RPCPORT=19565

cleanup() {
    $CLI stop >/dev/null 2>&1 || true
    for p in $(pgrep -f "datadir=$ROOT" 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
    sleep 1
    rm -rf "$ROOT"
}

for p in $(pgrep -f "datadir=$ROOT" 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
sleep 1; rm -rf "$ROOT"; mkdir -p "$ROOT"

CLI="/opt/btx/build/bin/btx-cli -regtest -datadir=$ROOT -rpcuser=u -rpcpassword=p -rpcport=$RPCPORT"
trap cleanup EXIT INT TERM

# buildhtlcclaim/buildhtlcrefund take a JSON-object prevout argument, which btx-cli sends as a
# raw string (these RPCs are intentionally not in the CLI arg-conversion table, since their real
# callers use JSON-RPC directly). Drive them via JSON-RPC POST so the prevout is a real object.
# Usage: rpc_call <wallet> <method> <json-array-of-params>  (uses python3; curl is unavailable)
rpc_call() {
    RPCPORT="$RPCPORT" python3 - "$1" "$2" "$3" <<'PY'
import sys, os, json, base64, urllib.request
wallet, method, params = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
port = os.environ["RPCPORT"]
body = json.dumps({"jsonrpc": "1.0", "id": "e2e", "method": method, "params": params}).encode()
req = urllib.request.Request("http://127.0.0.1:%s/wallet/%s" % (port, wallet), data=body)
req.add_header("Content-Type", "application/json")
req.add_header("Authorization", "Basic " + base64.b64encode(b"u:p").decode())
try:
    print(urllib.request.urlopen(req).read().decode())
except urllib.error.HTTPError as e:
    print(e.read().decode())
PY
}

$B -regtest -datadir="$ROOT" -port=$PORT -rpcport=$RPCPORT -rpcuser=u -rpcpassword=p \
   -listen=0 -server=1 -daemon -fallbackfee=0.0001 >"$ROOT/boot.log" 2>&1

for i in $(seq 1 80); do $CLI getblockcount >/dev/null 2>&1 && break; sleep 0.5; done
if ! $CLI getblockcount >/dev/null 2>&1; then
    echo "FAIL: node did not start"; cat "$ROOT/boot.log"; exit 1
fi
echo "node up; blockcount=$($CLI getblockcount)"

W="$CLI -rpcwallet=w"
$CLI createwallet w >/dev/null 2>&1
MINE=$($W getnewaddress "" p2mr)
$W generatetoaddress 110 "$MINE" >/dev/null 2>&1
echo "mined; balance=$($W getbalance)"

# Claimer + sender ML-DSA leaf pubkeys (both owned by wallet w so it can sign both paths),
# plus an internal key for the primary leaf. The raw ML-DSA pubkey is obtained via exportpqkey
# (getaddressinfo does not expose it for P2MR addresses); the wallet holds the private key.
extract_pubkey() { python3 -c "import sys,json
try: print(json.load(sys.stdin).get('pubkey',''))
except: print('')"; }
A1=$($W getnewaddress "" p2mr); A2=$($W getnewaddress "" p2mr)
PK1=$($W exportpqkey "$A1" "ml-dsa-44" | extract_pubkey)
PK2=$($W exportpqkey "$A2" "ml-dsa-44" | extract_pubkey)
INT=$($W exportpqkey "$MINE" "ml-dsa-44" | extract_pubkey)
echo "pk1_len=${#PK1} pk2_len=${#PK2} int_len=${#INT}"
if [ -z "$PK1" ] || [ -z "$PK2" ] || [ -z "$INT" ]; then echo "FAIL: missing pubkeys"; exit 1; fi

# Preimage + HASH160 = RIPEMD160(SHA256(preimage))
PRE=$(python3 -c "print('a3'*32)")
H160=$(python3 - "$PRE" <<'PY'
import sys,hashlib
pre=bytes.fromhex(sys.argv[1])
print(hashlib.new('ripemd160', hashlib.sha256(pre).digest()).hexdigest())
PY
)
echo "preimage=$PRE preimage_hash160=$H160"

LOCK=$(( $($W getblockcount) + 6 ))
DESC="mr($INT,{htlc($H160,$PK1),refund($LOCK,$PK2)})"
INFO=$($CLI getdescriptorinfo "$DESC" 2>&1)
CK=$(echo "$INFO" | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('checksum',''))
except: print('')" 2>/dev/null)
if [ -z "$CK" ]; then echo "FAIL: descriptor rejected: $INFO"; exit 1; fi
FULLDESC="$DESC#$CK"
echo "descriptor=$FULLDESC"

ADDR=$($CLI deriveaddresses "$FULLDESC" 2>&1 | python3 -c "import sys,json
try: print(json.load(sys.stdin)[0])
except Exception as e: print('')")
if [ -z "$ADDR" ]; then echo "FAIL: deriveaddresses failed"; exit 1; fi
echo "htlc_address=$ADDR"

# Helper: find vout of the htlc address in a wallet funding txid (uses gettransaction+decode,
# which works without -txindex).
find_vout() {
    $W gettransaction "$1" true true 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
tx=d.get('decoded',{})
for o in tx.get('vout',[]):
    spk=o.get('scriptPubKey',{})
    if spk.get('address')=='$ADDR':
        print(o['n']); break
"
}

##########################################################################
# (a) CLAIM path
##########################################################################
echo "=== CLAIM ==="
FTXID_C=$($W sendtoaddress "$ADDR" 5)
$W generatetoaddress 1 "$MINE" >/dev/null 2>&1
VOUT_C=$(find_vout "$FTXID_C")
echo "claim funding txid=$FTXID_C vout=$VOUT_C"
if [ -z "$VOUT_C" ]; then echo "FAIL: could not locate claim funding vout"; exit 1; fi

CLAIMDEST=$($W getnewaddress "" p2mr)
CLAIM_PARAMS="[\"$FULLDESC\",{\"txid\":\"$FTXID_C\",\"vout\":$VOUT_C},\"$PRE\",\"$CLAIMDEST\",100000]"
CLAIM_JSON=$(rpc_call w buildhtlcclaim "$CLAIM_PARAMS")
echo "buildhtlcclaim -> $(echo "$CLAIM_JSON" | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    if d.get('error'): print('ERROR',d['error'])
    else:
        r=d['result']; print('complete=%s selected_path=%s txid=%s' % (r.get('complete'), r.get('selected_path'), r.get('txid')))
except Exception as e: print('PARSE_ERR',e)")"
CLAIM_HEX=$(echo "$CLAIM_JSON" | python3 -c "import sys,json
try: print(json.load(sys.stdin)['result'].get('hex',''))
except: print('')")
if [ -z "$CLAIM_HEX" ]; then echo "FAIL: buildhtlcclaim produced no hex"; echo "$CLAIM_JSON" | head -c 500; exit 1; fi

CLAIM_SENT=$($W sendrawtransaction "$CLAIM_HEX" 2>&1)
echo "claim sendrawtransaction -> $CLAIM_SENT"
case "$CLAIM_SENT" in
  *error*|*Error*|"" ) echo "FAIL: claim broadcast failed"; exit 1 ;;
esac
$W generatetoaddress 1 "$MINE" >/dev/null 2>&1
CLAIM_CONF=$($W gettransaction "$CLAIM_SENT" true true 2>/dev/null | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('confirmations',0))
except: print(0)")
echo "claim confirmations=$CLAIM_CONF"
DEST_RECV=$($W gettransaction "$CLAIM_SENT" true true 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin); tx=d.get('decoded',{})
print(sum(o['value'] for o in tx.get('vout',[]) if o.get('scriptPubKey',{}).get('address')=='$CLAIMDEST'))")
echo "claim dest received=$DEST_RECV"
if [ "$CLAIM_CONF" -lt 1 ] 2>/dev/null; then echo "FAIL: claim not confirmed"; exit 1; fi

##########################################################################
# (b) REFUND path
##########################################################################
echo "=== REFUND ==="
FTXID_R=$($W sendtoaddress "$ADDR" 5)
$W generatetoaddress 1 "$MINE" >/dev/null 2>&1
VOUT_R=$(find_vout "$FTXID_R")
echo "refund funding txid=$FTXID_R vout=$VOUT_R"
if [ -z "$VOUT_R" ]; then echo "FAIL: could not locate refund funding vout"; exit 1; fi

# Mine until height >= locktime so CLTV is satisfiable.
while [ "$($W getblockcount)" -lt "$LOCK" ]; do $W generatetoaddress 1 "$MINE" >/dev/null 2>&1; done
echo "height=$($W getblockcount) locktime=$LOCK"

REFUNDDEST=$($W getnewaddress "" p2mr)
REFUND_PARAMS="[\"$FULLDESC\",{\"txid\":\"$FTXID_R\",\"vout\":$VOUT_R},\"$REFUNDDEST\",$LOCK,100000]"
REFUND_JSON=$(rpc_call w buildhtlcrefund "$REFUND_PARAMS")
echo "buildhtlcrefund -> $(echo "$REFUND_JSON" | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    if d.get('error'): print('ERROR',d['error'])
    else:
        r=d['result']; print('complete=%s selected_path=%s txid=%s locktime=%s' % (r.get('complete'), r.get('selected_path'), r.get('txid'), r.get('locktime')))
except Exception as e: print('PARSE_ERR',e)")"
REFUND_HEX=$(echo "$REFUND_JSON" | python3 -c "import sys,json
try: print(json.load(sys.stdin)['result'].get('hex',''))
except: print('')")
if [ -z "$REFUND_HEX" ]; then echo "FAIL: buildhtlcrefund produced no hex"; echo "$REFUND_JSON" | head -c 500; exit 1; fi

REFUND_SENT=$($W sendrawtransaction "$REFUND_HEX" 2>&1)
echo "refund sendrawtransaction -> $REFUND_SENT"
case "$REFUND_SENT" in
  *error*|*Error*|"" ) echo "FAIL: refund broadcast failed"; exit 1 ;;
esac
$W generatetoaddress 1 "$MINE" >/dev/null 2>&1
REFUND_CONF=$($W gettransaction "$REFUND_SENT" true true 2>/dev/null | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('confirmations',0))
except: print(0)")
echo "refund confirmations=$REFUND_CONF"
if [ "$REFUND_CONF" -lt 1 ] 2>/dev/null; then echo "FAIL: refund not confirmed"; exit 1; fi

echo "=========================================="
echo "RESULT: PASS"
echo "claim_txid=$CLAIM_SENT"
echo "refund_txid=$REFUND_SENT"
echo "=========================================="
