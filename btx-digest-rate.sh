#!/usr/bin/env bash
# Sample digest_requests twice and report the delta rate (nonces/s = rate x 10).
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
get_digests() {
  "$CLI" -datadir="$DATADIR" -rpcclienttimeout=20 getmininginfo 2>/dev/null \
    | python3 -c 'import json,sys; print(int(json.load(sys.stdin).get("backend_runtime",{}).get("digest_requests",0)))' 2>/dev/null || echo ""
}
a=$(get_digests); t0=$(date +%s)
[ -z "$a" ] && { echo "RPC unavailable on first sample"; exit 1; }
sleep "${INTERVAL:-30}"
b=$(get_digests); t1=$(date +%s)
[ -z "$b" ] && { echo "RPC unavailable on second sample"; exit 1; }
el=$((t1 - t0))
echo "digests: $a -> $b over ${el}s"
python3 -c "import sys; a,b,el=$a,$b,$el; r=(b-a)/el if el else 0; print(f'digest_rate={r:.1f}/s nonce_rate={r*10/1000:.2f} kH/s')"
