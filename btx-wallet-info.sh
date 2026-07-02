#!/usr/bin/env bash
# Balance + recent received outputs for the BTX mining/payout address (pruned node:
# scan the live UTXO set rather than rely on an address index).
set -u
C=/home/eldian/btx-node/bin/btx-cli
D=/home/eldian/.btx
A=${1:-btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35}

echo "address: $A"
echo "loaded wallets: $($C -datadir="$D" -rpcclienttimeout=10 listwallets 2>/dev/null | tr -d '\n ')"
TIP=$($C -datadir="$D" -rpcclienttimeout=10 getblockcount 2>/dev/null)
echo "chain tip height: $TIP"
echo "--- scanning UTXO set (a few seconds) ---"
$C -datadir="$D" -rpcclienttimeout=180 scantxoutset start "[\"addr($A)\"]" 2>/dev/null \
  | TIP="$TIP" python3 -c "
import json, os, sys
d = json.load(sys.stdin)
tip = int(os.environ.get('TIP') or 0)
print('SUCCESS:', d.get('success'))
print('CONFIRMED BALANCE: %.8f BTX' % d.get('total_amount', 0))
us = d.get('unspents', [])
print('unspent outputs:', len(us))
us.sort(key=lambda u: u.get('height', 0), reverse=True)
print('--- most recent received (unspent) outputs ---')
for u in us[:12]:
    h = u.get('height', 0)
    conf = (tip - h + 1) if (tip and h) else '?'
    print('  h=%-7s conf=%-7s %14.8f BTX  tx=%s' % (h, conf, u.get('amount', 0), u.get('txid', '')))
"
