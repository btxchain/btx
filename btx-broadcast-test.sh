#!/usr/bin/env bash
set -e
HEX=$(cat /mnt/d/BTX/test_send.hex)
echo "Broadcasting test tx ($(echo -n "$HEX" | wc -c) hex chars)..."
TXID=$(/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx sendrawtransaction "$HEX")
echo "BROADCAST OK"
echo "txid=$TXID"
echo "explorer: https://explorer.minebtx.com/tx/$TXID"
