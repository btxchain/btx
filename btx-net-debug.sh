#!/usr/bin/env bash
# Enable net debug logging briefly and capture disconnect reasons.
set -u
DATADIR=/home/eldian/.btx
CLI=/home/eldian/btx-node/bin/btx-cli

"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 logging '["net"]' >/dev/null
echo "net logging enabled; capturing 90s..."
sleep 90
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 logging '[]' '["net"]' >/dev/null
echo "net logging disabled."
echo "=== disconnect / socket events ==="
grep -E "disconnect|Disconnect|socket closed|connection reset|version handshake|ping timeout" "$DATADIR/debug.log" | tail -40
