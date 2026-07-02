#!/usr/bin/env bash
# Sample connection count + chain guard peer count every 5s.
set -u
DATADIR=/home/eldian/.btx
CLI=/home/eldian/btx-node/bin/btx-cli
DURATION=${1:-60}

END=$((SECONDS + DURATION))
while [ $SECONDS -lt $END ]; do
    CONN=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getconnectioncount 2>/dev/null || echo "?")
    GUARD=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getmininginfo 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin).get("chain_guard",{})
print(f"guard_peers={d.get(\"peer_count\")} healthy={d.get(\"healthy\")}")' 2>/dev/null || echo "guard=?")
    MINING=$(pgrep -f "btx-mine.sh" >/dev/null 2>&1 && echo yes || echo no)
    echo "[$(date +%T)] conn=$CONN $GUARD miner_running=$MINING"
    sleep 5
done
