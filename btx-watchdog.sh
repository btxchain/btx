#!/bin/bash
# BTX Watchdog — CUDA GPU mining with auto-restart
export BTX_MATMUL_BACKEND=cuda
CLI=/home/eldian/btx-node/bin/btx-cli
BTXD=/home/eldian/btx-node/bin/btxd
DATADIR=/home/eldian/.btx
ADDR=btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35
MINING=false

echo "=== BTX CUDA Watchdog Started (RTX 3090) ==="

while true; do
    # Check if btxd is running
    if ! pgrep -x btxd > /dev/null 2>&1; then
        echo "[$(date)] btxd is DOWN — restarting with CUDA..."
        if tail -30 "$DATADIR/debug.log" 2>/dev/null | grep -q 'Failed to initialize shielded state\|RebuildShieldedState.*failed'; then
            echo "[$(date)] Shielded state rebuild failure detected. Removing corrupt shielded_state."
            rm -rf "$DATADIR/shielded_state"
        fi
        $BTXD -datadir=$DATADIR -fastshieldedstartup=1 -daemon 2>&1
        sleep 15
        # Reload wallets after restart
        $CLI -datadir=$DATADIR loadwallet vps-miner 2>/dev/null
        echo "[$(date)] btxd restarted, wallet reloaded."
        MINING=false
        continue
    fi

    # Check if RPC is responding
    INFO=$($CLI -datadir=$DATADIR getblockchaininfo 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "[$(date)] RPC not responding, waiting..."
        sleep 10
        continue
    fi

    BLOCKS=$(echo "$INFO" | grep '"blocks"' | tr -dc '0-9')
    HEADERS=$(echo "$INFO" | grep '"headers"' | tr -dc '0-9')
    IBD=$(echo "$INFO" | grep '"initialblockdownload"' | grep -c true)

    if [ "$IBD" = "1" ]; then
        echo "[$(date)] Syncing: $BLOCKS / $HEADERS"
        sleep 30
        continue
    fi

    # Check chain guard
    GUARD=$($CLI -datadir=$DATADIR getmininginfo 2>/dev/null | grep '"should_pause_mining"' | grep -c true)
    if [ "$GUARD" = "1" ]; then
        echo "[$(date)] Chain guard: paused (waiting for peers). Block $BLOCKS"
        sleep 15
        continue
    fi

    # Synced and healthy — mine
    if [ "$MINING" = "false" ]; then
        echo "[$(date)] MINING STARTED on CUDA/RTX 3090 at block $BLOCKS"
        MINING=true
    fi

    $CLI -datadir=$DATADIR generatetoaddress 1 $ADDR 2>&1
    RESULT=$?
    if [ $RESULT -ne 0 ]; then
        echo "[$(date)] Mining error (exit $RESULT), retrying in 15s..."
        MINING=false
        sleep 15
    else
        echo "[$(date)] Block attempt done (tip: $BLOCKS)"
    fi
done
