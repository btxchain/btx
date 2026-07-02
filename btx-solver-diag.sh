#!/usr/bin/env bash
# Diagnostic: feed the solver daemon one real job and show ALL output (stdout+stderr).
set -u
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
SOLVER=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
SECS=${SECS:-8}; BATCH=${BATCH:-256}; GI=${GI:-0}

gbt=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=20 getblocktemplate '{"rules":["segwit"]}' 2>/dev/null)
job=$(printf '%s' "$gbt" | SECS="$SECS" python3 -c '
import json,os,sys
d=json.load(sys.stdin)
print(json.dumps({"version":d["version"],"prev_hash":d["previousblockhash"],"merkle_root":"b"*64,
"time":d["curtime"],"bits":d["bits"],"seed_a":d["seed_a"],"seed_b":d["seed_b"],
"block_height":d["height"],"nonce_start":1,"max_tries":1000000000,"max_seconds":float(os.environ["SECS"])}))')
echo "JOB: ${job:0:100}..."
echo "=== solver output (stdout+stderr) ==="
{ printf '%s\n' "$job"; sleep $((SECS+6)); } | env BTX_MATMUL_GPU_INPUTS=$GI \
  "$SOLVER" --matmul-n 512 --matmul-b 16 --matmul-r 8 --epsilon-bits 18 \
  --daemon --backend cuda --solver-threads 12 --batch-size "$BATCH" 2>&1 | head -30
