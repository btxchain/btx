#!/usr/bin/env bash
# Does gbt-solve actually use the GPU? Run the daemon ~18s with one job while
# sampling GPU peak util, capturing stderr for backend-selection messages.
set -u
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
SOLVER=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
GI=${GI:-0}; BATCH=${BATCH:-512}; TH=${TH:-12}
ERR=/tmp/btx-solver-err.$GI.log

pkill -f '[b]tx-gbt-solve' 2>/dev/null || true; sleep 2
gbt=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=20 getblocktemplate '{"rules":["segwit"]}' 2>/dev/null)
job=$(printf '%s' "$gbt" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(json.dumps({"version":d["version"],"prev_hash":d["previousblockhash"],"merkle_root":"b"*64,
"time":d["curtime"],"bits":d["bits"],"seed_a":d["seed_a"],"seed_b":d["seed_b"],
"block_height":d["height"],"nonce_start":1,"max_tries":100000000000,"max_seconds":30.0}))')

# Start daemon, feed job, keep stdin open via long sleep.
{ printf '%s\n' "$job"; sleep 20; } | env BTX_MATMUL_GPU_INPUTS=$GI "$SOLVER" \
  --matmul-n 512 --matmul-b 16 --matmul-r 8 --epsilon-bits 18 \
  --daemon --backend cuda --solver-threads "$TH" --batch-size "$BATCH" >/dev/null 2>"$ERR" &
SP=$!
sleep 3  # let it init
echo "=== GPU during solve (gpu_inputs=$GI batch=$BATCH) ==="
mx=0
for i in $(seq 1 7); do
  u=$(nvidia-smi --query-gpu=utilization.gpu,clocks.sm,power.draw --format=csv,noheader,nounits | head -1)
  echo "  $u"
  uu=$(echo "$u" | awk -F',' '{gsub(/ /,"",$1);print $1}')
  [ "$uu" -gt "$mx" ] 2>/dev/null && mx=$uu
  sleep 2
done
echo "peak_util=${mx}%"
kill "$SP" 2>/dev/null; pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
echo "=== solver stderr (backend/init messages) ==="
grep -iE 'backend|cuda|gpu|cpu|fallback|device|error|warn|init' "$ERR" | head -20
echo "(stderr lines: $(wc -l < "$ERR"))"
