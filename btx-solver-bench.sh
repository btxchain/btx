#!/usr/bin/env bash
# Sweep dexbtx solver batch-size / gpu_inputs / threads and report tries/sec.
# Drives the solver in DAEMON mode (the production code path): spawn daemon,
# feed ONE JSON job on stdin, read the result line. Pulls REAL matmul seeds
# from getblocktemplate. Run with the live miner STOPPED for clean numbers.
set -u
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
SOLVER=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
SECS=${SECS:-10}
THREADS_LIST=${THREADS_LIST:-12}
BATCH_LIST=${BATCH_LIST:-"128 256 512 1024 2048"}
GI_LIST=${GI_LIST:-"0 1"}

gbt=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=20 getblocktemplate '{"rules":["segwit"]}' 2>/dev/null)
job=$(printf '%s' "$gbt" | SECS="$SECS" python3 -c '
import json,os,sys
d=json.load(sys.stdin)
job={
  "version": d["version"],
  "prev_hash": d["previousblockhash"],
  "merkle_root": "b"*64,
  "time": d["curtime"],
  "bits": d["bits"],
  "seed_a": d["seed_a"],
  "seed_b": d["seed_b"],
  "block_height": d["height"],
  "nonce_start": 1,
  "max_tries": 100000000000,
  "max_seconds": float(os.environ["SECS"]),
}
print(json.dumps(job))
')
[ -z "$job" ] && { echo "GBT/job build failed"; exit 1; }
echo "# secs=$SECS job=${job:0:80}..."
echo "# gpu_inputs batch threads tries_used elapsed_s tries_per_sec"

best_rate=0; best_cfg=""
for gi in $GI_LIST; do
  for th in $THREADS_LIST; do
    for b in $BATCH_LIST; do
      out=$(printf '%s\n' "$job" | timeout $((SECS+25)) env BTX_MATMUL_GPU_INPUTS=$gi \
        "$SOLVER" --matmul-n 512 --matmul-b 16 --matmul-r 8 --epsilon-bits 18 \
        --daemon --backend cuda --solver-threads "$th" --batch-size "$b" 2>/dev/null \
        | grep -E '"tries_used"' | head -1)
      read tu es <<<"$(printf '%s' "$out" | python3 -c 'import json,sys
try:
  d=json.load(sys.stdin); print(d.get("tries_used",0), d.get("elapsed_s",0))
except Exception: print(0,0)')"
      rate=$(python3 -c "tu=$tu; es=$es; print(int(tu/es) if es>0 else 0)")
      printf '%10s %5s %7s %14s %10s %12s\n' "$gi" "$b" "$th" "$tu" "$es" "$rate"
      if [ "$rate" -gt "$best_rate" ] 2>/dev/null; then best_rate=$rate; best_cfg="gpu_inputs=$gi batch=$b threads=$th"; fi
    done
  done
done
echo "# BEST: $best_cfg -> $best_rate tries/sec ($(python3 -c "print('%.1f kH/s'%($best_rate/1000))"))"
