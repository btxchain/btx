#!/usr/bin/env bash
# Measure solver throughput with EXTERNALLY-timed wall clock (the solver's own
# elapsed_s is unreliable). Spawn daemon, send one job, time until result line,
# compute tries_used / measured_wall.
set -u
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
SOLVER=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
SECS=${SECS:-15}; BATCH=${BATCH:-128}; GI=${GI:-0}; TH=${TH:-12}
PIPE=/tmp/btx-solve-job.fifo
OUT=/tmp/btx-solve-time.out

pkill -f '[b]tx-gbt-solve' 2>/dev/null || true; sleep 2
rm -f "$PIPE" "$OUT"; mkfifo "$PIPE"

gbt=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=20 getblocktemplate '{"rules":["segwit"]}' 2>/dev/null)
job=$(printf '%s' "$gbt" | SECS="$SECS" python3 -c '
import json,os,sys
d=json.load(sys.stdin)
print(json.dumps({"version":d["version"],"prev_hash":d["previousblockhash"],"merkle_root":"b"*64,
"time":d["curtime"],"bits":d["bits"],"seed_a":d["seed_a"],"seed_b":d["seed_b"],
"block_height":d["height"],"nonce_start":1,"max_tries":100000000000,"max_seconds":float(os.environ["SECS"])}))')

# Hold the fifo open for writing so the daemon does not see EOF.
exec 3>"$PIPE"
stdbuf -oL env BTX_MATMUL_GPU_INPUTS=$GI "$SOLVER" \
  --matmul-n 512 --matmul-b 16 --matmul-r 8 --epsilon-bits 18 \
  --daemon --backend cuda --solver-threads "$TH" --batch-size "$BATCH" <"$PIPE" >"$OUT" 2>/dev/null &
SP=$!
# wait for daemon_ready
for _ in $(seq 1 50); do grep -q daemon_ready "$OUT" 2>/dev/null && break; sleep 0.2; done
t0=$(date +%s.%N)
printf '%s\n' "$job" >&3
# wait for a result line (tries_used)
for _ in $(seq 1 $((SECS*5+40))); do grep -q '"tries_used"' "$OUT" 2>/dev/null && break; sleep 0.2; done
t1=$(date +%s.%N)
exec 3>&-
kill "$SP" 2>/dev/null
tu=$(grep '"tries_used"' "$OUT" | tail -1 | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tries_used",0))' 2>/dev/null || echo 0)
python3 -c "
t0,t1,tu=$t0,$t1,$tu
w=t1-t0; r=tu/w if w>0 else 0
print('batch=$BATCH gi=$GI tries=%d wall=%.2fs rate=%.2f kH/s' % (tu, w, r/1000))"
rm -f "$PIPE" "$OUT"
