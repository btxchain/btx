#!/usr/bin/env bash
# Measure the pool solver's true nonce rate at the live config, exclusive-GPU.
# Stops the pool miner (parent+child) so nothing contends, runs gbt-solve with a
# real job and EXTERNAL wall timing (solver elapsed_s is unreliable), then
# restarts pool mining. Prints nonce rate (kH/s).
set -u
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
SOLVER=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
GI=${GI:-1}; BATCH=${BATCH:-128}; TH=${TH:-8}; SECS=${SECS:-20}
PIPE=/tmp/btx-rate.fifo; OUT=/tmp/btx-rate.out

echo "=== stopping pool miner for clean measurement ==="
bash /mnt/d/btx/btx-mining-mode.sh stop >/dev/null 2>&1 || true
pkill -f '[d]exbtx-miner' 2>/dev/null || true
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
sleep 3

gbt=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=20 getblocktemplate '{"rules":["segwit"]}' 2>/dev/null)
job=$(printf '%s' "$gbt" | SECS="$SECS" python3 -c '
import json,os,sys
d=json.load(sys.stdin)
print(json.dumps({"version":d["version"],"prev_hash":d["previousblockhash"],"merkle_root":"b"*64,
"time":d["curtime"],"bits":d["bits"],"seed_a":d["seed_a"],"seed_b":d["seed_b"],
"block_height":d["height"],"nonce_start":1,"max_tries":100000000000,"max_seconds":float(os.environ["SECS"])}))')

rm -f "$PIPE" "$OUT"; mkfifo "$PIPE"
exec 3>"$PIPE"
stdbuf -oL env BTX_MATMUL_GPU_INPUTS=$GI "$SOLVER" \
  --matmul-n 512 --matmul-b 16 --matmul-r 8 --epsilon-bits 18 \
  --daemon --backend cuda --solver-threads "$TH" --batch-size "$BATCH" <"$PIPE" >"$OUT" 2>/dev/null &
SP=$!
for i in $(seq 1 50); do grep -q daemon_ready "$OUT" 2>/dev/null && break; sleep 0.2; done
t0=$(date +%s.%N)
printf '%s\n' "$job" >&3
for i in $(seq 1 $((SECS*5+60))); do grep -q '"tries_used"' "$OUT" 2>/dev/null && break; sleep 0.2; done
t1=$(date +%s.%N)
exec 3>&-; kill "$SP" 2>/dev/null
tu=$(grep '"tries_used"' "$OUT" | tail -1 | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("tries_used",0))
except Exception: print(0)' 2>/dev/null || echo 0)
echo "=== RESULT ==="
python3 -c "
t0,t1,tu=$t0,$t1,$tu
w=t1-t0; r=tu/w if w>0 else 0
print('config: gpu_inputs=$GI batch=$BATCH threads=$TH')
print('tries=%d  wall=%.1fs  nonce_rate=%.0f H/s (%.2f kH/s)' % (tu, w, r, r/1000))"
rm -f "$PIPE" "$OUT"

echo "=== restarting pool mining ==="
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
rm -f /tmp/btx-pool-guard.stop
bash /mnt/d/btx/btx-mining-mode.sh pool >/dev/null 2>&1 || true
sleep 2
echo "pool restarted (guard + miner)"
