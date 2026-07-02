#!/usr/bin/env bash
# Clean solver sweep. Drives the daemon the way that actually flushes output:
# pipe stdout to a reader and let the daemon exit on stdin-EOF (a SIGTERM kill
# loses its block-buffered result). Kills stragglers before each run.
# Ranks by tries_used at fixed max_seconds (robust to the solver's unreliable
# elapsed_s); also prints externally-measured wall time.
set -u
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
SOLVER=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
SECS=${SECS:-10}
BATCH_LIST=${BATCH_LIST:-"128 256 512 1024 2048"}
GI_LIST=${GI_LIST:-"0 1"}
TH=${TH:-12}

kill_solvers() { pkill -f '[b]tx-gbt-solve' 2>/dev/null || true; sleep 2; }

gbt=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=20 getblocktemplate '{"rules":["segwit"]}' 2>/dev/null)
job=$(printf '%s' "$gbt" | SECS="$SECS" python3 -c '
import json,os,sys
d=json.load(sys.stdin)
print(json.dumps({"version":d["version"],"prev_hash":d["previousblockhash"],"merkle_root":"b"*64,
"time":d["curtime"],"bits":d["bits"],"seed_a":d["seed_a"],"seed_b":d["seed_b"],
"block_height":d["height"],"nonce_start":1,"max_tries":100000000000,"max_seconds":float(os.environ["SECS"])}))')
[ -z "$job" ] && { echo "job build failed"; exit 1; }
echo "# secs=$SECS threads=$TH (ranked by tries_used)"
echo "# gpu_inputs batch tries_used wall_s kH/s_extwall"

best=0; bestcfg=""
for gi in $GI_LIST; do
  for b in $BATCH_LIST; do
    kill_solvers
    t0=$(date +%s.%N)
    # Let the daemon read one job then hit EOF after SECS+5 and exit cleanly
    # (clean exit flushes its buffer; SIGTERM would not).
    line=$({ printf '%s\n' "$job"; sleep $((SECS+5)); } \
      | env BTX_MATMUL_GPU_INPUTS=$gi "$SOLVER" \
        --matmul-n 512 --matmul-b 16 --matmul-r 8 --epsilon-bits 18 \
        --daemon --backend cuda --solver-threads "$TH" --batch-size "$b" 2>/dev/null \
      | grep -m1 '"tries_used"')
    t1=$(date +%s.%N)
    tu=$(printf '%s' "$line" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("tries_used",0))
except Exception: print(0)')
    read wall khs <<<"$(python3 -c "t0,t1,tu=$t0,$t1,$tu; w=t1-t0; print('%.1f'%w, '%.2f'%((tu/w/1000) if w>0 else 0))")"
    printf '%10s %5s %12s %7s %12s\n' "$gi" "$b" "$tu" "$wall" "$khs"
    if [ "$tu" -gt "$best" ] 2>/dev/null; then best=$tu; bestcfg="gpu_inputs=$gi batch=$b"; fi
  done
done
kill_solvers
echo "# BEST (most tries in ${SECS}s): $bestcfg -> $best tries"
