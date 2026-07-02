#!/usr/bin/env bash
# Single daemon-mode solve, stdbuf line-buffered, captured to file, then parsed.
set -u
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
SOLVER=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
SECS=${SECS:-10}; BATCH=${BATCH:-128}; GI=${GI:-0}; TH=${TH:-12}
OUT=/tmp/btx-bench-$$.out

gbt=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=20 getblocktemplate '{"rules":["segwit"]}' 2>/dev/null)
job=$(printf '%s' "$gbt" | SECS="$SECS" python3 -c '
import json,os,sys
d=json.load(sys.stdin)
print(json.dumps({"version":d["version"],"prev_hash":d["previousblockhash"],"merkle_root":"b"*64,
"time":d["curtime"],"bits":d["bits"],"seed_a":d["seed_a"],"seed_b":d["seed_b"],
"block_height":d["height"],"nonce_start":1,"max_tries":100000000000,"max_seconds":float(os.environ["SECS"])}))')
[ -z "$job" ] && { echo "job build failed"; exit 1; }

# Keep stdin open past the solve so the daemon stays alive to flush its result,
# then close. stdbuf forces line-buffered stdout so the line is captured.
{ printf '%s\n' "$job"; sleep $((SECS+6)); } | stdbuf -oL -eL env BTX_MATMUL_GPU_INPUTS=$GI \
  "$SOLVER" --matmul-n 512 --matmul-b 16 --matmul-r 8 --epsilon-bits 18 \
  --daemon --backend cuda --solver-threads "$TH" --batch-size "$BATCH" >"$OUT" 2>/dev/null &
SPID=$!
sleep $((SECS+8))
kill "$SPID" 2>/dev/null
echo "=== raw solver output ==="
cat "$OUT"
echo "=== parsed ==="
grep -E '"tries_used"' "$OUT" | tail -1 | python3 -c 'import json,sys
line=sys.stdin.read().strip()
if not line: print("no result line"); raise SystemExit
d=json.loads(line); tu=d.get("tries_used",0); es=d.get("elapsed_s",0)
print("tries=%s elapsed=%s rate=%s kH/s" % (tu, es, ("%.1f"%(tu/es/1000)) if es else "?"))'
rm -f "$OUT"
