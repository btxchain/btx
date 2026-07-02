#!/usr/bin/env bash
# Discover btx-gbt-solve's full flags + daemon JSON input/output schema, using a
# fabricated easy job (CPU backend) so we learn the format without a live node.
set -u
SOLVER=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
echo "===== FULL --help ====="
"$SOLVER" --help 2>&1
echo
echo "===== DUMMY DAEMON JOB -> output schema ====="
job=$(python3 - <<'PY'
import json
print(json.dumps({
  "version":536870912,
  "prev_hash":"00"*32,
  "merkle_root":"11"*32,
  "time":1781890000,
  "bits":"207fffff",
  "seed_a":"22"*32,
  "seed_b":"33"*32,
  "block_height":135000,
  "parent_mtp":1781880000,
  "share_target":"ff"*32,
  "nonce_start":1,
  "max_tries":2000000
}))
PY
)
echo "JOB: $job"
echo "--- solver output ---"
printf '%s\n' "$job" | timeout 40 "$SOLVER" --daemon --backend cpu 2>&1 | head -25
