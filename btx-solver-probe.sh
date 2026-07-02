#!/usr/bin/env bash
# One-shot solver run with dummy (well-formed) inputs to reveal the output JSON
# schema. Matmul throughput is seed-independent (fixed n512/b16/r8), so dummy
# seeds give representative tries/sec.
SOLVER=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
H64=$(printf '%064d' 0 | tr '0' 'a')   # 64 hex chars
"$SOLVER" \
  --version 536870912 \
  --prev-hash "$H64" \
  --merkle-root "$H64" \
  --time "$(date +%s)" \
  --bits 1d0b2af5 \
  --seed-a "$H64" \
  --seed-b "$H64" \
  --block-height 129400 \
  --backend cuda \
  --solver-threads "${THREADS:-12}" \
  --batch-size "${BATCH:-128}" \
  --max-tries 100000000 \
  --max-seconds "${SECS:-6}" 2>&1
