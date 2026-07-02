#!/usr/bin/env bash
# Why won't the v0.32.11 solver engage the GPU scan on sm_86? Capture its own
# init/stderr (the miner swallows it), its flags, and CUDA linkage.
set -u
SB=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
echo "=== solver --version ==="; "$SB" --version 2>&1 | head -3
echo ""; echo "=== --help: scan/v3/gpu/seed/backend flags ==="
"$SB" --help 2>&1 | grep -iE 'scan|v3|gpu|seed|backend|cuda|matmul|fallback|cpu|parent|mtp|arch|sm_' | head -40
echo ""; echo "=== ldd: CUDA libs resolve? ==="
ldd "$SB" 2>&1 | grep -iE 'cuda|cublas|not found'
echo ""; echo "=== solver daemon init (10s, no job) — look for cuda/scan/sm_/device/error ==="
printf '' | timeout 10 "$SB" --matmul-n 512 --matmul-b 16 --matmul-r 8 --epsilon-bits 18 --daemon --backend cuda --solver-threads 8 --batch-size 128 2>&1 | grep -iE 'cuda|gpu|scan|seed|sm_|error|fail|cubin|device|fallback|warn|backend|arch|init|v3|kernel' | head -25
echo "(end init capture)"
