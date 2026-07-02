#!/usr/bin/env bash
BIN=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
echo "=== binary info ==="
ls -la "$BIN"; file "$BIN" 2>/dev/null
echo "=== does it link CUDA? ==="
ldd "$BIN" 2>/dev/null | grep -iE 'cuda|nvidia|cublas|cudart' || echo "NO CUDA LIBS LINKED"
echo "=== strings: backend/cuda hints ==="
strings "$BIN" 2>/dev/null | grep -iE 'cuda|backend|gpu_inputs|metal|cpu-only|no cuda|fallback' | sort -u | head -25
echo "=== --help ==="
"$BIN" --help 2>&1 | head -40
