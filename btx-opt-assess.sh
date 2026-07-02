#!/usr/bin/env bash
# Assessment for miner optimization: resource contention, config, solver knobs.
SOLVER=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
CFG=/home/eldian/.dexbtx-miner/config.yaml
echo "=== CPU: cores + load + overall busy% ==="
echo "nproc=$(nproc)"
read _ a b c d r1 r2 r3 < /proc/stat; t1=$((a+b+c+d)); i1=$d; sleep 2
read _ a b c d r1 r2 r3 < /proc/stat; t2=$((a+b+c+d)); i2=$d
awk "BEGIN{printf \"cpu_busy=%.0f%%\n\", 100*(1-($i2-$i1)/($t2-$t1))}"
echo "=== top CPU consumers ==="
top -bn1 -o %CPU 2>/dev/null | head -12 | tail -7
echo "=== btxd running? (competes for CPU/RAM; NOT needed for pool) ==="
pgrep -af 'btxd' | grep -v pgrep | head -1 || echo "btxd not running"
echo "=== RAM ==="
free -m | awk 'NR<=2'
echo "=== current miner config (solver knobs) ==="
grep -E '^(gpu_inputs|solver_threads|solver_batch_size|solver_prefetch_depth|solver_prepare_workers|solver_pipeline_async|nonces_per_slice|pool_slots):' "$CFG"
echo "=== solver env vars it actually reads (BTX_MATMUL_*) ==="
strings "$SOLVER" 2>/dev/null | grep -oE 'BTX_MATMUL_[A-Z_]+' | sort -u
echo "=== solver process: current niceness + GPU power ==="
pid=$(pgrep -f '[b]tx-gbt-solve' | head -1)
[ -n "$pid" ] && ps -o pid,ni,pri,%cpu,nlwp -p "$pid"
nvidia-smi --query-gpu=utilization.gpu,clocks.sm,power.draw,power.limit --format=csv,noheader | head -1
