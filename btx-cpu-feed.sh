#!/usr/bin/env bash
# Diagnose the CPU-feed bottleneck: WSL core count, per-process CPU%, and whether
# the feed is a single pegged thread (Python GIL = adding cores won't help) or
# all cores busy (more cores would help).
echo "=== WSL cores (nproc) ==="
nproc
echo "=== .wslconfig processors / memory ==="
grep -iE 'processors|memory' /mnt/c/Users/xgila/.wslconfig 2>/dev/null || echo "no .wslconfig found"
echo "=== top CPU consumers (snapshot) ==="
top -bn1 -o %CPU 2>/dev/null | head -18
echo "=== per-process %CPU (dexbtx + solver) ==="
ps -o pid,nlwp,%cpu,comm,args -C python3 2>/dev/null | grep -i dexbtx | grep -v grep
ps -o pid,nlwp,%cpu,comm -p "$(pgrep -f '[b]tx-gbt-solve' | head -1)" 2>/dev/null
echo "=== overall CPU idle% (mpstat-ish via /proc/stat over 2s) ==="
read _ a b c d rest < /proc/stat; t1=$((a+b+c+d)); i1=$d; sleep 2
read _ a b c d rest < /proc/stat; t2=$((a+b+c+d)); i2=$d
python3 -c "print('cpu_busy=%.0f%%' % (100*(1-($i2-$i1)/($t2-$t1))))"
