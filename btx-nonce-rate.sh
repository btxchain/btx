#!/usr/bin/env bash
# Measure live solver throughput from nonce_start advancement over a window.
# This is the real consumed-nonce rate (independent of dispatch pipelining):
# we track the max nonce_start seen at start vs end of the window.
set -u
LOG=/mnt/d/BTX/dexbtx-miner.log
WIN=${WIN:-40}
maxn() { grep -oE 'nonce_start=[0-9]+' "$LOG" | tail -400 | cut -d= -f2 | sort -n | tail -1; }
a=$(maxn); sleep "$WIN"; b=$(maxn)
python3 -c "
a,b,w=$a,$b,$WIN
d=b-a; r=d/w
print('nonce_start advanced %d over %ds' % (d,w))
print('throughput=%.1f kH/s' % (r/1000))
"
echo "=== vardiff / shares (recent) ==="
grep -E 'difficulty set to|accepted|submit raised|share' "$LOG" | tail -8
