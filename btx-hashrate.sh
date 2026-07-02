#!/usr/bin/env bash
# Estimate current dexbtx pool-miner hashrate from recent solver slice log lines.
# The pool miner does not print a direct H/s metric, but every "solver: working"
# line records the starting nonce for a fixed-size slice. The configured slice
# size is parsed from config.yaml (nonces_per_slice; default 2,000,000).
set -u
LOG=${LOG:-/mnt/d/BTX/dexbtx-miner.log}
CFG=${CFG:-/home/eldian/.dexbtx-miner/config.yaml}
WINDOW=${WINDOW:-300}

slice_size=$(python3 - "$CFG" <<'PY' 2>/dev/null || true
import re, sys
p=sys.argv[1]
try: text=open(p, errors='replace').read()
except OSError: text=''
m=re.search(r'^\s*nonces_per_slice\s*:\s*([0-9_]+)', text, re.M)
print((m.group(1).replace('_','') if m else '2000000'))
PY
)
slice_size=${slice_size:-2000000}

python3 - "$LOG" "$WINDOW" "$slice_size" <<'PY'
import datetime as dt, pathlib, re, sys, time
log=pathlib.Path(sys.argv[1]); window=int(sys.argv[2]); slice_size=int(sys.argv[3])
if not log.exists():
    print('hashrate_hs=0')
    print('hashrate=unavailable (no miner log)')
    raise SystemExit(0)
now=time.time()
# Timestamps are HH:MM:SS only, so lines from yesterday at the same wall-clock
# time would pass the window check. If the log itself is stale, report idle.
if now - log.stat().st_mtime > window:
    print('hashrate_hs=0')
    print('hashrate=idle (no recent miner log activity)')
    raise SystemExit(0)
rows=[]
# Read the tail without depending on external tail/head utilities.
lines=log.read_text(errors='replace').splitlines()[-5000:]
for line in lines:
    if 'solver: working' not in line:
        continue
    m=re.match(r'(\d\d):(\d\d):(\d\d)\s+', line)
    if not m:
        continue
    h,mi,s=map(int,m.groups())
    t=dt.datetime.now().replace(hour=h, minute=mi, second=s, microsecond=0).timestamp()
    # handle logs from just before midnight
    if t-now > 3600:
        t -= 86400
    if now-t <= window:
        rows.append(t)
if len(rows) < 2:
    print('hashrate_hs=0')
    print('hashrate=warming up / insufficient recent slices')
    print(f'recent_slices={len(rows)}')
    raise SystemExit(0)
elapsed=max(rows)-min(rows)
hs=(len(rows)-1)*slice_size/elapsed if elapsed > 0 else 0.0
if hs >= 1e9: human=f'{hs/1e9:.3f} GH/s'
elif hs >= 1e6: human=f'{hs/1e6:.3f} MH/s'
elif hs >= 1e3: human=f'{hs/1e3:.3f} kH/s'
else: human=f'{hs:.1f} H/s'
print(f'hashrate_hs={hs:.2f}')
print(f'hashrate={human}')
print(f'window_s={window}')
print(f'recent_slices={len(rows)}')
print(f'slice_size={slice_size}')
PY
