#!/usr/bin/env bash
# Estimate live solo-mining hashrate from the node's matmul backend counters.
# Stateful: compares against the previous invocation's sample (cached in /tmp),
# so each call returns instantly. First call after a node restart warms up.
set -u
CLI=${CLI:-/home/eldian/btx-node/bin/btx-cli}
DATADIR=${DATADIR:-/home/eldian/.btx}
STATE=${STATE:-/tmp/btx-solo-hashrate.state}

INFO=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=8 getmininginfo 2>/dev/null || true)
if [ -z "$INFO" ]; then
    echo "solo_hashrate_hs=0"
    echo "solo_hashrate=unavailable (node RPC offline)"
    exit 0
fi

BTX_MININGINFO="$INFO" python3 - "$STATE" <<'PY'
import json, os, sys, time

# Calibration: one CUDA digest request evaluates a batch of nonce attempts.
# Measured via btx-matmul-solve-bench: tries / batched_nonce_attempts ~= 10.
NONCES_PER_DIGEST = 10

state_path = sys.argv[1]
info = json.loads(os.environ["BTX_MININGINFO"])
rt = info.get("backend_runtime", {})
digests = int(rt.get("digest_requests", 0))
now = time.time()

prev = None
try:
    with open(state_path) as fh:
        prev = json.load(fh)
except Exception:
    pass

with open(state_path, "w") as fh:
    json.dump({"time": now, "digests": digests}, fh)

net_hps = float(info.get("networkhashps", 0) or 0)
print(f"network_hashps={net_hps:.0f}")

if not prev or digests < prev.get("digests", 0) or now - prev.get("time", 0) < 3:
    print("solo_hashrate_hs=0")
    print("solo_hashrate=measuring... (check again shortly)")
    sys.exit(0)

elapsed = now - prev["time"]
digest_rate = (digests - prev["digests"]) / elapsed
nonce_rate = digest_rate * NONCES_PER_DIGEST

if nonce_rate >= 1e6: human = f"{nonce_rate/1e6:.2f} MH/s"
elif nonce_rate >= 1e3: human = f"{nonce_rate/1e3:.1f} kH/s"
else: human = f"{nonce_rate:.0f} H/s"

print(f"solo_hashrate_hs={nonce_rate:.0f}")
if nonce_rate <= 0:
    print("solo_hashrate=idle (no mining work in window)")
    sys.exit(0)
print(f"solo_hashrate={human}")
print(f"solo_window_s={elapsed:.0f}")
if net_hps > 0:
    share = nonce_rate / net_hps * 100
    # ~960 blocks/day at the 90s target spacing
    blocks_day = 960 * nonce_rate / net_hps
    print(f"solo_share_pct={share:.2f}")
    print(f"solo_est_blocks_per_day={blocks_day:.1f}")
PY
