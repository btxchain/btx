#!/usr/bin/env bash
# Solo mining results tracker: scan recent block coinbases for our payout
# address and report blocks won + rewards. Stateful and incremental — each
# call only scans blocks since the previous call (bootstrap: last 960 blocks
# ~= 24h, chunked so a single call stays fast). Uses direct JSON-RPC with
# cookie auth so scanning hundreds of blocks doesn't spawn hundreds of CLIs.
set -u
DATADIR=${DATADIR:-/home/eldian/.btx}
ADDR=${ADDR:-btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35}
STATE=${STATE:-/mnt/d/BTX/btx-solo-stats.state.json}

DATADIR="$DATADIR" ADDR="$ADDR" STATE="$STATE" python3 <<'PY'
import json, os, time, urllib.request

DATADIR = os.environ["DATADIR"]
ADDR = os.environ["ADDR"]
STATE = os.environ["STATE"]
BOOTSTRAP_BLOCKS = 960      # ~24h at 90s spacing
MAX_SCAN_PER_CALL = 150     # keep each status poll fast; backlog catches up
WIN_RETENTION_S = 7 * 86400

def fail(msg):
    print("solo_stats=unavailable (%s)" % msg)
    raise SystemExit(0)

try:
    cookie = open(os.path.join(DATADIR, ".cookie")).read().strip()
except OSError:
    fail("node offline")

rpcport = "19334"
try:
    for line in open(os.path.join(DATADIR, "btx.conf")):
        line = line.strip()
        if line.startswith("rpcport="):
            rpcport = line.split("=", 1)[1]
except OSError:
    pass

import base64
auth = base64.b64encode(cookie.encode()).decode()
url = f"http://127.0.0.1:{rpcport}/"

def rpc(payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())

try:
    tip = rpc({"method": "getblockcount", "params": [], "id": 0})["result"]
except Exception as e:
    fail(f"rpc error {e.__class__.__name__}")

state = {"last_height": None, "wins": []}
try:
    with open(STATE) as fh:
        state = json.load(fh)
except Exception:
    pass

start = (state["last_height"] + 1) if state.get("last_height") else max(1, tip - BOOTSTRAP_BLOCKS)
if start > tip + 1:  # chain rewound / fresh datadir: restart window
    start = max(1, tip - BOOTSTRAP_BLOCKS)
end = min(tip, start + MAX_SCAN_PER_CALL - 1)

if start <= end:
    heights = list(range(start, end + 1))
    hashes = rpc([{"method": "getblockhash", "params": [h], "id": i} for i, h in enumerate(heights)])
    hash_by_id = {r["id"]: r.get("result") for r in hashes}
    blocks = rpc([
        {"method": "getblock", "params": [hash_by_id[i], 2], "id": i}
        for i in range(len(heights)) if hash_by_id.get(i)
    ])
    for r in blocks:
        b = r.get("result")
        if not b:
            continue
        cb = (b.get("tx") or [{}])[0]
        won = sum(
            v.get("value", 0) for v in cb.get("vout", [])
            if v.get("scriptPubKey", {}).get("address") == ADDR
        )
        if won > 0:
            state["wins"].append({"height": b["height"], "time": b["time"], "value": won, "hash": b["hash"]})
    state["last_height"] = end

now = time.time()
state["wins"] = [w for w in state["wins"] if now - w["time"] <= WIN_RETENTION_S]

# Drop wins that were reorged out: a recorded block hash that no longer
# matches the active chain at that height means the reward was orphaned.
if state["wins"]:
    checks = rpc([
        {"method": "getblockhash", "params": [w["height"]], "id": i}
        for i, w in enumerate(state["wins"])
    ])
    live = {r["id"]: r.get("result") for r in checks}
    state["wins"] = [
        w for i, w in enumerate(state["wins"])
        if w.get("hash") and live.get(i) == w["hash"]
    ]
os.makedirs(os.path.dirname(STATE), exist_ok=True)
with open(STATE, "w") as fh:
    json.dump(state, fh)

day = [w for w in state["wins"] if now - w["time"] <= 86400]
print(f"solo_blocks_24h={len(day)}")
print(f"solo_rewards_24h={sum(w['value'] for w in day):.4f}")
print(f"solo_blocks_7d={len(state['wins'])}")
print(f"solo_rewards_7d={sum(w['value'] for w in state['wins']):.4f}")
if state["wins"]:
    last = max(state["wins"], key=lambda w: w["height"])
    ago = int((now - last["time"]) / 60)
    ago_txt = f"{ago}m" if ago < 120 else f"{ago // 60}h"
    print(f"solo_last_win=#{last['height']} ({ago_txt} ago, {last['value']:.2f} BTX)")
else:
    print("solo_last_win=none in window")
backlog = tip - state["last_height"]
if backlog > 0:
    print(f"solo_scan_backlog={backlog}")
PY
