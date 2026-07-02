import json, datetime, time

A = "btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35"
txs = json.load(open("/tmp/txs.json"))

print("num txs returned:", len(txs))
rows = []
for t in txs:
    st = t.get("status", {})
    bt = st.get("block_time")
    h = st.get("block_height")
    recv = sum(v.get("value", 0) for v in t.get("vout", []) if v.get("scriptpubkey_address") == A)
    rows.append((bt or 0, h, recv, t["txid"][:12]))
rows.sort()

print("%-18s %8s %13s  %s" % ("date(UTC)", "height", "BTX recv", "txid"))
tot = 0
for bt, h, recv, tx in rows:
    d = datetime.datetime.utcfromtimestamp(bt).strftime("%Y-%m-%d %H:%M") if bt else "unconfirmed"
    tot += recv
    print("%-18s %8s %13.3f  %s" % (d, h, recv/1e8, tx))
print("-" * 52)
print("TOTAL received: %.3f BTX  (in %d payouts)" % (tot/1e8, len(rows)))

if len(rows) >= 2 and rows[0][0] and rows[-1][0]:
    span = (rows[-1][0] - rows[0][0]) / 86400.0
    nowspan = (time.time() - rows[0][0]) / 86400.0
    last_gap = (time.time() - rows[-1][0]) / 86400.0
    print("first payout:           %s UTC" % datetime.datetime.utcfromtimestamp(rows[0][0]).strftime("%Y-%m-%d %H:%M"))
    print("last  payout:           %s UTC" % datetime.datetime.utcfromtimestamp(rows[-1][0]).strftime("%Y-%m-%d %H:%M"))
    print("first->last span:       %.2f days" % span)
    print("time since last payout: %.2f days" % last_gap)
    if span > 0:
        print("avg over payout span:   %.3f BTX/day  (excludes the lead-in lump's accrual)" % (tot/1e8/span))
    print("avg since first payout: %.3f BTX/day" % (tot/1e8/nowspan))
    # excluding the first (likely a one-off lump) to estimate steady-state
    if len(rows) >= 3:
        tail = rows[1:]
        ttot = sum(r[2] for r in tail)/1e8
        tspan = (tail[-1][0] - tail[0][0]) / 86400.0
        if tspan > 0:
            print("steady-state (excl 1st): %.3f BTX over %.2f d = %.3f BTX/day" % (ttot, tspan, ttot/tspan))
