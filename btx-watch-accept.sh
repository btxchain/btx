#!/usr/bin/env bash
# After a miner restart, wait and report whether shares are being ACCEPTED now.
LOG=/mnt/d/BTX/dexbtx-miner.log
# wait for miner+solver back up
for i in $(seq 1 30); do pgrep -f '[b]tx-gbt-solve' >/dev/null && break; sleep 2; done
echo "=== reconnect lines ==="
tail -40 "$LOG" | grep -iE 'connecting to pool|subscribed;|authorized as|difficulty set to' | tail -5
echo "=== watching for share results for ~70s ==="
ok=0; rej=0
end=$((SECONDS+70))
last=""
while [ $SECONDS -lt $end ]; do
  line=$(grep -E 'share OK|submit raised' "$LOG" | tail -1)
  if [ "$line" != "$last" ]; then
    last="$line"
    echo "$line" | grep -q 'share OK' && { ok=$((ok+1)); echo "  ACCEPT: $(echo "$line" | grep -oE 'a/r/b=[0-9/]+')"; }
    echo "$line" | grep -q 'submit raised' && rej=$((rej+1))
  fi
  sleep 3
done
echo "=== over ~70s window: new-accept-events=$ok new-reject-events=$rej ==="
grep -E 'share OK|submit raised' "$LOG" | tail -6
