#!/usr/bin/env bash
# Add miningchainguardmaxmediangap=30 to btx.conf and restart btxd (solo guard relaunches it with CUDA).
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
CONF="$DATADIR/btx.conf"
if grep -q '^miningchainguardmaxmediangap=' "$CONF" 2>/dev/null; then
  sed -i 's/^miningchainguardmaxmediangap=.*/miningchainguardmaxmediangap=30/' "$CONF"
else
  echo 'miningchainguardmaxmediangap=30' >> "$CONF"
fi
echo "--- chainguard lines in btx.conf ---"
grep miningchainguard "$CONF"
echo "--- restarting btxd ---"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=15 stop 2>&1 || true
for _ in $(seq 1 60); do pgrep -f '/bin/btxd' >/dev/null 2>&1 || break; sleep 1; done
echo "btxd stopped: $(pgrep -f '/bin/btxd' >/dev/null 2>&1 && echo no || echo yes)"
