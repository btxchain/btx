#!/usr/bin/env bash
# Test reachability of the mining pool from WSL.
HOST=minebtx.com; PORT=3333
echo "=== DNS ==="
getent hosts "$HOST" || echo "DNS resolve FAILED"
echo "=== TCP connect to $HOST:$PORT (5s timeout) ==="
if timeout 5 bash -c "exec 3<>/dev/tcp/$HOST/$PORT" 2>/dev/null; then
  echo "TCP CONNECT OK"
  exec 3>&-
else
  echo "TCP CONNECT FAILED"
fi
echo "=== stratum subscribe probe ==="
printf '{"id":1,"method":"mining.subscribe","params":[]}\n' \
  | timeout 6 bash -c "cat > /dev/tcp/$HOST/$PORT & exec 0</dev/tcp/$HOST/$PORT; timeout 5 head -c 300" 2>/dev/null \
  || echo "(no stratum response within timeout)"
echo
echo "=== pool website reachable? ==="
curl -s -o /dev/null -w "http_status=%{http_code} time=%{time_total}s\n" --max-time 8 https://pool.minebtx.com/ || echo "website unreachable"
echo "=== alt: ping host ==="
ping -c 2 -W 3 "$HOST" 2>&1 | tail -3 || echo "ping failed"
