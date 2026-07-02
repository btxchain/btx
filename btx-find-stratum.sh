#!/usr/bin/env bash
# Find a working stratum endpoint for minebtx. Tests common host:port variants
# and scrapes the pool site for an advertised stratum address.
test_tcp() {
  if timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then
    echo "  OK   $1:$2"; exec 3>&- 2>/dev/null
  else
    echo "  fail $1:$2"
  fi
}
echo "=== testing host:port candidates ==="
for hp in \
  "minebtx.com 3333" "pool.minebtx.com 3333" "stratum.minebtx.com 3333" \
  "minebtx.com 3334" "minebtx.com 4444" "minebtx.com 3256" \
  "pool.minebtx.com 4444" "stratum.minebtx.com 4444" \
  "peers.minebtx.com 3333" "us.minebtx.com 3333" "eu.minebtx.com 3333"; do
  test_tcp $hp
done
echo "=== scrape pool site for stratum/port hints ==="
for url in "https://pool.minebtx.com/" "https://minebtx.com/" "https://pool.minebtx.com/help" "https://pool.minebtx.com/getting-started" "https://pool.minebtx.com/connect"; do
  body=$(curl -s --max-time 8 "$url" 2>/dev/null)
  hit=$(printf '%s' "$body" | grep -ioE 'stratum\+tcp://[^"<> ]+|[a-z0-9.-]*minebtx\.com:[0-9]{2,5}|port[^0-9]{0,8}[0-9]{3,5}' | sort -u | head -10)
  [ -n "$hit" ] && { echo "--- $url ---"; echo "$hit"; }
done
