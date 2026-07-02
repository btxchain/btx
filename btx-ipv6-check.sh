#!/usr/bin/env bash
# Can this host accept inbound over IPv6 (no-NAT path) or reach Tor?
echo "=== global IPv6 address on host? ==="
ip -6 addr show scope global 2>/dev/null | grep -E 'inet6' | grep -v 'fd00\|fc00\|temporary' || echo "no global IPv6"
echo "=== IPv6 internet reachable? ==="
if curl -6 -s --max-time 8 https://api64.ipify.org 2>/dev/null; then echo " <- public IPv6 (egress works)"; else echo "no IPv6 egress"; fi
echo
echo "=== is a Tor daemon present/running? ==="
pgrep -x tor >/dev/null && echo "tor running" || echo "tor NOT running"
command -v tor >/dev/null && echo "tor binary: $(command -v tor)" || echo "tor NOT installed"
echo "=== btxd current net view (onion/ipv6 local addrs + inbound) ==="
/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx -rpcclienttimeout=8 getnetworkinfo 2>/dev/null | python3 -c 'import json,sys
try:
  d=json.load(sys.stdin)
  print("connections_in:", d.get("connections_in"), "out:", d.get("connections_out"))
  for n in d.get("localaddresses",[]): print("  local:", n.get("address"), n.get("port"))
  for nw in d.get("networks",[]): print("  net:", nw.get("name"), "reachable=", nw.get("reachable"), "proxy=", nw.get("proxy") or "-")
except Exception as e: print("node RPC not available:", e)'
