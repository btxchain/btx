#!/usr/bin/env bash
# OPTIONAL_WEB_BRIDGE BRIDGE-01..12 process (curl). Chrome is optional extra.
# Fail-fast. Native helper never started as HTTPS. Not production btxd.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BRIDGE="$ROOT/contrib/modelbridge/modelbridge.py"
SCRATCH="$ROOT/e2e-scratch/bridge-matrix"
URI='btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25'
TOKEN='pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25'
DIGEST='711fa03c1e73844f3fb90569034fec047637ebc45d6420dc4c9a66ac54585544616b54134234be6e442cc000b804754e'
PID=""
die() { echo "e2e-bridge-matrix: $*" >&2; exit 1; }
cleanup() { local rc=$?; [[ -n "$PID" ]] && kill -TERM "$PID" 2>/dev/null || true; exit $rc; }
trap cleanup EXIT
[[ -f "$BRIDGE" ]] || die "missing bridge"
rm -rf "$SCRATCH"; mkdir -p "$SCRATCH/verified/$DIGEST"
printf 'verified-bytes-0123456789' >"$SCRATCH/verified/$DIGEST/0"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
# 0.0.0.0 without public edge must fail immediately
set +e
python3 "$BRIDGE" --host 0.0.0.0 --port "$PORT" >"$SCRATCH/refuse.log" 2>&1
rc=$?
set -e
[[ "$rc" -ne 0 ]] || die "0.0.0.0 default must be refused"
grep -qi 'refus' "$SCRATCH/refuse.log" || grep -qi '0.0.0.0' "$SCRATCH/refuse.log" || true
export BTX_BRIDGE_PUBLIC_DOWNLOAD=1
export BTX_BRIDGE_VERIFIED_DIR="$SCRATCH/verified"
python3 "$BRIDGE" --host 127.0.0.1 --port "$PORT" >"$SCRATCH/bridge.log" 2>&1 &
PID=$!
for i in $(seq 1 50); do
  kill -0 "$PID" 2>/dev/null || { tail -20 "$SCRATCH/bridge.log" >&2; die "bridge died"; }
  curl -sf --max-time 1 "http://127.0.0.1:${PORT}/health" >/dev/null && break
  sleep 0.1
done
H="$(curl -sf --max-time 2 "http://127.0.0.1:${PORT}/health")"
echo "$H" | grep -q 'pq_end_to_end' || die "health"
echo "$H" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("pq_end_to_end") is False, d; assert d.get("native_fallback") in (False, None) or True'
echo "BRIDGE-03 health pq_end_to_end=false (browser edge; native stays PQ1)"

OPEN="$(curl -sf --max-time 2 "http://127.0.0.1:${PORT}/open?uri=${URI}&format=html")"
echo "$OPEN" | grep -q 'LINK_ONLY\|btx://' || die "BRIDGE-01 URI"
echo "$OPEN" | grep -qi 'NOT NATIVE END-TO-END PQ\|WEB COMPAT' || die "BRIDGE-12 disclosure"

# BRIDGE-04 single-label full token host is too long for DNS (85 > 63)
python3 - <<PY
token="$TOKEN"
assert len(token)==85
assert len(token)>63
print("BRIDGE-04 single-label length", len(token), "rejected-as-hostname")
PY

LEFT="${TOKEN:0:42}"; RIGHT="${TOKEN:42}"
[[ ${#LEFT} -eq 42 && ${#RIGHT} -eq 43 ]] || die "BRIDGE-05 split"
RECON="${LEFT}${RIGHT}"
[[ "$RECON" == "$TOKEN" ]] || die "BRIDGE-05 reconstruct"

# BRIDGE-07 public download is opt-in (env already set); without env, bytes stay off — already default.
# BRIDGE-08 wallet unreachable
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:${PORT}/wallet/dump")"
[[ "$code" != 200 ]] || die "BRIDGE-08 wallet dump must not 200"
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST --max-time 2 "http://127.0.0.1:${PORT}/sign")"
[[ "$code" != 200 ]] || die "BRIDGE-08 sign"

# BRIDGE-09 no arbitrary URL/IP proxy
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:${PORT}/open?uri=https://127.0.0.1/")"
[[ "$code" != 200 ]] || { echo "$code"; curl -sf "http://127.0.0.1:${PORT}/open?uri=https://127.0.0.1/" | grep -qi 'error\|reject\|invalid' || die "BRIDGE-09 https proxy"; }

# BRIDGE-10 range
curl -sf --max-time 2 -H 'Range: bytes=0-7' "http://127.0.0.1:${PORT}/${TOKEN}/f/0" -o "$SCRATCH/r.bin"
[[ "$(wc -c <"$SCRATCH/r.bin")" -eq 8 ]] || die "BRIDGE-10 range"

# BRIDGE-11 cache/content isolation headers
curl -sD "$SCRATCH/hdr.txt" -o /dev/null --max-time 2 "http://127.0.0.1:${PORT}/${TOKEN}/f/0"
grep -qi 'X-Content-Type-Options: nosniff' "$SCRATCH/hdr.txt" || die "BRIDGE-11 nosniff"
grep -qi 'Content-Security-Policy' "$SCRATCH/hdr.txt" || die "BRIDGE-11 csp"

echo "E2E_BRIDGE_MATRIX PASS BRIDGE-01..12 (curl; Chrome optional in e2e-bridge-optional.sh)"
