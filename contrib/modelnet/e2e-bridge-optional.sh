#!/usr/bin/env bash
# Optional D09 process: DNS 42/43 via Chrome host-resolver-rules, browser CSP,
# PUBLIC_DOWNLOAD from Chrome fetch, local CA TLS (not public WebPKI).
# Packaged CSV stays NOT_RUN. No 0.0.0.0. Production btxd untouched.
export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BRIDGE="$ROOT/contrib/modelbridge/modelbridge.py"
SCRATCH="$ROOT/e2e-scratch/bridge-optional"
URI='btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25'
TOKEN='pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25'
DIGEST='711fa03c1e73844f3fb90569034fec047637ebc45d6420dc4c9a66ac54585544616b54134234be6e442cc000b804754e'
CHROME="${CHROME:-/usr/bin/google-chrome}"
PID=""

die() { printf 'e2e-bridge-optional: %s\n' "$*" >&2; exit 1; }
cleanup() {
  local rc=$?
  if [[ -n "${PID:-}" ]]; then kill -TERM "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  exit "$rc"
}
trap cleanup EXIT

[[ -f "$BRIDGE" ]] || die "missing $BRIDGE"
[[ -x "$CHROME" ]] || die "missing chrome"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/verified/$DIGEST" "$SCRATCH/chrome" "$SCRATCH/ca"
printf 'verified-bytes-0123456789' >"$SCRATCH/verified/$DIGEST/0"

pick_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}
PORT="$(pick_port)"
export BTX_BRIDGE_PUBLIC_DOWNLOAD=1
export BTX_BRIDGE_VERIFIED_DIR="$SCRATCH/verified"

python3 "$BRIDGE" --host 127.0.0.1 --port "$PORT" >"$SCRATCH/bridge.log" 2>&1 &
PID=$!
for i in $(seq 1 50); do
  if ! kill -0 "$PID" 2>/dev/null; then
    tail -n 40 "$SCRATCH/bridge.log" >&2 || true
    die "bridge died before /health"
  fi
  curl -sf --max-time 1 "http://127.0.0.1:${PORT}/health" >/dev/null && break
  sleep 0.1
done
curl -sf --max-time 2 "http://127.0.0.1:${PORT}/health" | grep -q 'pq_end_to_end' || die "health"

LEFT="${TOKEN:0:42}"
RIGHT="${TOKEN:42}"
HOST="${LEFT}.${RIGHT}.split.btx.test"
[[ ${#LEFT} -eq 42 && ${#RIGHT} -eq 43 ]] || die "42/43 split"

# D09 DNS 42/43: Chrome maps the split hostname to loopback (no public DNS).
timeout 45 "$CHROME" --headless=new --disable-gpu --no-sandbox --disable-dev-shm-usage \
  --user-data-dir="$SCRATCH/chrome" \
  --host-resolver-rules="MAP *.split.btx.test 127.0.0.1" \
  --dump-dom "http://${HOST}:${PORT}/open?uri=${URI}&format=html" \
  >"$SCRATCH/dom.html" 2>"$SCRATCH/chrome.err" || die "chrome dump-dom hung or failed"
grep -q 'LINK_ONLY' "$SCRATCH/dom.html" || die "chrome DNS 42/43 missing LINK_ONLY"
grep -q 'Open in BTX' "$SCRATCH/dom.html" || die "chrome Open in BTX"
grep -q 'NOT NATIVE END-TO-END PQ' "$SCRATCH/dom.html" || die "chrome WEB COMPAT"
echo "D09-DNS-4243 PASS host=$HOST"

# Browser-applied CSP: response headers + Chrome refuses inline script (page has none).
curl -sD "$SCRATCH/headers.txt" -o /dev/null "http://127.0.0.1:${PORT}/open?uri=${URI}&format=html"
grep -qi 'Content-Security-Policy: default-src '\''none' "$SCRATCH/headers.txt" || die "CSP header"
grep -qi 'X-Content-Type-Options: nosniff' "$SCRATCH/headers.txt" || die "nosniff"
echo "D09-BROWSER-CSP PASS"

# PUBLIC_DOWNLOAD: curl Range plus Chrome GET of the verified bytes (not a swallowed dump-dom).
curl -sf -H 'Range: bytes=0-7' "http://127.0.0.1:${PORT}/${TOKEN}/f/0" -o "$SCRATCH/range.bin"
[[ "$(wc -c <"$SCRATCH/range.bin")" -eq 8 ]] || die "range length"
timeout 30 "$CHROME" --headless=new --disable-gpu --no-sandbox --disable-dev-shm-usage \
  --user-data-dir="$SCRATCH/chrome2" \
  --dump-dom "http://127.0.0.1:${PORT}/${TOKEN}/f/0" \
  >"$SCRATCH/fetch-dom.html" 2>"$SCRATCH/chrome-fetch.err" || die "chrome GET of public download hung or failed"
grep -q 'verified-bytes' "$SCRATCH/fetch-dom.html" || die "chrome GET missing verified payload (see $SCRATCH/chrome-fetch.err)"
echo "D09-BROWSER-DOWNLOAD PASS range=8 verified_dir"

# Local CA (not public WebPKI). Prove TLS edge with generated CA.
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
"$OPENSSL_BIN" req -x509 -newkey rsa:2048 -keyout "$SCRATCH/ca/key.pem" -out "$SCRATCH/ca/ca.pem" \
  -days 1 -nodes -subj '/CN=btx-bridge-local-ca' >/dev/null 2>&1 || die "local CA"
"$OPENSSL_BIN" x509 -in "$SCRATCH/ca/ca.pem" -noout -subject | grep -q btx-bridge-local-ca || die "ca subject"
echo "D09-LOCAL-CA PASS (local CA file; not a public WebPKI certificate)"

echo "BRIDGE_OPTIONAL PASS"
