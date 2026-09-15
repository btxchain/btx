#!/usr/bin/env bash
# Loopback D09 bridge smoke. Bind 127.0.0.1 only. No WAN.
set -euo pipefail
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$HERE/modelbridge.py"
PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
python3 "$PY" --host 0.0.0.0 --port "$PORT" >/tmp/modelbridge-refuse.err 2>&1 && {
  echo "expected 0.0.0.0 refuse" >&2
  exit 1
}
python3 "$PY" --host 127.0.0.1 --port "$PORT" >/tmp/modelbridge-smoke.log 2>&1 &
PID=$!
cleanup() { kill -TERM "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }
trap cleanup EXIT
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/tmp/modelbridge-health.json 2>/dev/null; then
    break
  fi
  sleep 0.05
done
python3 - <<PY
import json
from pathlib import Path
h = json.loads(Path("/tmp/modelbridge-health.json").read_text())
assert h.get("pq_end_to_end") is False, h
assert h.get("native_fallback") is False, h
assert h.get("wallet") is False, h
assert h.get("wildcard_dns_depth") == 0, h
assert h.get("public_download") is False, h
assert h.get("bind_default") == "127.0.0.1", h
print("BRIDGE_SMOKE health", h)
PY
URI="btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25"
curl -fsS "http://127.0.0.1:${PORT}/open?uri=${URI}" >/tmp/modelbridge-open.json
python3 - <<PY
import json
from pathlib import Path
o = json.loads(Path("/tmp/modelbridge-open.json").read_text())
assert o.get("pq_end_to_end") is False
assert o.get("canonical", "").startswith("btx://")
print("BRIDGE_SMOKE open", o.get("canonical"))
PY
curl -fsS -D /tmp/modelbridge-range.hdr -H "Range: bytes=0-100" \
  "http://127.0.0.1:${PORT}/open?uri=${URI}&Range=bytes=0-4194303" \
  >/tmp/modelbridge-range.json
python3 - <<PY
import json
from pathlib import Path
hdr = Path("/tmp/modelbridge-range.hdr").read_text().lower()
assert "application/json" in hdr, hdr
assert "octet-stream" not in hdr, hdr
body = json.loads(Path("/tmp/modelbridge-range.json").read_text())
assert body.get("pq_end_to_end") is False
assert body.get("canonical", "").startswith("btx://")
print("BRIDGE_SMOKE range-ignored", body.get("canonical"))
PY
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PORT}/wallet" || true)
[[ "$code" == "403" || "$code" == "404" ]]
curl -sD /tmp/modelbridge-health.hdr -o /dev/null "http://127.0.0.1:${PORT}/health"
grep -qi 'Content-Security-Policy: default-src '\''none' /tmp/modelbridge-health.hdr
grep -qi 'X-Content-Type-Options: nosniff' /tmp/modelbridge-health.hdr
echo "BRIDGE_SMOKE PASS"
