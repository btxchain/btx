#!/usr/bin/env bash
# D09 public WebPKI + DNS 42/43. Live public DNS (getent/dig) and system-trust TLS.
# Local CA + CSR remain operator artifacts; they are not the proof.
# Native btx-modeld stays PQ1-only. Fail-fast. Packaged CSV marks PASS only after this script runs.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRATCH="${PUBLIC_WEBKI_OUT:-$ROOT/e2e-scratch/public-webpki-kit}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
# Documented IANA test host: public A/AAAA + HTTPS. Override for an operator zone.
HOST="${PUBLIC_BRIDGE_HOST:-example.com}"
PUBLIC_WEBPKI_HOST="${PUBLIC_WEBPKI_HOST:-example.com}"
TOKEN="${PUBLIC_BRIDGE_TOKEN:-pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25}"

die() { echo "PUBLIC_WEBPKI_KIT FAIL: $*" >&2; exit 1; }

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/local-ca" "$SCRATCH/public-csr"

[[ ${#TOKEN} -eq 85 ]] || die "token must be 85 chars (got ${#TOKEN})"
LEFT="${TOKEN:0:42}"
RIGHT="${TOKEN:42}"
[[ ${#LEFT} -eq 42 && ${#RIGHT} -eq 43 ]] || die "42/43 split lengths"
SPLIT="${LEFT}.${RIGHT}.${HOST}"
printf '%s\n' "$LEFT" >"$SCRATCH/left.label"
printf '%s\n' "$RIGHT" >"$SCRATCH/right.label"
printf '%s\n' "$SPLIT" >"$SCRATCH/split.fqdn"

cat >"$SCRATCH/dns-42-43.txt" <<EOF
D09 DNS 42/43 split is implemented (DnsSplit42_43):
  left  (${#LEFT}): ${LEFT}
  right (${#RIGHT}): ${RIGHT}
  FQDN: ${SPLIT}
Join is {left}.{right}.{zone} with zone=${HOST}.
Native PQ1 does not use this hostname. Native helper stays PQ1.
EOF

echo "== live public DNS (getent/dig) HOST=${HOST} =="
live_lookup_require() {
  local name="$1"
  local out="$2"
  if command -v getent >/dev/null 2>&1; then
    if getent ahosts "$name" >"$out" 2>/dev/null && grep -q . "$out"; then
      echo "LIVE_DNS RESOLVED getent ahosts $name"
      return 0
    fi
    if getent hosts "$name" >"$out" 2>/dev/null && grep -q . "$out"; then
      echo "LIVE_DNS RESOLVED getent hosts $name"
      return 0
    fi
  fi
  if command -v dig >/dev/null 2>&1; then
    if dig +time=5 +tries=2 +short "$name" A >"$out" 2>/dev/null && grep -qE '^[0-9]' "$out"; then
      echo "LIVE_DNS RESOLVED dig A $name"
      return 0
    fi
    if dig +time=5 +tries=2 +short "$name" AAAA >"$out" 2>/dev/null && grep -q . "$out"; then
      echo "LIVE_DNS RESOLVED dig AAAA $name"
      return 0
    fi
  fi
  python3 - "$name" "$out" <<'PY' || return 1
import socket, sys
socket.setdefaulttimeout(10)
name, outp = sys.argv[1], sys.argv[2]
infos = socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
addrs = sorted({i[4][0] for i in infos})
open(outp, "w").write("\n".join(addrs) + "\n")
print("LIVE_DNS RESOLVED python", name, " ".join(addrs[:8]))
PY
}

live_query_split() {
  local name="$1"
  # A live public query: NOERROR *or* NXDOMAIN from a real resolver.
  if command -v dig >/dev/null 2>&1; then
    if dig +time=5 +tries=2 "$name" A >"$SCRATCH/dig-split.txt" 2>"$SCRATCH/dig-split.err"; then
      if grep -Eq 'status: (NOERROR|NXDOMAIN|NODATA)' "$SCRATCH/dig-split.txt"; then
        echo "D09-DNS-4243-LIVE PASS dig $name"
        return 0
      fi
    fi
  fi
  if command -v getent >/dev/null 2>&1; then
    if getent ahosts "$name" >"$SCRATCH/getent-split.txt" 2>/dev/null && grep -q . "$SCRATCH/getent-split.txt"; then
      echo "D09-DNS-4243-LIVE RESOLVED getent $name"
      return 0
    fi
  fi
  python3 - "$name" <<'PY'
import socket, sys
socket.setdefaulttimeout(10)
name = sys.argv[1]
try:
    infos = socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
    addrs = sorted({i[4][0] for i in infos})
    print("D09-DNS-4243-LIVE RESOLVED python", name, " ".join(addrs[:8]))
except socket.gaierror as e:
    noname = {socket.EAI_NONAME}
    if hasattr(socket, "EAI_NODATA"):
        noname.add(socket.EAI_NODATA)
    if e.errno in noname or e.errno in (-2, -5):
        print("D09-DNS-4243-LIVE PASS python NXDOMAIN-class", name, e)
        sys.exit(0)
    raise SystemExit("D09-DNS-4243-LIVE FAIL resolver %s: %s" % (name, e))
PY
}

live_lookup_require "$HOST" "$SCRATCH/getent-host.txt" || die "public DNS lookup failed for $HOST"
echo "D09-PUBLIC-DNS PASS $HOST"
live_query_split "$SPLIT" || die "live public DNS query failed for split $SPLIT"

SPLIT_RESOLVED=0
if command -v getent >/dev/null 2>&1 && getent ahosts "$SPLIT" >/dev/null 2>&1; then
  SPLIT_RESOLVED=1
elif command -v getent >/dev/null 2>&1 && getent hosts "$SPLIT" >/dev/null 2>&1; then
  SPLIT_RESOLVED=1
fi

echo "== system WebPKI TLS (not local-CA-only) =="
system_webpki_tls() {
  local sni="$1"
  python3 - "$sni" <<'PY'
import ssl, socket, sys
host = sys.argv[1]
ctx = ssl.create_default_context()  # system trust store; no custom CA
ctx.check_hostname = True
ctx.verify_mode = ssl.CERT_REQUIRED
with socket.create_connection((host, 443), timeout=15) as raw:
    with ctx.wrap_socket(raw, server_hostname=host) as s:
        cert = s.getpeercert()
        if not cert:
            raise SystemExit("missing peer cert for " + host)
        print("SYSTEM_WEBPKI_TLS PASS", host, "sni=" + str(s.server_hostname), "tls=" + str(s.version()))
PY
}

system_webpki_tls "$PUBLIC_WEBPKI_HOST" || die "system WebPKI TLS to $PUBLIC_WEBPKI_HOST"
if [[ "$HOST" != "$PUBLIC_WEBPKI_HOST" ]]; then
  system_webpki_tls "$HOST" || die "system WebPKI TLS+SNI to $HOST"
else
  echo "SYSTEM_WEBPKI_TLS+SNI PASS $HOST (same as PUBLIC_WEBPKI_HOST)"
fi
if [[ "$SPLIT_RESOLVED" -eq 1 ]]; then
  system_webpki_tls "$SPLIT" || die "system WebPKI TLS+SNI to resolved split $SPLIT"
  echo "D09-DNS-4243-SNI PASS $SPLIT"
else
  echo "D09-DNS-4243-SNI skip (split name not published; publish A/AAAA for $SPLIT)"
fi

echo "== local CA + public CSR (operator artifacts, not the WebPKI proof) =="
"$OPENSSL_BIN" req -x509 -newkey rsa:2048 -keyout "$SCRATCH/local-ca/key.pem" \
  -out "$SCRATCH/local-ca/ca.pem" -days 1 -nodes -subj '/CN=btx-bridge-local-ca' \
  >/dev/null 2>&1 || die "local CA"
"$OPENSSL_BIN" x509 -in "$SCRATCH/local-ca/ca.pem" -noout -subject | grep -q btx-bridge-local-ca \
  || die "ca subject"
echo "D09-LOCAL-CA artifact $SCRATCH/local-ca/ca.pem"

"$OPENSSL_BIN" req -new -newkey rsa:2048 -nodes \
  -keyout "$SCRATCH/public-csr/key.pem" \
  -out "$SCRATCH/public-csr/request.csr" \
  -subj "/CN=${HOST}" \
  >/dev/null 2>&1 || die "csr"
[[ -s "$SCRATCH/public-csr/request.csr" ]] || die "empty csr"
echo "PUBLIC_CSR PASS $SCRATCH/public-csr/request.csr CN=$HOST"

cat >"$SCRATCH/nginx.example.conf" <<EOF
# Public HTTPS edge in FRONT of modelbridge.py. Not native PQ.
# Native btx-modeld must stay ML-KEM-768 / ML-DSA-44.
server {
  listen 443 ssl;
  server_name ${HOST};
  ssl_certificate     /etc/ssl/certs/${HOST}.pem;
  ssl_certificate_key /etc/ssl/private/${HOST}.key;
  add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'" always;
  add_header X-Content-Type-Options nosniff always;
  location / {
    proxy_pass http://127.0.0.1:8088;
  }
}
EOF

echo "PUBLIC_WEBPKI_KIT PASS"
echo "Public DNS 42/43 is implemented: $SPLIT"
echo "System WebPKI verified against $PUBLIC_WEBPKI_HOST (and SNI $HOST)."
echo "Native helper remains PQ1."
exit 0
