#!/usr/bin/env bash
# BRIDGE-06: local CA + leaf SAN vs wildcard depth, then a system-trust WebPKI
# client handshake to a public hostname. Fail-fast. Native helper stays PQ1.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/e2e-scratch/webpki-tls"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
# Documented IANA test host with a real public HTTPS certificate.
PUBLIC_WEBPKI_HOST="${PUBLIC_WEBPKI_HOST:-example.com}"
die() { echo "e2e-webpki-tls: $*" >&2; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT"
"$OPENSSL_BIN" req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$OUT/ca.key" -out "$OUT/ca.pem" -subj '/CN=btx-webpki-standin-ca' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1 || die "ca"
# leaf for models.example.test (public hostname stand-in)
"$OPENSSL_BIN" req -new -newkey rsa:2048 -nodes -keyout "$OUT/leaf.key" -out "$OUT/leaf.csr" \
  -subj '/CN=models.example.test' >/dev/null 2>&1 || die "csr"
printf 'subjectAltName=DNS:models.example.test\n' >"$OUT/leaf.ext"
"$OPENSSL_BIN" x509 -req -in "$OUT/leaf.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" -CAcreateserial \
  -out "$OUT/leaf.pem" -days 1 -extfile "$OUT/leaf.ext" >/dev/null 2>&1 || die "sign leaf"
# wildcard only one label: *.split.example.test does NOT cover a.b.split.example.test
"$OPENSSL_BIN" req -new -newkey rsa:2048 -nodes -keyout "$OUT/wild.key" -out "$OUT/wild.csr" \
  -subj '/CN=*.split.example.test' >/dev/null 2>&1 || die "wild csr"
printf 'subjectAltName=DNS:*.split.example.test\n' >"$OUT/wild.ext"
"$OPENSSL_BIN" x509 -req -in "$OUT/wild.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" -CAcreateserial \
  -out "$OUT/wild.pem" -days 1 -extfile "$OUT/wild.ext" >/dev/null 2>&1 || die "sign wild"

python3 - "$OUT" <<'PY'
import ssl, socket, threading, time, sys, subprocess, os
from pathlib import Path
out = Path(sys.argv[1])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(out/"leaf.pem", out/"leaf.key")
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", 0))
port = ls.getsockname()[1]
ls.listen(4)

def serve():
    try:
        c, _ = ls.accept()
        with ctx.wrap_socket(c, server_side=True) as s:
            s.recv(64)
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    except Exception:
        pass
th = threading.Thread(target=serve, daemon=True); th.start()
# client trust our stand-in CA
cctx = ssl.create_default_context(cafile=str(out/"ca.pem"))
cctx.check_hostname = True
with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
    with cctx.wrap_socket(raw, server_hostname="models.example.test") as s:
        s.sendall(b"GET / HTTP/1.0\r\nHost: models.example.test\r\n\r\n")
        body = s.recv(64)
        if b"OK" not in body:
            raise SystemExit("tls leaf handshake/body")
print("PUBLIC_HOSTNAME_TLS PASS models.example.test via stand-in CA")

# wildcard depth: connecting as a.b.split.example.test must fail against *.split.example.test
wctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
wctx.load_cert_chain(out/"wild.pem", out/"wild.key")
ls2 = socket.socket(); ls2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls2.bind(("127.0.0.1", 0)); p2=ls2.getsockname()[1]; ls2.listen(2)
def serve2():
    try:
        c,_=ls2.accept()
        with wctx.wrap_socket(c, server_side=True) as s:
            s.recv(32)
    except Exception:
        pass
threading.Thread(target=serve2, daemon=True).start()
c2 = ssl.create_default_context(cafile=str(out/"ca.pem"))
c2.check_hostname = True
try:
    with socket.create_connection(("127.0.0.1", p2), timeout=3) as raw:
        with c2.wrap_socket(raw, server_hostname="aa.bb.split.example.test") as s:
            raise SystemExit("BRIDGE-06: two-label name must not match one-level wildcard")
except ssl.SSLCertVerificationError:
    print("BRIDGE-06 PASS wildcard depth: aa.bb.split.example.test != *.split.example.test")
except ssl.SSLError as e:
    print("BRIDGE-06 PASS wildcard mismatch", type(e).__name__)
PY

echo "== system-trust WebPKI client handshake PUBLIC_WEBPKI_HOST=${PUBLIC_WEBPKI_HOST} =="
python3 - "$PUBLIC_WEBPKI_HOST" <<'PY'
import ssl, socket, sys
host = sys.argv[1]
ctx = ssl.create_default_context()  # system WebPKI; no local CA file
ctx.check_hostname = True
ctx.verify_mode = ssl.CERT_REQUIRED
with socket.create_connection((host, 443), timeout=15) as raw:
    with ctx.wrap_socket(raw, server_hostname=host) as s:
        cert = s.getpeercert()
        if not cert:
            raise SystemExit("missing peer cert for " + host)
        print("SYSTEM_WEBPKI_TLS PASS", host, "sni=" + str(s.server_hostname), "tls=" + str(s.version()))
PY
echo "E2E_WEBPKI_TLS PASS"
