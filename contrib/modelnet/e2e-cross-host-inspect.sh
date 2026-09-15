#!/usr/bin/env bash
# Cross-host inspection: fetcher and seeder report catalog + production PIDs.
# Fail-fast. Never SIGKILL production. Never getmodel on production helper.
#
#   FETCHER_HOST=... SEEDER_HOST=... FETCHER_PROD_PIDS=... SEEDER_PROD_PIDS=... \
#     contrib/modelnet/e2e-cross-host-inspect.sh
export LC_ALL=C
set -euo pipefail
die() { echo "E2E_CROSS FAIL: $*" >&2; exit 1; }

MAC="${FETCHER_HOST:?set FETCHER_HOST}"
RTX="${SEEDER_HOST:?set SEEDER_HOST}"
PROD_MAC="${FETCHER_PROD_PIDS:?set FETCHER_PROD_PIDS}"
PROD_RTX="${SEEDER_PROD_PIDS:?set SEEDER_PROD_PIDS}"

mac_out="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$MAC" "PROD_PIDS='$PROD_MAC' bash -s" <<'EOS' || true
set -euo pipefail
ps -p $PROD_PIDS -o pid= || true
echo '---GRANITE---'
python3 -s <<'PY'
import json, socket
from pathlib import Path
sock = Path.home()/".local/opt/btx-0.34.7-rc-modeld/e2e-granite/modeld.sock"
if not sock.exists():
    print("granite_helper missing")
    raise SystemExit(0)
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10)
s.connect(str(sock))
s.sendall(b'{"jsonrpc":"1.0","id":1,"method":"listmodels","params":[]}\n')
s.shutdown(socket.SHUT_WR)
data=b""
while True:
    c=s.recv(1<<20)
    if not c: break
    data+=c
    if b"\n" in data: break
s.close()
m=json.loads(data.decode()).get("result") or {}
models=m.get("models") or []
if not models:
    print("granite_models 0")
else:
    x=models[0]
    print("granite_bytes", x.get("bytes"), "seeded", x.get("seeded"), "admission", x.get("content_admission") or x.get("admission"))
PY
echo '---SOCKS---'
ss -ltn | grep -E '29447|29448' || true
EOS
)" || die "fetcher ssh"

rtx_out="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$RTX" "PROD_PIDS='$PROD_RTX' bash -s" <<'EOS' || true
set -euo pipefail
ps -p $PROD_PIDS -o pid= || true
echo '---GPU---'
nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv
echo '---SEEDER---'
python3 -s <<'PY'
import json, socket
from pathlib import Path
cands=list(Path("/opt/btx-0347-rc").rglob("modeld.sock")) + list(Path("/run").glob("**/modeld.sock"))
sock=None
for p in cands:
    if p.is_socket():
        sock=p
        break
print("seeder_sock", sock)
if sock is None:
    raise SystemExit(0)
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10)
s.connect(str(sock))
s.sendall(b'{"jsonrpc":"1.0","id":1,"method":"listmodels","params":[]}\n')
s.shutdown(socket.SHUT_WR)
data=b""
while True:
    c=s.recv(1<<20)
    if not c: break
    data+=c
    if b"\n" in data: break
s.close()
m=json.loads(data.decode()).get("result") or {}
models=m.get("models") or []
if models:
    x=models[0]
    print("seeder_bytes", x.get("bytes"), "seeded", x.get("seeded"), "admission", x.get("content_admission") or x.get("admission"))
else:
    print("seeder_models 0")
PY
ss -ltn | grep -E '29447|29448' || true
EOS
)" || die "seeder ssh"

echo "== fetcher =="
echo "$mac_out"
echo "== seeder =="
echo "$rtx_out"

IFS=',' read -r -a fp <<<"$PROD_MAC"
for p in "${fp[@]}"; do
  echo "$mac_out" | grep -q "$p" || die "fetcher production pid $p gone"
done
IFS=',' read -r -a sp <<<"$PROD_RTX"
for p in "${sp[@]}"; do
  echo "$rtx_out" | grep -q "$p" || die "seeder production pid $p gone"
done

mac_b="$(echo "$mac_out" | awk '/granite_bytes/{print $2; exit}')"
rtx_b="$(echo "$rtx_out" | awk '/seeder_bytes/{print $2; exit}')"
if [[ -n "${mac_b:-}" && -n "${rtx_b:-}" ]]; then
  [[ "$mac_b" == "$rtx_b" ]] || die "granite bytes mismatch fetcher=$mac_b seeder=$rtx_b"
  echo "cross-inspect granite bytes match $mac_b"
else
  echo "cross-inspect: one side missing catalog (helper/sock); PIDs still required"
fi
echo "$rtx_out" | grep -q btxd.real || die "seeder GPU still holds production btxd.real"
echo "E2E_CROSS_HOST PASS"
