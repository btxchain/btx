#!/usr/bin/env bash
# Local unix-RPC e2e for btx-modeld. Does not start btxd.
# No WAN, no granite, no operator hosts. Scratch lives on disk (not /tmp tmpfs).
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/build-gcc13/bin"
MODELD="$BIN/btx-modeld"
WORKDIR="$ROOT/e2e-scratch/local-helper"
HELPER_PID=""

cleanup() {
  if [[ -n "${HELPER_PID}" ]] && kill -0 "$HELPER_PID" 2>/dev/null; then
    kill -TERM "$HELPER_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$HELPER_PID" 2>/dev/null || break
      sleep 0.1
    done
    # Test helper only; never production btxd.
    if kill -0 "$HELPER_PID" 2>/dev/null; then
      echo "warning: test helper still running after SIGTERM" >&2
    fi
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

if [[ ! -x "$MODELD" ]]; then
  echo "btx-modeld missing: $MODELD" >&2
  exit 1
fi

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/modeldir" "$WORKDIR/import"
ST="$WORKDIR/import/model.safetensors"
python3 -c 'import struct,sys; open(sys.argv[1],"wb").write(struct.pack("<Q",2)+b"{}")' "$ST"

SOCK="$WORKDIR/modeldir/modeld.sock"
"$MODELD" \
  -modeldir="$WORKDIR/modeldir" \
  -modelstorage=8MiB \
  -modelrpcsocket="$SOCK" \
  >"$WORKDIR/modeld.log" 2>&1 &
HELPER_PID=$!

python3 - "$SOCK" "$ST" "$WORKDIR/modeld.log" "$HELPER_PID" "$ROOT/contrib/modelnet" "$WORKDIR" <<'PY'
import json, socket, sys, time
from pathlib import Path

sock, src, log_path = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
helper_pid = int(sys.argv[4])
sys.path.insert(0, sys.argv[5])
workdir = Path(sys.argv[6])
from failfast import wait_unix


def rpc(method, params, timeout=30):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    reply = json.loads(data.decode())
    if reply.get("error"):
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply["result"]


def wait_ready(seconds=20):
    def connect():
        info = rpc("getmodelnetworkinfo", [])
        if info.get("helper_ready"):
            return info
        return None

    return wait_unix(connect, timeout=seconds, pid=helper_pid, log=log_path)


info = wait_ready()
if not info.get("helper_ready"):
    raise SystemExit(f"helper_ready false: {info}")

imported = rpc("importmodel", [str(src)])
if not isinstance(imported, dict):
    raise SystemExit(f"importmodel expected object: {imported}")
uri = imported.get("uri") or imported.get("model_id")
if not uri:
    raise SystemExit(f"importmodel missing uri/model_id: {imported}")
if imported.get("seeded") is not True:
    raise SystemExit(f"import must demand-seed without seedmodel: {imported}")

listed = rpc("listmodels", [])
if int(listed.get("local_count", 0)) < 1:
    raise SystemExit(f"listmodels local_count < 1: {listed}")

got = rpc("getmodel", [uri, "FREE_ONLY"])
if not isinstance(got, dict):
    raise SystemExit(f"getmodel expected object: {got}")

exported = rpc("exportmodelpath", [uri])
if exported.get("runtime_started") or exported.get("runtime_exec") or exported.get("inference"):
    raise SystemExit(f"exportmodelpath must not start a runtime: {exported}")
if not exported.get("files"):
    raise SystemExit(f"exportmodelpath files: {exported}")

ident = rpc("createmodelidentity", ["e2e-local"])
if ident.get("wallet_backed") or ident.get("contains_wallet_material"):
    raise SystemExit(f"identity must not be wallet-backed: {ident}")
listed_id = rpc("listmodelidentities", [])
if not listed_id.get("identities"):
    raise SystemExit(f"listmodelidentities: {listed_id}")

paid = rpc("getmodel", [uri, "EXPLICIT_PAID"])
if not isinstance(paid, dict):
    raise SystemExit(f"EXPLICIT_PAID: {paid}")
if paid.get("automatic_spend_atoms", paid.get("automatic_spend", 1)) not in (0, "0"):
    raise SystemExit(f"EXPLICIT_PAID must not auto-spend: {paid}")
if "quote" not in paid:
    raise SystemExit(f"EXPLICIT_PAID must journal a quote: {paid}")
if paid.get("funding_rpc") != "preparemodelfunding":
    raise SystemExit(f"EXPLICIT_PAID funding_rpc: {paid}")

plan = rpc("getmodel", [uri, "FREE_FIRST_APPROVAL"])
if not isinstance(plan, dict) or "quote" not in plan:
    raise SystemExit(f"FREE_FIRST_APPROVAL must journal a quote without spend: {plan}")
quotes_path = workdir / "modeldir" / "quotes.json"
if not quotes_path.is_file():
    raise SystemExit(f"quote journal missing: {quotes_path}")
try:
    rpc("preparemodelfunding", [""])
    raise SystemExit("preparemodelfunding empty args must fail")
except RuntimeError as e:
    if "NOT_IMPLEMENTED" in str(e):
        raise SystemExit(f"preparemodelfunding still NOT_IMPLEMENTED: {e}")

recip = rpc("getmodelreciprocity", [])
if not isinstance(recip, dict):
    raise SystemExit(f"getmodelreciprocity: {recip}")

deleg = rpc("delegatemodelservice", [{}])
if not isinstance(deleg, dict):
    raise SystemExit(f"delegatemodelservice: {deleg}")

manifest = rpc("getmodelmanifest", [uri])
if not isinstance(manifest, dict):
    raise SystemExit(f"getmodelmanifest expected object: {manifest}")

job = rpc("getmodeljob", [])
if not isinstance(job, dict):
    raise SystemExit(f"getmodeljob expected object: {job}")

policy = rpc("getmodelpolicy", [])
spend = policy.get("automatic_spend", policy.get("automatic_spend_atoms"))
if spend is None or int(spend) != 0:
    raise SystemExit(f"getmodelpolicy automatic_spend must be 0: {policy}")

print("E2E_LOCAL_HELPER PASS")
print("uri", uri)
print("local_count", listed["local_count"])
print("getmodel_status", got.get("status"))
PY
