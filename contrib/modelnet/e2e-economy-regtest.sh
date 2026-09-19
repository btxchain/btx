#!/usr/bin/env bash
# Isolated -regtest btxd (second process) proving economy RPCs through btx-cli.
# Never touches production btxd.
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ -n "${BIN:-}" && -d "${BIN}" && -x "${BIN}/btxd" ]]; then
  :
else
  BIN="$ROOT/build-gcc13/bin"
fi
WORKDIR="${WORKDIR:-/tmp/btx-econ-regtest-$$}"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/node"
BTXD="$BIN/btxd"
CLI="$BIN/btx-cli"
MODELD="$BIN/btx-modeld"
[[ -x "$BTXD" ]] || { echo "e2e-economy-regtest: missing executable $BTXD (BIN=$BIN)" >&2; exit 1; }
[[ -x "$CLI" ]] || { echo "e2e-economy-regtest: missing executable $CLI (BIN=$BIN)" >&2; exit 1; }
[[ -x "$MODELD" ]] || { echo "e2e-economy-regtest: missing executable $MODELD (BIN=$BIN)" >&2; exit 1; }
# Dedicated ports: never share 18443/18444 with the lab /var/lib/btxd node.
PORT=37744
RPC=37743
DATADIR="$WORKDIR/node"
CLIW=("$CLI" -regtest -datadir="$DATADIR" -rpcport="$RPC" -rpcuser=u -rpcpassword=p)
PID=""
cleanup() {
  local rc=$?
  if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
    "${CLIW[@]}" stop >/dev/null 2>&1 || true
    for i in $(seq 1 40); do
      kill -0 "$PID" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$PID" 2>/dev/null; then
      kill -TERM "$PID" 2>/dev/null || true
      sleep 1
    fi
  fi
  rm -rf "$WORKDIR" /tmp/test_runner_* 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

"$BTXD" -regtest -datadir="$DATADIR" -listen=0 -server=1 \
  -port="$PORT" -rpcport="$RPC" \
  -rpcuser=u -rpcpassword=p -fallbackfee=0.0001 \
  -modelhelper="$MODELD" -modelstorage=8MiB \
  -autoshieldcoinbase=0 \
  -regtestmatmulbindingheight=2147483647 \
  -regtestmatmulproductdigestheight=2147483647 \
  -regtestmatmulv4height=2147483647 \
  -regtestmatmulrequireproductpayload=0 \
  -daemon=0 \
  >"$WORKDIR/btxd.log" 2>&1 &
PID=$!
ok=0
for i in $(seq 1 80); do
  if "${CLIW[@]}" getblockchaininfo >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.25
done
test "$ok" = 1
info="$("${CLIW[@]}" getmodelnetworkinfo)"
echo "$info" | python3 -c 'import json,sys; j=json.load(sys.stdin); assert j.get("automatic_spend_atoms",1)==0'
ready=0
for i in $(seq 1 40); do
  info="$("${CLIW[@]}" getmodelnetworkinfo)"
  if echo "$info" | grep -q '"helper_ready": true'; then ready=1; break; fi
  sleep 0.25
done
test "$ready" = 1

MID="$(python3 -c 'print("a1"+"00"*47)')"
test "${#MID}" = 96
"${CLIW[@]}" publishmodelsearchrecord \
  "$MID" \
  '{"type":"btx-model-search-v1","canonical_name":"RegtestA17","display_name":"RegtestA17","short_description":"A specialized model for coding agents and repository tool use.","expires_at":0}'

sm="$("${CLIW[@]}" searchmodels '{"text":"coding agent","scope":"LOCAL"}')"
echo "$sm" | python3 -c 'import json,sys
j=json.load(sys.stdin)
assert j.get("automatic_spend_atoms",1)==0
names=[h.get("name") for h in (j.get("results") or [])]
assert "RegtestA17" in names, names
assert any(h.get("result_type")=="PUBLIC_MODEL" for h in (j.get("results") or [])), j
'
feed="$("${CLIW[@]}" getmodelfeed '{"scope":"LOCAL","mode":"NEWEST","limit":20}')"
echo "$feed" | python3 -c 'import json,sys
j=json.load(sys.stdin)
assert j.get("coverage",{}).get("global_complete") is not True
assert j.get("automatic_spend_atoms",1)==0
assert j.get("feed_sequence",0)>=1
'
econ="$("${CLIW[@]}" getmodeleconomyentry "$MID")"
echo "$econ" | python3 -c 'import json,sys
j=json.load(sys.stdin)
assert j.get("schema_version")==3
assert (j.get("lifecycle") or {}).get("state") or j.get("lifecycle_state")
assert j.get("automatic_spend_atoms")==0
'
"${CLIW[@]}" getblockchaininfo >/dev/null

"${CLIW[@]}" createwallet w >/dev/null
ADDR="$("${CLIW[@]}" -rpcwallet=w getnewaddress)"
"${CLIW[@]}" generatetoaddress 101 "$ADDR" >/dev/null
python3 - "$DATADIR" "$WORKDIR" "$CLI" "$RPC" <<'PY'
import json, os, socket, struct, subprocess, sys, time
from pathlib import Path
datadir, workdir, cli = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
rpcport = sys.argv[4]
cliw = [cli, "-regtest", f"-datadir={datadir}", "-rpcuser=u", "-rpcpassword=p", f"-rpcport={rpcport}", "-rpcwallet=w"]

def cli(*args):
    out = subprocess.check_output([*cliw, *args], text=True)
    out = out.strip()
    if not out:
        return {}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out

src = workdir / "weights.safetensors"
n = 64
header = {"w": {"dtype": "F32", "shape": [n], "data_offsets": [0, n * 4]}}
hb = json.dumps(header, separators=(",", ":")).encode()
src.write_bytes(struct.pack("<Q", len(hb)) + hb + bytes(n * 4))
imp = cli("importmodel", str(src), '{"pin":true}')
uri = imp.get("uri")
if not uri:
    raise SystemExit(f"importmodel {imp}")
secret = "22" * 32
height = int(cli("getblockcount")) + 1000
rel = cli("createmodelrelease", json.dumps({
    "uri": uri,
    "secret32_hex": secret,
    "refund_height": height,
    "target_atoms": 100000,
    "publish_search_record": True,
    "display_name": "RegtestFunded",
    "short_description": "chain join campaign",
}))
rid = rel.get("release_id") or rel.get("id")
econ = cli("getmodelreleaseeconomics", rid)
kh = (econ.get("key_hash") or (econ.get("release") or {}).get("key_hash") or
      rel.get("key_hash"))
if not kh:
    raise SystemExit(f"no key_hash {econ} {rel}")
def dummy(seed):
    return bytes((seed + i) & 0xFF for i in range(1312)).hex()
opts = {
    "release_id": rid,
    "key_hash": kh,
    "claimant": dummy(0x21),
    "refund_pubkey": dummy(0x31),
    "refund_height": height,
    "amount_atoms": 100000,
    "auto_pay": False,
    "assurance": "KEY_RELEASE_ONLY",
}
frozen = cli("preparemodelfunding", json.dumps(opts))
if not isinstance(frozen, dict) or "unsigned_hex" not in frozen:
    raise SystemExit(f"preparemodelfunding {frozen}")
if frozen.get("automatic_spend", 1) != 0:
    raise SystemExit(f"auto spend {frozen}")
unsigned = frozen["unsigned_hex"]
signed = cli("signmodelfunding", unsigned, json.dumps(frozen))
if not signed.get("complete"):
    raise SystemExit(f"sign incomplete {signed}")
submitted = cli("submitmodelfunding", signed["hex"], json.dumps(frozen))
txid = submitted.get("txid")
if not txid:
    raise SystemExit(f"submit {submitted}")
addr = cli("getnewaddress")
if isinstance(addr, dict):
    raise SystemExit(addr)
cli("generatetoaddress", "1", addr)
# Join confirmed funding into economy cards.
econ2 = cli("getmodelreleaseeconomics", rid)
rel2 = econ2.get("release") if isinstance(econ2.get("release"), dict) else econ2
src = rel2.get("funding_source") or econ2.get("funding_source")
confirmed = rel2.get("confirmed_funded_atoms", econ2.get("confirmed_funded_atoms"))
if src != "CHAIN_OBSERVATION":
    raise SystemExit(f"funding_source {src} card={econ2}")
if not confirmed or int(confirmed) <= 0:
    raise SystemExit(f"confirmed_funded_atoms {confirmed} {econ2}")
print("ECON chain-join PASS", confirmed, flush=True)
PY
echo "e2e-economy-regtest: PASS"
