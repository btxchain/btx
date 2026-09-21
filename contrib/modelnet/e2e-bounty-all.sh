#!/usr/bin/env bash
# Isolated bounty E2E A–J. Never touches production btxd. One helper/regtest at a time.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Inherited BIN may be a binary (btx-hcpd). Only honor a directory that contains btxd.
if [[ -n "${BIN:-}" && -d "${BIN}" && -x "${BIN}/btxd" ]]; then
  :
elif [[ -n "${BIN_DIR:-}" && -d "${BIN_DIR}" && -x "${BIN_DIR}/btxd" ]]; then
  BIN="$BIN_DIR"
else
  BIN="$ROOT/build-gcc13/bin"
fi
MODELD="${MODELD:-$BIN/btx-modeld}"
TEST_BTX="${TEST_BTX:-$BIN/test_btx}"
BTXD="${BTXD:-$BIN/btxd}"
CLI="${CLI:-$BIN/btx-cli}"
WORKDIR="$ROOT/e2e-scratch/bounty-all-$$"
HELPER_PID=""
BTXD_PID=""
# Dedicated ports: never share 18443/18444 with the lab /var/lib/btxd node.
RPCPORT=37943
failn=0
passn=0

die() { printf 'E2E-BOUNTY FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf 'E2E-BOUNTY %s PASS\n' "$1"; passn=$((passn + 1)); }
bad() { printf 'E2E-BOUNTY %s FAIL: %s\n' "$1" "$2" >&2; failn=$((failn + 1)); }

cleanup() {
  if [[ -n "${HELPER_PID}" ]] && kill -0 "$HELPER_PID" 2>/dev/null; then
    kill -TERM "$HELPER_PID" 2>/dev/null || true
    for _ in $(seq 1 40); do
      kill -0 "$HELPER_PID" 2>/dev/null || break
      sleep 0.05
    done
  fi
  if [[ -n "${BTXD_PID}" ]] && kill -0 "$BTXD_PID" 2>/dev/null; then
    "$CLI" -regtest -datadir="$WORKDIR/node" -rpcuser=u -rpcpassword=p -rpcport="$RPCPORT" stop >/dev/null 2>&1 || true
    for _ in $(seq 1 40); do
      kill -0 "$BTXD_PID" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$BTXD_PID" 2>/dev/null; then
      kill -TERM "$BTXD_PID" 2>/dev/null || true
    fi
  fi
  rm -rf "$WORKDIR" /tmp/test_runner_* 2>/dev/null || true
}
trap cleanup EXIT

[[ -x "$MODELD" ]] || die "missing $MODELD"
[[ -x "$TEST_BTX" ]] || die "missing $TEST_BTX"
[[ -x "$BTXD" ]] || die "missing executable $BTXD (BIN=$BIN)"
[[ -x "$CLI" ]] || die "missing executable $CLI (BIN=$BIN)"

# I — GUI source (no terminal required for the contract)
"$ROOT/contrib/modelnet/e2e-bounty-gui-gates.sh" || die "GUI gates"
ok I-gui-source

# reference codec
( cd "$ROOT/contrib/modelnet/bounty/reference" && python3 -m unittest discover -s . -p 'test_*.py' -v ) \
  || die "python reference"
ok REF-python

# native unit
"$TEST_BTX" --run_test=modelnet_bounty_tests || die "modelnet_bounty_tests"
ok UNIT-native

mkdir -p "$WORKDIR/modeldir" "$WORKDIR/node"
SOCK="$WORKDIR/modeldir/modeld.sock"
"$MODELD" -modeldir="$WORKDIR/modeldir" -modelstorage=8MiB -modelrpcsocket="$SOCK" \
  >"$WORKDIR/modeld.log" 2>&1 &
HELPER_PID=$!

python3 - "$SOCK" "$WORKDIR" "$HELPER_PID" "$ROOT" <<'PY'
import json, os, socket, sys, time, urllib.request
from pathlib import Path

sock, workdir, helper_pid = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
root = Path(sys.argv[4])

def rpc(method, params=None, timeout=30):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}).encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(1 << 20)
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

def wait_ready(seconds=25):
    t0 = time.time()
    while time.time() - t0 < seconds:
        if not Path(f"/proc/{helper_pid}").exists():
            raise SystemExit("helper died")
        try:
            info = rpc("getmodelnetworkinfo")
            if info.get("helper_ready"):
                return info
        except Exception:
            time.sleep(0.2)
            continue
        time.sleep(0.2)
    raise SystemExit("helper_ready timeout")

wait_ready()
caps = rpc("getbountycapabilities")
if caps.get("automatic_spend_atoms") not in (0, "0"):
    raise SystemExit(f"automatic spend: {caps}")
if caps.get("trust_label") != "COUNCIL_CUSTODIAL_AUTHORITY_WITH_INDIVIDUAL_REFUND_PATHS":
    raise SystemExit(f"trust label: {caps}")
ready = {p["id"]: p.get("ready") for p in caps.get("evaluation_profiles", [])}
if not ready.get("EXACT_CHECKS"):
    raise SystemExit("EXACT_CHECKS not ready")
for k, v in ready.items():
    if k != "EXACT_CHECKS" and v:
        raise SystemExit(f"unexecuted profile advertised: {k}")

nid = "0" * 64
terms = {
    "terms_version": 1,
    "network_id": nid,
    "requester_identity": "",
    "title": "Japanese coding model bounty",
    "description": "A specialized model for coding agents and repository tool use.",
    "tags": ["coding"],
    "deliverable_classes": ["weights"],
    "evaluation_spec_id": "EXACT_CHECKS",
    "submission_mode": "PUBLIC",
    "payout_authority": "COUNCIL",
    "council": [{"public_key_hex": bytes((i + j) % 256 for j in range(1312)).hex()} for i in range(1, 6)],
    "threshold": 3,
    "nomination_min_bps": 500,
    "target_atoms": "100000000",
    "max_lots_per_round": 4,
    "funding_close_height": 100,
    "submission_close_height": 200,
    "evaluation_close_height": 300,
    "earliest_award_height": 400,
    "last_safe_award_height": 500,
    "refund_height": 600,
    "minimum_confirmations": 1,
    "claim_margin_blocks": 1,
    "challenge_policy": "typed",
    "selection_rule": "council",
    "license_statement": "open",
    "max_model_bytes": 1048576,
    "fee_policy": "reserve",
    "sealed_confidentiality_disclosure": "",
}
v = rpc("validatebountyterms", [terms])
if v.get("ok") is not True:
    raise SystemExit(f"validate: {v}")
draft = rpc("createbountydraft", [terms])
pub = rpc("publishbounty", [{"draft_id": draft["draft_id"]}])
bounty_id = pub["bounty_id"]
hits = rpc("searchbounties", [{"text": "coding agents", "scope": "LOCAL"}])
if not hits.get("results"):
    raise SystemExit(f"search empty: {hits}")
got = rpc("getbounty", [bounty_id])
if got.get("object_kind") != "BOUNTY":
    raise SystemExit(got)
econ = rpc("getbountyeconomy", [bounty_id])
if econ.get("pledged_atoms") in (None, ""):
    raise SystemExit(f"pledged_atoms missing: {econ}")
# A — discover by description
print("A-discover-ok", bounty_id)

# D — no automatic award
award = rpc("proposebountyaward", [{"bounty_id": bounty_id, "winner": "nobody"}])
if award.get("automatic") or award.get("paid"):
    raise SystemExit(f"automatic award: {award}")
print("D-no-auto-award")

# F — freeze before broadcast (no chain)
frozen = rpc("freezebountyfundinground", [{"bounty_id": bounty_id, "lots": [{"ordinal": 0, "principal_atoms": "1000000"}]}])
if not frozen.get("round_id"):
    raise SystemExit(f"F-freeze missing round_id: {frozen}")
if frozen.get("mutable_outputs") is not False:
    raise SystemExit(f"F-freeze outputs still mutable: {frozen}")
print("F-freeze", frozen.get("round_id"))

# G — mandate budget / refund swap
man = rpc("createagentmandate", [{
    "owner_approval_ref": "e2e",
    "total_atoms": "100",
    "per_action_atoms": "40",
}])
mid = man["mandate_id"]
rpc("reservemandate", [{"idempotency_key": "g1", "amount_atoms": 40, "refund_key": "aa"}])
try:
    rpc("reservemandate", [{"idempotency_key": "g1", "amount_atoms": 40, "refund_key": "bb"}])
    raise SystemExit("refund swap allowed")
except RuntimeError:
    pass
try:
    rpc("reservemandate", [{"idempotency_key": "g2", "amount_atoms": 40, "refund_key": "aa"}])
    rpc("reservemandate", [{"idempotency_key": "g3", "amount_atoms": 40, "refund_key": "aa"}])
    raise SystemExit("budget exceeded")
except RuntimeError:
    pass
print("G-mandate")

# C — staged lineage advertised (both HTLC and refund trees)
caps_blob = json.dumps(caps)
profile = str(caps.get("script_profile", "")).lower()
if "htlc_sha256" not in caps_blob and "htlc" not in profile:
    raise SystemExit(f"script profile missing htlc tree: {caps}")
if "refund" not in profile and "refund" not in caps_blob:
    raise SystemExit(f"script profile missing refund tree: {caps}")
print("C-script-profile")

# E — reorg reverses chain facts
obs = rpc("observebountychain", [{
    "outpoint": "aa:0", "bounty_id": bounty_id, "lot_id": "lot1",
    "amount_atoms": "100", "confirmations": 2, "height": 10,
}])
reorg = rpc("reorgbountychain", [{"bounty_id": bounty_id}])
if not reorg.get("reorg"):
    raise SystemExit(reorg)
print("E-reorg")

# B — recovery export contains no secrets; helper may later be offline
rec = rpc("exportbountyrecovery", [{"bounty_id": bounty_id}])
if rec.get("wallet_seed") not in (None, False, "false", 0, ""):
    raise SystemExit(f"recovery leaked wallet_seed: {rec}")
if rec.get("private_keys") not in (None, False, "false", 0, "", []):
    raise SystemExit(f"recovery leaked private_keys: {rec}")
if rec.get("secrets") not in (None, False, "false", 0, ""):
    raise SystemExit(f"recovery leaked secrets: {rec}")
print("B-recovery")

# J — bounded page / no flood
big = rpc("searchbounties", [{"text": "", "scope": "LOCAL", "limit": 10000}])
if len(big.get("results", [])) > 100:
    raise SystemExit("unbounded page")
print("J-bounds")

# Remaining catalog helper methods (live handlers, not name-only)
rpc("getbountyterms", [bounty_id])
rpc("getmodelbounties", [{"text": "coding agents", "scope": "LOCAL"}])
net = rpc("searchbounties", [{"text": "coding agents", "scope": "NETWORK"}])
if net.get("complete") is True or net.get("global_complete") is True:
    raise SystemExit(f"NETWORK claimed complete: {net}")
if "index_peers_configured" not in net and "fanout_attempted" not in net:
    raise SystemExit(f"NETWORK search did not attempt fanout: {net}")

rev_terms = dict(terms)
rev_terms["title"] = "Revised Japanese coding model bounty"
rev = rpc("revisebounty", [{"bounty_id": bounty_id, "terms": rev_terms}])
if not rev.get("bounty_id") or rev["bounty_id"] == bounty_id:
    raise SystemExit(f"revise id: {rev}")
rpc("nominatebountyevaluator", [{"bounty_id": bounty_id, "nominee_identity": "n1", "nominee_key": "aa"}])
rpc("acceptbountyappointment", [{"terms_id": bounty_id, "appointment": {"bounty_id": bounty_id}}])
rpc("listbountyevaluators", [bounty_id])
pledged = rpc("pledgebounty", [{"bounty_id": bounty_id, "principal_atoms": "1000"}])
rpc("withdrawbountypledge", [{"pledge_id": pledged["pledge_id"]}])
rpc("getbountyfunding", [bounty_id])
cmt = rpc("commitbountysubmission", [{"bounty_id": bounty_id, "digest": "aa"}])
art = workdir / "eval-art"
art.mkdir(parents=True, exist_ok=True)
(art / "weights.safetensors").write_bytes(b"ok")
revsub = rpc("revealbountysubmission", [{
    "commitment_id": cmt["commitment_id"],
    "submission": {"artifact_dir": str(art)},
}])
sid = revsub["submission_id"]
rpc("getbountysubmission", [sid])
rpc("listbountysubmissions", [bounty_id])
plan = rpc("preparebountyevaluation", [{
    "submission_id": sid,
    "profile_id": "EXACT_CHECKS",
    "required_files": ["weights.safetensors"],
    "artifact_dir": str(art),
}])
job = rpc("runbountyevaluation", [{"plan_id": plan["plan_id"], "execution_approval_ref": "e2e"}])
if not job.get("isolated_process"):
    raise SystemExit(f"eval not isolated: {job}")
rpc("getbountyevaluationjob", [job["job_id"]])
pub_eval = rpc("publishbountyevaluation", [{"job_id": job["job_id"]}])
if pub_eval.get("is_award") or pub_eval.get("is_transaction_signature"):
    raise SystemExit(f"eval is award: {pub_eval}")
rpc("listbountyevaluations", [sid])
rpc("cancelbountyevaluation", [job["job_id"]])
chal = rpc("createbountychallenge", [{"bounty_id": bounty_id, "kind": "typed"}])
rpc("listbountychallenges", [bounty_id])
rpc("resolvebountychallenge", [{"challenge_id": chal["challenge_id"], "resolution": {"decision": "OPEN"}}])
aw = rpc("proposebountyaward", [{"bounty_id": bounty_id, "submission_id": sid}])
if aw.get("paid") or aw.get("automatic"):
    raise SystemExit(f"award paid: {aw}")
rpc("approvebountyaward", [{"award_id": aw["award_id"]}])
rpc("getbountyaward", [aw["award_id"]])
rpc("getbountyevents", [{"bounty_id": bounty_id, "limit": 20}])
w = rpc("watchbounty", [bounty_id])
rpc("unwatchbounty", [w["watch_id"]])
rpc("getagentmandate", [mid])
rpc("getagentactivity", [])
rpc("revokeagentmandate", [mid])
rpc("importbountyrecovery", [{"manifest": {"lots": [{"outpoint": "cc:1", "lot_id": "lot2", "amount_atoms": "50"}]}}])
rpc("withdrawbountysubmission", [sid])
feed = rpc("getmodelfeed", [{"scope": "NETWORK", "mode": "NEWEST", "limit": 10}])
if feed.get("global_complete") is True:
    raise SystemExit(f"feed complete: {feed}")
rpc("gettrendingmodels", [{"scope": "LOCAL", "limit": 5}])
print("CATALOG-helper-ok")

# H — explorer files are GET-only
exp = (root / "contrib/modelnet/explorer-bounties/app.js").read_text()
for forbidden in ("preparebounty", "createagentmandate", "runbountyevaluation", "signbounty", "submitbounty"):
    if forbidden in exp:
        raise SystemExit(f"explorer calls {forbidden}")
if "/api/v1/bounties" not in exp:
    raise SystemExit("explorer missing /api/v1/bounties")
print("H-explorer-source")
print("HELPER-RPC-OK")
PY
ok A-H-helper

# Live-path wallet RPC inventory via isolated regtest btxd (never production).
mkdir -p "$WORKDIR/node"
"$BTXD" -regtest -datadir="$WORKDIR/node" -listen=0 -server=1 -nomodelnet \
  -rpcuser=u -rpcpassword=p -rpcport="$RPCPORT" -fallbackfee=0.0001 -daemon=0 \
  >"$WORKDIR/btxd.log" 2>&1 &
BTXD_PID=$!
ready=0
for _ in $(seq 1 80); do
  if "$CLI" -regtest -datadir="$WORKDIR/node" -rpcuser=u -rpcpassword=p -rpcport="$RPCPORT" getblockchaininfo >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done
[[ "$ready" = 1 ]] || die "isolated btxd rpc not ready (see $WORKDIR/btxd.log)"
for rpcname in preparebountyfunding inspectbountytransaction signbountyfunding submitbountyfunding \
               inspectbountyaward signbountyaward submitbountyaward preparebountyclaim signbountyclaim \
               submitbountyclaim preparebountyrefund signbountyrefund submitbountyrefund \
               searchbounties getbountycapabilities getmodelfeed; do
  helpout="$("$CLI" -regtest -datadir="$WORKDIR/node" -rpcuser=u -rpcpassword=p -rpcport="$RPCPORT" help "$rpcname" 2>&1)" \
    || die "RPC help failed: $rpcname"
  if echo "$helpout" | grep -qi 'unknown command\|not found\|method not found'; then
    die "RPC not registered: $rpcname ($helpout)"
  fi
  echo "$helpout" | grep -Fq "$rpcname" || die "RPC help missing $rpcname ($helpout)"
done
"$CLI" -regtest -datadir="$WORKDIR/node" -rpcuser=u -rpcpassword=p -rpcport="$RPCPORT" stop >/dev/null 2>&1 || true
for _ in $(seq 1 40); do
  kill -0 "$BTXD_PID" 2>/dev/null || break
  sleep 0.1
done
BTXD_PID=""
ok WALLET-rpc-help
BTX_BOUNTY_E2E_SCALE_CAP="${BTX_BOUNTY_E2E_SCALE_CAP:-32}" \
  BIN="$BIN" MODELD="$MODELD" python3 "$ROOT/contrib/modelnet/e2e-bounty-scenarios.py" \
  || die "e2e-bounty-scenarios"
ok E2E-A-J-regtest

# HTTP bridge 403 on wallet/eval/mandate (H) — native HandleBridgeRequest 403s must exist
python3 - "$ROOT/src/test/modelnet_bounty_tests.cpp" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
need = (
    ("/signbountyfunding", "403"),
    ("/api/v1/runbountyevaluation", "403"),
    ("/createagentmandate", "403"),
)
for path, status in need:
    i = text.find(f'HandleBridgeRequest("GET", "{path}"')
    if i < 0:
        raise SystemExit(f"missing HandleBridgeRequest GET {path}")
    window = text[i:i + 280]
    if status not in window:
        raise SystemExit(f"{path} missing {status}: {window}")
print("H-bridge-unit source 403s present")
PY
ok H-bridge-unit

# B continued: helper crash must not be required for refund path in source
grep -n 'preparebountyrefund' "$ROOT/src/rpc/modelnet.cpp" >/dev/null || die "preparebountyrefund missing"
grep -n 'MergeHelperCampaign' "$ROOT/src/wallet/model_funding.cpp" >/dev/null || die "MergeHelperCampaign missing"
grep -n 'helper cannot supply amount' "$ROOT/src/wallet/model_funding.cpp" >/dev/null \
  || grep -n 'GAP-12' "$ROOT/src/wallet/model_funding.cpp" >/dev/null \
  || die "GAP-12 no-op missing"
ok B-refund-source

# J soak: helper still alive, no /tmp leak of this run
[[ -n "${HELPER_PID}" ]] && kill -0 "$HELPER_PID" 2>/dev/null || die "helper died before J-resource"
ok J-resource

if [[ "$failn" -ne 0 ]]; then
  die "$failn scenarios failed ($passn passed)"
fi
echo "E2E-BOUNTY-ALL PASS ($passn checks). Isolated only. NOT a release."
