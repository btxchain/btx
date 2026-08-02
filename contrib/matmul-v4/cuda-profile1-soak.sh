#!/usr/bin/env bash
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
#
# Bounded CUDA Profile-1 ExactReplay soak harness (pre-ratification).
#
# Roadmap §4 gate 7 asks for a multi-day multi-peer testnet soak. This script
# is an intentionally narrower one-GPU-host kickoff: two local regtest nodes,
# block relay, competing branches, restarts, cache persistence probes, and a
# bounded IBD catch-up. It does NOT claim gate-7 completion and must never
# flip ratification constants.
#
# Typical resume (after higher-priority campaign agents release the GPU):
#   mkdir -p /tmp/btx-pr97-campaigns/logs/soak
#   nohup env \
#     BTX_SOAK_DURATION_SECS=14400 \
#     BTX_SOAK_LOG_DIR=/tmp/btx-pr97-campaigns/logs/soak \
#     BTX_SOAK_STATUS_JSON=/tmp/btx-pr97-campaigns/status/soak.json \
#     BTX_SOAK_GPU_LOCK=/tmp/btx-pr97-campaigns/locks/gpu.lock \
#     BTX_BUILD_DIR="$PWD/build-cuda" \
#     ./contrib/matmul-v4/cuda-profile1-soak.sh \
#     > /tmp/btx-pr97-campaigns/logs/soak/nohup.out 2>&1 &
#   echo $! > /tmp/btx-pr97-campaigns/logs/soak/soak.pid
#
# Logs destined for public evidence must stay sanitized: no hostname, username,
# or home-directory paths. Runtime status under /tmp may include local paths.
#
# Exit: 0 = soak completed within budget without hard failures;
#       1 = runtime/assertion failure; 2 = usage / missing binary / lock refuse.

export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BTX_BUILD_DIR:-${ROOT}/build-cuda}"
BTXD="${BTX_BTXD:-${BUILD_DIR}/bin/btxd}"
BTXCLI="${BTX_BTXCLI:-${BUILD_DIR}/bin/btx-cli}"

DURATION_SECS="${BTX_SOAK_DURATION_SECS:-14400}"   # default 4h
MINE_INTERVAL_SECS="${BTX_SOAK_MINE_INTERVAL_SECS:-90}"
RESTART_INTERVAL_SECS="${BTX_SOAK_RESTART_INTERVAL_SECS:-900}"
BRANCH_INTERVAL_SECS="${BTX_SOAK_BRANCH_INTERVAL_SECS:-1200}"
IBD_INTERVAL_SECS="${BTX_SOAK_IBD_INTERVAL_SECS:-1800}"
IBD_LAG_BLOCKS="${BTX_SOAK_IBD_LAG_BLOCKS:-3}"
RC_HEIGHT="${BTX_SOAK_RC_HEIGHT:-6}"
# Default 128 + toy dims keeps two concurrent CUDA ExactReplay processes
# practical for multi-hour soak; set BTX_SOAK_MODE=production for dim=4096.
SOAK_MODE="${BTX_SOAK_MODE:-toy}"
if [[ "${SOAK_MODE}" == "production" ]]; then
  V4_DIM="${BTX_SOAK_V4_DIM:-4096}"
  TOY_DIMS=0
  # Production-dim ExactReplay must stay on the strict device path.
  RC_EXECUTION="${BTX_SOAK_RC_EXECUTION:-strict-device}"
else
  V4_DIM="${BTX_SOAK_V4_DIM:-128}"
  TOY_DIMS=1
  # Toy RC fixtures resolve ExactReplay to toy-rc; strict-device then fails
  # AcceptBlock with "local execution failed". auto-fallback keeps CUDA mining
  # while allowing the portable ExactReplay oracle for the soak boundary.
  RC_EXECUTION="${BTX_SOAK_RC_EXECUTION:-auto-fallback}"
fi
DISABLED_HEIGHT=2147483647
V3_BINDING_HEIGHT=2
RPC_USER="${BTX_SOAK_RPC_USER:-soak_cuda}"
RPC_PASS="${BTX_SOAK_RPC_PASS:-soak_cuda_password}"
BASE_PORT="${BTX_SOAK_BASE_PORT:-18440}"
WORKDIR="${BTX_SOAK_WORKDIR:-/tmp/btx-pr97-campaigns/logs/soak/runtime}"
LOG_DIR="${BTX_SOAK_LOG_DIR:-/tmp/btx-pr97-campaigns/logs/soak}"
STATUS_JSON="${BTX_SOAK_STATUS_JSON:-/tmp/btx-pr97-campaigns/status/soak.json}"
GPU_LOCK="${BTX_SOAK_GPU_LOCK:-/tmp/btx-pr97-campaigns/locks/gpu.lock}"
REQUIRE_EXCLUSIVE="${BTX_SOAK_REQUIRE_EXCLUSIVE:-1}"
KEEP_RUNTIME="${BTX_SOAK_KEEP_RUNTIME:-1}"

METRICS_JSONL="${LOG_DIR}/metrics.jsonl"
EVENTS_LOG="${LOG_DIR}/events.log"
SUMMARY_JSON="${LOG_DIR}/summary.json"
SANITIZED_METRICS="${LOG_DIR}/metrics.sanitized.jsonl"

usage() {
  cat <<'EOF'
Usage: cuda-profile1-soak.sh

Env knobs (defaults shown):
  BTX_BUILD_DIR                 $ROOT/build-cuda
  BTX_SOAK_DURATION_SECS        14400
  BTX_SOAK_MINE_INTERVAL_SECS   90
  BTX_SOAK_RESTART_INTERVAL_SECS 900
  BTX_SOAK_BRANCH_INTERVAL_SECS 1200
  BTX_SOAK_IBD_INTERVAL_SECS    1800
  BTX_SOAK_IBD_LAG_BLOCKS       3
  BTX_SOAK_MODE                 toy          # or production (dim 4096)
  BTX_SOAK_V4_DIM               128/4096 by mode
  BTX_SOAK_RC_HEIGHT            6
  BTX_SOAK_LOG_DIR              /tmp/btx-pr97-campaigns/logs/soak
  BTX_SOAK_STATUS_JSON          /tmp/btx-pr97-campaigns/status/soak.json
  BTX_SOAK_GPU_LOCK             /tmp/btx-pr97-campaigns/locks/gpu.lock
  BTX_SOAK_REQUIRE_EXCLUSIVE    1   # flock exclusive gpu.lock or refuse
  BTX_SOAK_KEEP_RUNTIME         1

Scenarios exercised (one GPU host, two local regtest peers):
  relay            mine on A, wait for B tip match + relay telemetry
  competing_branch disconnect, mine divergent tips, reconnect, converge
  restart          stop/start B, re-check CUDA canary + tip catch-up
  cache_persist    after restart, require CUDA provider and mine again
  ibd_boundary     stop B, mine lag on A, restart B and sync (bounded)

Not covered here (explicitly out of scope for this harness):
  multi-day wall clock, multi-peer public testnet, DoS admission storms,
  ASERT calibration campaigns, ratification / activation gate flips.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ ! -x "${BTXD}" || ! -x "${BTXCLI}" ]]; then
  echo "error: missing binaries under ${BUILD_DIR}/bin (need btxd + btx-cli)" >&2
  exit 2
fi

mkdir -p "${LOG_DIR}" "${WORKDIR}" "$(dirname "${STATUS_JSON}")" "$(dirname "${GPU_LOCK}")"
: >"${METRICS_JSONL}"
: >"${EVENTS_LOG}"
: >"${SANITIZED_METRICS}"

LOCK_FD=""
acquire_gpu_lock() {
  # Exclusive ownership for GPU-heavy soak sections. Higher-priority campaign
  # agents are expected to hold the same path while they run.
  exec {LOCK_FD}>"${GPU_LOCK}"
  if [[ "${REQUIRE_EXCLUSIVE}" == "1" ]]; then
    if ! flock -n "${LOCK_FD}"; then
      echo "error: could not acquire exclusive ${GPU_LOCK}; another campaign holds the GPU" >&2
      exit 2
    fi
  else
    flock "${LOCK_FD}"
  fi
}

release_gpu_lock() {
  if [[ -n "${LOCK_FD}" ]]; then
    flock -u "${LOCK_FD}" || true
    eval "exec ${LOCK_FD}>&-" || true
    LOCK_FD=""
  fi
}

now_iso() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
now_epoch() { date -u +%s; }

# Held in a variable and passed with `python3 -c`, NOT as `python3 - <<PY`.
# With `python3 -`, the interpreter reads its PROGRAM from stdin, so the piped
# input this function is supposed to sanitize was consumed by the interpreter
# and sys.stdin.read() always returned "". Every "sanitized" evidence file
# (events.sanitized.log, metrics.sanitized.jsonl) was therefore written empty
# while the gate appeared to pass.
read -r -d '' SANITIZE_PY <<'PY' || true
import os, re, sys
line = sys.stdin.read() if not sys.argv[1:] else open(sys.argv[1], encoding="utf-8").read()
home = os.path.expanduser("~")
user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
host = os.uname().nodename if hasattr(os, "uname") else ""
for token in filter(None, [home, user, host]):
    line = line.replace(token, "<redacted>")
line = re.sub(r"/home/[^/\s]+", "/home/<redacted>", line)
line = re.sub(r"/Users/[^/\s]+", "/Users/<redacted>", line)
# Additional hostnames to scrub, supplied by the operator at run time as a
# comma-separated list. Deliberately NOT hard-coded: a redaction list that
# names real machines publishes exactly what it exists to hide, which is what
# the previous literal pattern here did.
for extra in filter(None, (h.strip() for h in os.environ.get("BTX_SANITIZE_EXTRA_HOSTS", "").split(","))):
    line = re.sub(re.escape(extra), "<host>", line, flags=re.I)
sys.stdout.write(line)
PY

sanitize_line() {
  # Strip home paths, usernames, and hostnames from lines copied into evidence.
  python3 -c "${SANITIZE_PY}" "$@"
}

event() {
  local msg="$1"
  local line
  line="$(printf '%s %s\n' "$(now_iso)" "${msg}")"
  printf '%s\n' "${line%$'\n'}" >>"${EVENTS_LOG}"
  printf '%s\n' "${line%$'\n'}" | sanitize_line >>"${LOG_DIR}/events.sanitized.log"
}

write_status() {
  local status="$1"
  local note="${2:-}"
  local elapsed=0
  if [[ -n "${SOAK_START_EPOCH:-}" ]]; then
    elapsed=$(( $(now_epoch) - SOAK_START_EPOCH ))
  fi
  python3 - "${STATUS_JSON}" "${status}" "${note}" "${elapsed}" "${DURATION_SECS}" \
    "${SCENARIO_COUNTS_JSON:-{}}" "${SOAK_PID:-$$}" <<'PY'
import json, sys, datetime
path, status, note, elapsed, planned, counts_s, pid = sys.argv[1:8]
try:
    counts = json.loads(counts_s)
except Exception:
    counts = {}
payload = {
    "agent": "SOAK",
    "priority": 5,
    "status": status,
    "ratification": False,
    "gate7_claim": False,
    "scope": "bounded_one_gpu_host_pre_ratification",
    "planned_duration_secs": int(planned),
    "elapsed_secs": int(elapsed),
    "pid": int(pid),
    "scenarios": counts,
    "note": note,
    "updated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
PY
}

cli_a() {
  "${BTXCLI}" -regtest -datadir="${WORKDIR}/nodeA" -rpcport="${PORT_A}" \
    -rpcuser="${RPC_USER}" -rpcpassword="${RPC_PASS}" -rpcwait -rpcwaittimeout=180 "$@"
}
cli_b() {
  "${BTXCLI}" -regtest -datadir="${WORKDIR}/nodeB" -rpcport="${PORT_B}" \
    -rpcuser="${RPC_USER}" -rpcpassword="${RPC_PASS}" -rpcwait -rpcwaittimeout=180 "$@"
}

# NOTE: this heredoc is expanded straight into btxd's argv -- every line is an
# argument. Do NOT put shell comments inside it; `# noban must be explicit...`
# previously reached the daemon as `Invalid command '# noban...'` and the soak
# could never start a node. Rationale for -whitelist=noban below: consensus-mode
# sync stalls when NODE_MATMUL_CONSENSUS is unpublished (empty production golden
# canary), so noban must be explicit.
node_common_args() {
  local datadir="$1" rpcport="$2" p2pport="$3"
  # Epoch-A height package mirrors measure-cuda-lifecycle-campaign.py so
  # ValidateMatMulAsertParams / BMX4C construction invariants hold.
  cat <<EOF
-regtest
-datadir=${datadir}
-rpcport=${rpcport}
-port=${p2pport}
-rpcuser=${RPC_USER}
-rpcpassword=${RPC_PASS}
-server=1
-listen=1
-discover=0
-dnsseed=0
-fixedseeds=0
-listenonion=0
-upnp=0
-natpmp=0
-externalip=127.0.0.1
-bind=127.0.0.1
-whitelist=noban,in,out@127.0.0.1
-miningminoutboundpeers=0
-miningminsyncedoutboundpeers=0
-matmulvalidation=consensus
-matmulrcexecution=${RC_EXECUTION}
-matmulasyncverify=1
-regtestmatmulbindingheight=${V3_BINDING_HEIGHT}
-regtestmatmulproductdigestheight=${V3_BINDING_HEIGHT}
-regtestmatmulrequireproductpayload=0
-regtestmatmulv4height=${RC_HEIGHT}
-regtestbmx4cheight=${RC_HEIGHT}
-regtestdrltheight=${DISABLED_HEIGHT}
-regtestrcheight=${RC_HEIGHT}
-regtestrccoupledheight=${DISABLED_HEIGHT}
-regtestrcprofile=1
-regtestrctoydims=${TOY_DIMS}
-regtestrccoupledtoydims=0
-regtestmatmulltsealaspow=0
-regtestmatmulv4dimension=${V4_DIM}
-regtestmatmulv4maxdimension=${V4_DIM}
-printtoconsole=0
EOF
}

start_node() {
  local which="$1"
  local datadir rpcport p2pport
  if [[ "${which}" == "A" ]]; then
    datadir="${WORKDIR}/nodeA"; rpcport="${PORT_A}"; p2pport="${P2P_A}"
  else
    datadir="${WORKDIR}/nodeB"; rpcport="${PORT_B}"; p2pport="${P2P_B}"
  fi
  mkdir -p "${datadir}"
  mapfile -t args < <(node_common_args "${datadir}" "${rpcport}" "${p2pport}")
  env BTX_MATMUL_BACKEND=cuda BTX_MATMUL_V4_BACKEND=cuda BTX_MATMUL_REQUIRE_BACKEND=cuda \
    "${BTXD}" "${args[@]}" -daemonwait
}

stop_node() {
  local which="$1"
  if [[ "${which}" == "A" ]]; then
    cli_a stop >/dev/null 2>&1 || true
  else
    cli_b stop >/dev/null 2>&1 || true
  fi
  local pidfile
  if [[ "${which}" == "A" ]]; then
    pidfile="${WORKDIR}/nodeA/regtest/btxd.pid"
  else
    pidfile="${WORKDIR}/nodeB/regtest/btxd.pid"
  fi
  local deadline=$(( $(now_epoch) + 60 ))
  while [[ -f "${pidfile}" && $(now_epoch) -lt ${deadline} ]]; do
    sleep 0.2
  done
  if [[ -f "${pidfile}" ]]; then
    local pid
    pid="$(tr -d '[:space:]' <"${pidfile}" || true)"
    if [[ -n "${pid}" ]]; then
      kill "${pid}" >/dev/null 2>&1 || true
      sleep 1
      kill -9 "${pid}" >/dev/null 2>&1 || true
    fi
    rm -f "${pidfile}"
  fi
}

wait_rpc() {
  local which="$1"
  local deadline=$(( $(now_epoch) + 240 ))
  while [[ $(now_epoch) -lt ${deadline} ]]; do
    if [[ "${which}" == "A" ]]; then
      cli_a getblockcount >/dev/null 2>&1 && return 0
    else
      cli_b getblockcount >/dev/null 2>&1 && return 0
    fi
    sleep 1
  done
  echo "error: RPC timeout waiting for node ${which}" >&2
  return 1
}

connect_peers() {
  cli_a addnode "127.0.0.1:${P2P_B}" onetry >/dev/null 2>&1 || true
  cli_b addnode "127.0.0.1:${P2P_A}" onetry >/dev/null 2>&1 || true
}

disconnect_peers() {
  cli_a disconnectnode "127.0.0.1:${P2P_B}" >/dev/null 2>&1 || true
  cli_b disconnectnode "127.0.0.1:${P2P_A}" >/dev/null 2>&1 || true
  sleep 1
}

wait_tips_equal() {
  local timeout_s="${1:-600}"
  local deadline=$(( $(now_epoch) + timeout_s ))
  while [[ $(now_epoch) -lt ${deadline} ]]; do
    local ha hb
    ha="$(cli_a getbestblockhash)"
    hb="$(cli_b getbestblockhash)"
    if [[ "${ha}" == "${hb}" ]]; then
      return 0
    fi
    connect_peers
    sleep 2
  done
  echo "error: tips diverged beyond timeout" >&2
  return 1
}

record_metrics() {
  local which="$1"
  local scenario="$2"
  local info
  if [[ "${which}" == "A" ]]; then
    info="$(cli_a getmininginfo)"
  else
    info="$(cli_b getmininginfo)"
  fi
  local line
  line="$(INFO_JSON="${info}" WHICH="${which}" SCENARIO="${scenario}" python3 <<'PY'
import json, os, datetime
info = json.loads(os.environ["INFO_JSON"])
which = os.environ["WHICH"]
scenario = os.environ["SCENARIO"]
rt = info.get("backend_runtime") or {}
rc = rt.get("rc_exact_replay") or {}
canary = rc.get("production_canary") or {}
sched = rt.get("rc_accelerator_scheduler") or {}
ready = sched.get("complete_lifecycle_readiness") or {}
out = {
  "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "scenario": scenario,
  "node": which,
  "blocks": info.get("blocks"),
  "active_backend": rt.get("active_backend"),
  "required_backend_satisfied": rt.get("required_backend_satisfied"),
  "resolved_provider": rc.get("resolved_provider"),
  "canary_outcome": canary.get("outcome"),
  "device_architecture": canary.get("device_architecture"),
  "cuda_fallbacks_to_cpu": rt.get("cuda_fallbacks_to_cpu"),
  "authenticated_relay_samples": sched.get("authenticated_relay_samples"),
  "last_authenticated_relay_s": sched.get("last_authenticated_relay_s"),
  "max_authenticated_relay_s": sched.get("max_authenticated_relay_s"),
  "authenticated_relay_measured": ready.get("authenticated_relay_measured"),
  "within_target_spacing": ready.get("within_target_spacing"),
}
print(json.dumps(out, sort_keys=True))
PY
)"
  printf '%s\n' "${line}" >>"${METRICS_JSONL}"
  printf '%s\n' "${line}" | sanitize_line >>"${SANITIZED_METRICS}"

  # Hard fail-closed checks for CUDA soak integrity.
  # Toy-dim RC fixtures resolve ExactReplay to the portable cpu_reference
  # provider by design; mining still requires the CUDA active backend.
  # Production-dim soaks additionally require a CUDA ExactReplay provider.
  METRIC_LINE="${line}" SOAK_MODE="${SOAK_MODE}" python3 <<'PY'
import json, os, sys
m = json.loads(os.environ["METRIC_LINE"])
mode = os.environ.get("SOAK_MODE", "toy")
active = (m.get("active_backend") or "").lower()
if active != "cuda":
    sys.exit(f"active_backend is not cuda on node {m.get('node')}: {m.get('active_backend')}")
if not m.get("required_backend_satisfied", False):
    sys.exit(f"required CUDA backend unsatisfied on node {m.get('node')}")
prov = (m.get("resolved_provider") or "").lower()
if mode == "production" and "cuda" not in prov:
    sys.exit(f"non-CUDA ExactReplay provider on node {m.get('node')}: {m.get('resolved_provider')}")
fb = m.get("cuda_fallbacks_to_cpu")
if fb not in (None, 0):
    sys.exit(f"cuda_fallbacks_to_cpu={fb} on node {m.get('node')}")
PY
}

assert_cuda_ready() {
  local which="$1"
  record_metrics "${which}" "health"
}

mine_one() {
  local which="$1"
  local n="${2:-1}"
  if [[ "${which}" == "A" ]]; then
    cli_a generatetodescriptor "${n}" "raw(51)" >/dev/null
  else
    cli_b generatetodescriptor "${n}" "raw(51)" >/dev/null
  fi
}

scenario_relay() {
  event "scenario=relay start"
  mine_one A 1
  wait_tips_equal 900
  record_metrics A "relay" 1
  record_metrics B "relay" 1
  SCENARIO_COUNTS[relay]=$(( ${SCENARIO_COUNTS[relay]:-0} + 1 ))
  event "scenario=relay ok"
}

scenario_competing_branch() {
  event "scenario=competing_branch start"
  disconnect_peers
  local tip_a tip_b
  tip_a="$(cli_a getbestblockhash)"
  tip_b="$(cli_b getbestblockhash)"
  if [[ "${tip_a}" != "${tip_b}" ]]; then
    connect_peers
    wait_tips_equal 900
  fi
  # Divergent work while isolated (sequential mines to limit dual-GPU VRAM spike).
  mine_one A 1
  sleep 2
  mine_one B 1
  connect_peers
  # Prefer the heavier side by mining one more on A after reconnect window.
  sleep 2
  mine_one A 1
  wait_tips_equal 1200
  record_metrics A "competing_branch" 1
  record_metrics B "competing_branch" 1
  SCENARIO_COUNTS[competing_branch]=$(( ${SCENARIO_COUNTS[competing_branch]:-0} + 1 ))
  event "scenario=competing_branch ok"
}

scenario_restart_and_cache() {
  event "scenario=restart_cache start"
  local height_before
  height_before="$(cli_a getblockcount)"
  stop_node B
  start_node B
  wait_rpc B
  connect_peers
  assert_cuda_ready B 1
  wait_tips_equal 1200
  mine_one A 1
  wait_tips_equal 900
  record_metrics B "cache_persist" 1
  local height_after
  height_after="$(cli_b getblockcount)"
  if [[ "${height_after}" -lt "${height_before}" ]]; then
    echo "error: node B lost height across restart (${height_after} < ${height_before})" >&2
    return 1
  fi
  SCENARIO_COUNTS[restart]=$(( ${SCENARIO_COUNTS[restart]:-0} + 1 ))
  SCENARIO_COUNTS[cache_persist]=$(( ${SCENARIO_COUNTS[cache_persist]:-0} + 1 ))
  event "scenario=restart_cache ok height_before=${height_before} height_after=${height_after}"
}

scenario_ibd_boundary() {
  event "scenario=ibd_boundary start"
  stop_node B
  mine_one A "${IBD_LAG_BLOCKS}"
  local height_a
  height_a="$(cli_a getblockcount)"
  start_node B
  wait_rpc B
  connect_peers
  wait_tips_equal 1800
  local height_b
  height_b="$(cli_b getblockcount)"
  if [[ "${height_b}" -ne "${height_a}" ]]; then
    echo "error: IBD catch-up mismatch A=${height_a} B=${height_b}" >&2
    return 1
  fi
  record_metrics A "ibd_boundary" 1
  record_metrics B "ibd_boundary" 1
  assert_cuda_ready B 1
  SCENARIO_COUNTS[ibd_boundary]=$(( ${SCENARIO_COUNTS[ibd_boundary]:-0} + 1 ))
  event "scenario=ibd_boundary ok lag=${IBD_LAG_BLOCKS} height=${height_a}"
}

counts_json() {
  python3 -c 'import json,os; print(json.dumps({
  "relay": int(os.environ.get("C_RELAY","0")),
  "competing_branch": int(os.environ.get("C_BRANCH","0")),
  "restart": int(os.environ.get("C_RESTART","0")),
  "cache_persist": int(os.environ.get("C_CACHE","0")),
  "ibd_boundary": int(os.environ.get("C_IBD","0")),
}))'
}

# Wrapper that exports counts for counts_json
export_counts() {
  export C_RELAY="${SCENARIO_COUNTS[relay]:-0}"
  export C_BRANCH="${SCENARIO_COUNTS[competing_branch]:-0}"
  export C_RESTART="${SCENARIO_COUNTS[restart]:-0}"
  export C_CACHE="${SCENARIO_COUNTS[cache_persist]:-0}"
  export C_IBD="${SCENARIO_COUNTS[ibd_boundary]:-0}"
}

write_summary() {
  local status="$1"
  local elapsed="$2"
  python3 - "${SUMMARY_JSON}" "${status}" "${elapsed}" "${DURATION_SECS}" "$(counts_json)" <<'PY'
import json, sys, datetime
path, status, elapsed, planned, counts_s = sys.argv[1:6]
counts = json.loads(counts_s)
payload = {
  "title": "CUDA Profile-1 bounded soak (pre-ratification)",
  "ratification": False,
  "gate7_multi_day_multi_peer_claim": False,
  "status": status,
  "planned_duration_secs": int(planned),
  "elapsed_secs": int(elapsed),
  "hardware_class": {
    "os": "Linux x86_64",
    "gpu": "NVIDIA consumer Blackwell-class discrete GPU, 16 GiB VRAM, CC 12.0",
    "note": "hostname/username redacted from evidence copies",
  },
  "scenarios": counts,
  "not_covered": [
    "multi-day wall-clock soak",
    "multi-peer public/testnet topology",
    "upgrade-behavior across release binaries",
    "ratification / activation readiness",
  ],
  "updated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(path, "w", encoding="utf-8") as fh:
  json.dump(payload, fh, indent=2)
  fh.write("\n")
PY
  # sanitized twin without local workdir hints
  cp "${SUMMARY_JSON}" "${LOG_DIR}/summary.sanitized.json"
}

declare -A SCENARIO_COUNTS=(
  [relay]=0
  [competing_branch]=0
  [restart]=0
  [cache_persist]=0
  [ibd_boundary]=0
)

cleanup() {
  local rc=$?
  event "cleanup begin rc=${rc}"
  stop_node A || true
  stop_node B || true
  local elapsed=0
  if [[ -n "${SOAK_START_EPOCH:-}" ]]; then
    elapsed=$(( $(now_epoch) - SOAK_START_EPOCH ))
  fi
  export_counts
  SCENARIO_COUNTS_JSON="$(counts_json 2>/dev/null || echo '{}')"
  if [[ ${rc} -eq 0 ]]; then
    write_status "done" "soak completed"
    write_summary "done" "${elapsed}" || true
  else
    write_status "failed" "soak exited rc=${rc}"
    write_summary "failed" "${elapsed}" || true
  fi
  if [[ "${KEEP_RUNTIME}" != "1" ]]; then
    rm -rf "${WORKDIR}"
  fi
  release_gpu_lock
  event "cleanup end"
}
trap cleanup EXIT

PORT_A="${BASE_PORT}"
PORT_B="$((BASE_PORT + 1))"
P2P_A="$((BASE_PORT + 10))"
P2P_B="$((BASE_PORT + 11))"
SOAK_PID="$$"
SOAK_START_EPOCH="$(now_epoch)"
END_EPOCH=$(( SOAK_START_EPOCH + DURATION_SECS ))

acquire_gpu_lock
write_status "running" "acquired gpu.lock; starting two-node Profile-1 soak"
event "soak start duration_secs=${DURATION_SECS} rc_height=${RC_HEIGHT} v4_dim=${V4_DIM}"

rm -rf "${WORKDIR}/nodeA" "${WORKDIR}/nodeB"
start_node A
start_node B
wait_rpc A
wait_rpc B
connect_peers
assert_cuda_ready A
assert_cuda_ready B

# Bootstrap to parent of RC height, then cross the ExactReplay boundary once.
local_boot=$(( RC_HEIGHT - 1 ))
if [[ ${local_boot} -gt 0 ]]; then
  mine_one A "${local_boot}"
  wait_tips_equal 1800
fi
event "crossing RC height=${RC_HEIGHT}"
mine_one A 1
wait_tips_equal 1800
record_metrics A "rc_boundary" 1
record_metrics B "rc_boundary" 1
assert_cuda_ready A 1
assert_cuda_ready B 1
SCENARIO_COUNTS[relay]=$(( ${SCENARIO_COUNTS[relay]:-0} + 1 ))

LAST_MINE=${SOAK_START_EPOCH}
LAST_RESTART=${SOAK_START_EPOCH}
LAST_BRANCH=${SOAK_START_EPOCH}
LAST_IBD=${SOAK_START_EPOCH}
LAST_STATUS=${SOAK_START_EPOCH}

while [[ $(now_epoch) -lt ${END_EPOCH} ]]; do
  now="$(now_epoch)"
  if (( now - LAST_MINE >= MINE_INTERVAL_SECS )); then
    scenario_relay
    LAST_MINE=${now}
  fi
  if (( now - LAST_BRANCH >= BRANCH_INTERVAL_SECS )); then
    scenario_competing_branch
    LAST_BRANCH=${now}
  fi
  if (( now - LAST_RESTART >= RESTART_INTERVAL_SECS )); then
    scenario_restart_and_cache
    LAST_RESTART=${now}
  fi
  if (( now - LAST_IBD >= IBD_INTERVAL_SECS )); then
    scenario_ibd_boundary
    LAST_IBD=${now}
  fi
  if (( now - LAST_STATUS >= 60 )); then
    export_counts
    SCENARIO_COUNTS_JSON="$(counts_json)"
    write_status "running" "in-loop soak"
    LAST_STATUS=${now}
  fi
  sleep 5
done

# Final health sample.
scenario_relay
export_counts
SCENARIO_COUNTS_JSON="$(counts_json)"
write_status "finishing" "duration budget exhausted cleanly"
event "soak complete"
exit 0
