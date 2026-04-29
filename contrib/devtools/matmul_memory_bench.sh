#!/usr/bin/env bash
set -euo pipefail

BIN_DEFAULT="/Users/admin/Documents/btxchain/btx-node/build-btx/bin"
BIN_DIR="${BIN_DIR:-$BIN_DEFAULT}"
MODE="${MODE:-wallet}"                # wallet | descriptor
ITERATIONS="${ITERATIONS:-10}"
BLOCKS_PER_ITER="${BLOCKS_PER_ITER:-25}"
DISABLE_WALLET="${DISABLE_WALLET:-0}" # 1 to disable wallet
BACKEND="${BACKEND:-}"                # cpu | metal | cuda | empty (default policy)
FIXED_CYCLE="${FIXED_CYCLE:-0}"       # 1 => invalidate each mined batch to keep active height constant
DAEMONIZE="${DAEMONIZE:-1}"           # 1 => -daemon/-daemonwait, 0 => foreground process (sanitizer-friendly)
RPCPORT="${RPCPORT:-$((20000 + (RANDOM % 2000)))}"
P2PPORT="${P2PPORT:-$((22000 + (RANDOM % 2000)))}"
DATADIR="${DATADIR:-/tmp/btx-membench-$RANDOM}"

if [[ ! -x "${BIN_DIR}/btxd" || ! -x "${BIN_DIR}/btx-cli" ]]; then
  echo "error: btxd/btx-cli not found under BIN_DIR=${BIN_DIR}" >&2
  exit 1
fi

mkdir -p "${DATADIR}"
CONF="${DATADIR}/bitcoin.conf"
cat >"${CONF}" <<EOF
regtest=1
server=1
listen=0
fallbackfee=0.0001
rpcuser=u
rpcpassword=p
disablewallet=${DISABLE_WALLET}
[regtest]
rpcport=${RPCPORT}
port=${P2PPORT}
EOF

echo "datadir=${DATADIR}"
echo "mode=${MODE} iterations=${ITERATIONS} blocks_per_iter=${BLOCKS_PER_ITER} disablewallet=${DISABLE_WALLET} backend=${BACKEND:-default} fixed_cycle=${FIXED_CYCLE} daemonize=${DAEMONIZE}"
if [[ "${FIXED_CYCLE}" == "1" && "${BLOCKS_PER_ITER}" != "1" ]]; then
  echo "error: FIXED_CYCLE=1 currently requires BLOCKS_PER_ITER=1 for deterministic rollback" >&2
  exit 1
fi
fixed_cycle_base_time=""

rpc() {
  "${BIN_DIR}/btx-cli" -datadir="${DATADIR}" -rpcport="${RPCPORT}" -rpcuser=u -rpcpassword=p "$@"
}

extract_mined_hash() {
  local mined_json="$1"
  if command -v jq >/dev/null 2>&1; then
    echo "${mined_json}" | jq -r '.[-1] // empty'
    return 0
  fi
  if command -v rg >/dev/null 2>&1; then
    echo "${mined_json}" | rg -o '[0-9a-f]{64}' | tail -n1
    return 0
  fi
  echo "${mined_json}" | grep -Eo '[0-9a-f]{64}' | tail -n1
}

if [[ -n "${BACKEND}" ]]; then
  if [[ "${DAEMONIZE}" == "1" ]]; then
    BTX_MATMUL_BACKEND="${BACKEND}" "${BIN_DIR}/btxd" -datadir="${DATADIR}" -daemon -daemonwait >/dev/null
  else
    BTX_MATMUL_BACKEND="${BACKEND}" "${BIN_DIR}/btxd" -datadir="${DATADIR}" >"${DATADIR}/btxd.stdout.log" 2>"${DATADIR}/btxd.stderr.log" &
    DAEMON_PID=$!
  fi
else
  if [[ "${DAEMONIZE}" == "1" ]]; then
    "${BIN_DIR}/btxd" -datadir="${DATADIR}" -daemon -daemonwait >/dev/null
  else
    "${BIN_DIR}/btxd" -datadir="${DATADIR}" >"${DATADIR}/btxd.stdout.log" 2>"${DATADIR}/btxd.stderr.log" &
    DAEMON_PID=$!
  fi
fi

for _ in $(seq 1 60); do
  if rpc getblockchaininfo >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if [[ "${DAEMONIZE}" == "1" ]]; then
  PID="$(pgrep -f "btxd -datadir=${DATADIR}" | head -n1)"
else
  PID="${DAEMON_PID:-}"
fi
if [[ -z "${PID}" ]]; then
  echo "error: unable to find btxd pid for ${DATADIR}" >&2
  exit 1
fi

thread_count() {
  local tc="0"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    tc="$(ps -M -p "${PID}" 2>/dev/null | tail -n +2 | wc -l | tr -d ' ' || true)"
  else
    tc="$(ps -o nlwp= -p "${PID}" 2>/dev/null | tr -d ' ' || true)"
    if [[ -z "${tc}" ]]; then
      tc="$(ps -o thcount= -p "${PID}" 2>/dev/null | tr -d ' ' || true)"
    fi
  fi
  if [[ -z "${tc}" || ! "${tc}" =~ ^[0-9]+$ ]]; then
    tc="0"
  fi
  echo "${tc}"
}

TARGET_DESC="raw(51)"
if [[ "${DISABLE_WALLET}" == "0" && "${MODE}" == "wallet" ]]; then
  rpc createwallet memtest >/dev/null
  TARGET_ADDR="$(rpc -rpcwallet=memtest getnewaddress)"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  vmmap -summary "${PID}" > "${DATADIR}/vmmap.before.txt" || true
elif [[ -r "/proc/${PID}/smaps_rollup" ]]; then
  cat "/proc/${PID}/smaps_rollup" > "${DATADIR}/smaps_rollup.before.txt" || true
fi

echo "iter,height_before,height_after,rss_before_kb,rss_after_kb,diff_kb,threads_before,threads_after,elapsed_s"
for i in $(seq 1 "${ITERATIONS}"); do
  height_before="$(rpc getblockcount)"
  rss_before="$(ps -o rss= -p "${PID}" | tr -d ' ')"
  tc_before="$(thread_count)"
  start="$(date +%s)"
  if [[ "${FIXED_CYCLE}" == "1" ]]; then
    if [[ -z "${fixed_cycle_base_time}" ]]; then
      fixed_cycle_base_time="$(date +%s)"
    fi
    rpc setmocktime "$((fixed_cycle_base_time + i))" >/dev/null
  fi
  mined_json=""
  if [[ "${DISABLE_WALLET}" == "0" && "${MODE}" == "wallet" ]]; then
    mined_json="$(rpc -rpcwallet=memtest generatetoaddress "${BLOCKS_PER_ITER}" "${TARGET_ADDR}")"
  else
    mined_json="$(rpc generatetodescriptor "${BLOCKS_PER_ITER}" "${TARGET_DESC}")"
  fi

  if [[ "${FIXED_CYCLE}" == "1" ]]; then
    mined_hash="$(extract_mined_hash "${mined_json}" || true)"
    if [[ -n "${mined_hash}" ]]; then
      rpc invalidateblock "${mined_hash}" >/dev/null
    fi
  fi
  end="$(date +%s)"
  height_after="$(rpc getblockcount)"
  rss_after="$(ps -o rss= -p "${PID}" | tr -d ' ')"
  tc_after="$(thread_count)"
  diff="$((rss_after - rss_before))"
  echo "${i},${height_before},${height_after},${rss_before},${rss_after},${diff},${tc_before},${tc_after},$((end - start))"
done | tee "${DATADIR}/rss.csv"

first_rss_before="$(awk -F, 'NR==1 {print $4}' "${DATADIR}/rss.csv" 2>/dev/null || true)"
last_rss_after="$(awk -F, 'END {print $5}' "${DATADIR}/rss.csv" 2>/dev/null || true)"
if [[ "${first_rss_before}" =~ ^[0-9]+$ && "${last_rss_after}" =~ ^[0-9]+$ ]]; then
  echo "net_rss_kb=$((last_rss_after - first_rss_before))"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  vmmap -summary "${PID}" > "${DATADIR}/vmmap.after.txt" || true
elif [[ -r "/proc/${PID}/smaps_rollup" ]]; then
  cat "/proc/${PID}/smaps_rollup" > "${DATADIR}/smaps_rollup.after.txt" || true
fi

if [[ "${FIXED_CYCLE}" == "1" ]]; then
  rpc setmocktime 0 >/dev/null || true
fi

rpc stop >/dev/null || true
sleep 2
if [[ "${DAEMONIZE}" == "0" ]]; then
  wait "${PID}" || true
fi

echo "results_dir=${DATADIR}"
