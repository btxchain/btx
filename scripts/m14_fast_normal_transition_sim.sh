#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m14_fast_normal_transition_sim.sh [options]

Run a deterministic local replay of BTX fast-mining -> normal-mining transition
on a temporary node and emit a JSON artifact with timing/target checkpoints.

This script is intentionally a local simulation harness. It temporarily rewrites
`src/kernel/chainparams.cpp` to override nFastMineHeight for the build used in
this run, then restores the file automatically.

Options:
  --build-dir <path>         Build directory (default: build-btx-transition-sim)
  --fast-mine-height <n>     Override transition height for this replay (default: 1000)
  --normal-blocks <n>        Number of post-transition blocks to observe (default: 40)
  --artifact <path>          JSON artifact path
                             (default: .btx-validation/m14-fast-normal-transition.json)
  --log-file <path>          Human-readable checkpoint log path
                             (default: .btx-validation/m14-fast-normal-transition.log)
  --max-wall-seconds <n>     Optional total runtime cap for mining loop (default: 0 = unlimited)
  --backend <name>           MatMul backend hint: cpu|metal|mlx|cuda (default: cpu)
  --datadir <path>           Explicit node datadir (default: temporary directory)
  --skip-build               Reuse existing binaries in --build-dir (no rebuild)
  --keep-datadir             Preserve datadir after completion
  -h, --help                 Show this help message
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx-transition-sim"
FAST_MINE_HEIGHT=1000
NORMAL_BLOCKS=40
ARTIFACT="${ROOT_DIR}/.btx-validation/m14-fast-normal-transition.json"
LOG_FILE="${ROOT_DIR}/.btx-validation/m14-fast-normal-transition.log"
MAX_WALL_SECONDS=0
BACKEND="cpu"
DATADIR=""
SKIP_BUILD=0
KEEP_DATADIR=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --fast-mine-height)
      FAST_MINE_HEIGHT="$2"
      shift 2
      ;;
    --normal-blocks)
      NORMAL_BLOCKS="$2"
      shift 2
      ;;
    --artifact)
      ARTIFACT="$2"
      shift 2
      ;;
    --log-file)
      LOG_FILE="$2"
      shift 2
      ;;
    --max-wall-seconds)
      MAX_WALL_SECONDS="$2"
      shift 2
      ;;
    --backend)
      BACKEND="$2"
      shift 2
      ;;
    --datadir)
      DATADIR="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --keep-datadir)
      KEEP_DATADIR=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! [[ "${FAST_MINE_HEIGHT}" =~ ^[0-9]+$ ]] || [[ "${FAST_MINE_HEIGHT}" -lt 2 ]]; then
  echo "error: --fast-mine-height must be an integer >= 2" >&2
  exit 1
fi
if ! [[ "${NORMAL_BLOCKS}" =~ ^[0-9]+$ ]] || [[ "${NORMAL_BLOCKS}" -lt 1 ]]; then
  echo "error: --normal-blocks must be an integer >= 1" >&2
  exit 1
fi
if ! [[ "${MAX_WALL_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "error: --max-wall-seconds must be an integer >= 0" >&2
  exit 1
fi

CHAINPARAMS_FILE="${ROOT_DIR}/src/kernel/chainparams.cpp"
CHAINPARAMS_BACKUP="$(mktemp "${TMPDIR:-/tmp}/btx-chainparams.backup.XXXXXX")"
cp "${CHAINPARAMS_FILE}" "${CHAINPARAMS_BACKUP}"
CHAINPARAMS_RESTORED=0

if [[ -z "${DATADIR}" ]]; then
  DATADIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m14-transition.XXXXXX")"
fi
mkdir -p "$(dirname "${ARTIFACT}")" "$(dirname "${LOG_FILE}")" "${DATADIR}"
CHECKPOINT_CSV="$(mktemp "${TMPDIR:-/tmp}/btx-m14-checkpoints.XXXXXX.csv")"

BITCOIND_PID=""
RPC_PORT=""
P2P_PORT=""
BITCOIND_BIN=""
BITCOIN_CLI_BIN=""

resolve_btx_binary() {
  local canonical="$1"
  local legacy="$2"
  if [[ -x "${canonical}" ]]; then
    printf '%s\n' "${canonical}"
  elif [[ -x "${legacy}" ]]; then
    printf '%s\n' "${legacy}"
  else
    printf '%s\n' "${canonical}"
  fi
}

restore_chainparams() {
  if [[ "${CHAINPARAMS_RESTORED}" -eq 0 ]]; then
    cp "${CHAINPARAMS_BACKUP}" "${CHAINPARAMS_FILE}"
    CHAINPARAMS_RESTORED=1
  fi
}

cleanup() {
  if [[ -n "${BITCOIND_PID}" ]]; then
    if [[ -z "${BITCOIN_CLI_BIN}" ]]; then
      BITCOIN_CLI_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btx-cli" "${BUILD_DIR}/bin/bitcoin-cli")"
    fi
    "${BITCOIN_CLI_BIN}" -rpcclienttimeout=0 -datadir="${DATADIR}" -rpcport="${RPC_PORT}" stop >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      if ! kill -0 "${BITCOIND_PID}" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
    if kill -0 "${BITCOIND_PID}" >/dev/null 2>&1; then
      kill "${BITCOIND_PID}" >/dev/null 2>&1 || true
    fi
    wait "${BITCOIND_PID}" 2>/dev/null || true
  fi
  restore_chainparams
  rm -f "${CHAINPARAMS_BACKUP}" "${CHECKPOINT_CSV}"
  if [[ "${KEEP_DATADIR}" -eq 0 ]]; then
    rm -rf "${DATADIR}"
  fi
}
trap cleanup EXIT

find_free_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

nproc_detect() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu
  else
    echo 4
  fi
}

RPC_PORT="$(find_free_port)"
P2P_PORT="$(find_free_port)"
while [[ "${P2P_PORT}" == "${RPC_PORT}" ]]; do
  P2P_PORT="$(find_free_port)"
done

if [[ "${SKIP_BUILD}" -eq 0 ]]; then
  python3 - "${CHAINPARAMS_FILE}" "${FAST_MINE_HEIGHT}" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
fast_height = int(sys.argv[2])
text = path.read_text()
fast_pattern = re.compile(r"(consensus\.nFastMineHeight\s*=\s*)([^;]+)(;)")
asert_pattern = re.compile(r"(consensus\.nMatMulAsertHeight\s*=\s*)([^;]+)(;)")

rewritten, fast_count = fast_pattern.subn(
    lambda match: f"{match.group(1)}{fast_height}{match.group(3)}",
    text,
)
rewritten, asert_count = asert_pattern.subn(
    lambda match: f"{match.group(1)}{fast_height}{match.group(3)}",
    rewritten,
)
if fast_count == 0:
    raise SystemExit("error: could not locate expected nFastMineHeight assignments")
if asert_count == 0:
    raise SystemExit("error: could not locate expected nMatMulAsertHeight assignments")
if fast_count != asert_count:
    raise SystemExit(
        f"error: inconsistent assignment counts (nFastMineHeight={fast_count}, "
        f"nMatMulAsertHeight={asert_count})"
    )
path.write_text(rewritten)
PY

  if [[ ! -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
    cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}"
  fi
  cmake --build "${BUILD_DIR}" --target btxd btx-cli -j"$(nproc_detect)"
  restore_chainparams
else
  echo "note: --skip-build uses existing binaries in ${BUILD_DIR}"
fi

BITCOIND_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btxd" "${BUILD_DIR}/bin/bitcoind")"
BITCOIN_CLI_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btx-cli" "${BUILD_DIR}/bin/bitcoin-cli")"
if [[ ! -x "${BITCOIND_BIN}" || ! -x "${BITCOIN_CLI_BIN}" ]]; then
  echo "error: missing btxd/btx-cli (or legacy aliases) in ${BUILD_DIR}/bin" >&2
  exit 1
fi

cli() {
  "${BITCOIN_CLI_BIN}" -rpcclienttimeout=0 -datadir="${DATADIR}" -rpcport="${RPC_PORT}" "$@"
}

BTX_MATMUL_BACKEND="${BACKEND}" "${BITCOIND_BIN}" \
  -datadir="${DATADIR}" \
  -daemon=1 \
  -server=1 \
  -port="${P2P_PORT}" \
  -rpcport="${RPC_PORT}" \
  -dnsseed=0 \
  -listen=0 \
  -fallbackfee=0.0002 \
  -minimumchainwork=0 \
  -maxtipage=999999999 \
  -printtoconsole=0 \
  >/dev/null 2>&1

BITCOIND_PID="$(pgrep -f "${DATADIR}" | head -n1 || true)"
if [[ -z "${BITCOIND_PID}" ]]; then
  echo "error: could not determine btxd PID for datadir ${DATADIR}" >&2
  exit 1
fi

for _ in $(seq 1 180); do
  if cli getblockcount >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! cli getblockcount >/dev/null 2>&1; then
  echo "error: btxd RPC did not become ready" >&2
  exit 1
fi

if ! cli -rpcwallet=miner getwalletinfo >/dev/null 2>&1; then
  cli createwallet miner >/dev/null
fi
MINER_ADDR="$(cli -rpcwallet=miner getnewaddress "transition-miner" p2mr)"

TARGET_HEIGHT=$((FAST_MINE_HEIGHT + NORMAL_BLOCKS))
echo "# m14 transition replay" > "${LOG_FILE}"
echo "# fast_mine_height=${FAST_MINE_HEIGHT} normal_blocks=${NORMAL_BLOCKS} target_height=${TARGET_HEIGHT} backend=${BACKEND} max_wall_seconds=${MAX_WALL_SECONDS}" >> "${LOG_FILE}"
echo "timestamp,height,phase,block_delta_seconds,wall_seconds,bits,difficulty,hash" > "${CHECKPOINT_CSV}"

RUN_START_EPOCH="$(date +%s)"
TERMINATION_REASON="target_height_reached"

while true; do
  if [[ "${MAX_WALL_SECONDS}" -gt 0 ]]; then
    now_epoch="$(date +%s)"
    elapsed_epoch=$((now_epoch - RUN_START_EPOCH))
    if [[ "${elapsed_epoch}" -ge "${MAX_WALL_SECONDS}" ]]; then
      TERMINATION_REASON="max_wall_seconds_exceeded"
      printf "%s warning=max_wall_seconds_exceeded elapsed=%ss max=%ss\n" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${elapsed_epoch}" "${MAX_WALL_SECONDS}" | tee -a "${LOG_FILE}"
      break
    fi
  fi

  height="$(cli getblockcount)"
  if [[ "${height}" -ge "${TARGET_HEIGHT}" ]]; then
    break
  fi

  prev_hash="$(cli getblockhash "${height}")"
  prev_time="$(cli getblockheader "${prev_hash}" | jq -r '.time')"
  t0="$(date +%s)"
  mined_hash="$(cli -rpcwallet=miner generatetoaddress 1 "${MINER_ADDR}" | jq -r '.[0]')"
  t1="$(date +%s)"
  header_json="$(cli getblockheader "${mined_hash}")"
  mined_height="$(jq -r '.height' <<< "${header_json}")"
  mined_time="$(jq -r '.time' <<< "${header_json}")"
  bits="$(jq -r '.bits' <<< "${header_json}")"
  difficulty="$(cli getdifficulty)"
  block_delta=$((mined_time - prev_time))
  wall_seconds=$((t1 - t0))
  phase="fast"
  if [[ "${mined_height}" -ge "${FAST_MINE_HEIGHT}" ]]; then
    phase="normal"
  fi

  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf "%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "${timestamp}" "${mined_height}" "${phase}" "${block_delta}" "${wall_seconds}" "${bits}" "${difficulty}" "${mined_hash}" >> "${CHECKPOINT_CSV}"
  printf "%s h=%s phase=%s dt=%ss wall=%ss bits=%s diff=%s hash=%s\n" \
    "${timestamp}" "${mined_height}" "${phase}" "${block_delta}" "${wall_seconds}" "${bits}" "${difficulty}" "${mined_hash}" | tee -a "${LOG_FILE}"
done

FINAL_HEIGHT="$(cli getblockcount)"
COMPLETED=0
if [[ "${FINAL_HEIGHT}" -ge "${TARGET_HEIGHT}" ]]; then
  COMPLETED=1
  TERMINATION_REASON="target_height_reached"
fi

python3 - "${CHECKPOINT_CSV}" "${ARTIFACT}" "${FAST_MINE_HEIGHT}" "${NORMAL_BLOCKS}" "${BUILD_DIR}" "${BACKEND}" "${DATADIR}" "${TARGET_HEIGHT}" "${FINAL_HEIGHT}" "${COMPLETED}" "${TERMINATION_REASON}" <<'PY'
import csv
import json
import statistics
import sys
from datetime import datetime, timezone

rows_path, artifact_path, fast_height_s, normal_blocks_s, build_dir, backend, datadir, target_height_s, final_height_s, completed_s, termination_reason = sys.argv[1:12]
fast_height = int(fast_height_s)
normal_blocks = int(normal_blocks_s)
target_height = int(target_height_s)
final_height = int(final_height_s)
completed = completed_s == "1"

rows = []
with open(rows_path, newline="", encoding="utf-8") as fh:
    reader = csv.DictReader(fh)
    for row in reader:
        rows.append(
            {
                "timestamp": row["timestamp"],
                "height": int(row["height"]),
                "phase": row["phase"],
                "block_delta_seconds": int(row["block_delta_seconds"]),
                "wall_seconds": int(row["wall_seconds"]),
                "bits": row["bits"],
                "difficulty": float(row["difficulty"]),
                "hash": row["hash"],
            }
        )

if not rows:
    raise SystemExit("error: no checkpoints captured")

def summarize(items):
    if not items:
        return {
            "count": 0,
            "avg_wall_seconds": None,
            "median_wall_seconds": None,
            "avg_block_delta_seconds": None,
            "median_block_delta_seconds": None,
            "min_difficulty": None,
            "max_difficulty": None,
        }
    wall = [x["wall_seconds"] for x in items]
    # Exclude genesis->block1 gap from phase-level timing summaries.
    delta_rows = [x for x in items if x["height"] > 1]
    if not delta_rows:
        delta_rows = items
    delta = [x["block_delta_seconds"] for x in delta_rows]
    diff = [x["difficulty"] for x in items]
    return {
        "count": len(items),
        "avg_wall_seconds": sum(wall) / len(wall),
        "median_wall_seconds": statistics.median(wall),
        "avg_block_delta_seconds": sum(delta) / len(delta),
        "median_block_delta_seconds": statistics.median(delta),
        "min_difficulty": min(diff),
        "max_difficulty": max(diff),
    }

fast_rows = [x for x in rows if x["phase"] == "fast"]
normal_rows = [x for x in rows if x["phase"] == "normal"]
transition_seen = any(x["height"] == fast_height for x in rows)

artifact = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "build_dir": build_dir,
    "backend": backend,
    "fast_mine_height_override": fast_height,
    "normal_blocks_requested": normal_blocks,
    "target_height": target_height,
    "final_height": final_height,
    "completed": completed,
    "termination_reason": termination_reason,
    "datadir": datadir,
    "summary": {
        "start_height": rows[0]["height"] - 1,
        "end_height": rows[-1]["height"],
        "transition_height": fast_height,
        "transition_seen": transition_seen,
        "fast": summarize(fast_rows),
        "normal": summarize(normal_rows),
    },
    "checkpoints": rows,
}

with open(artifact_path, "w", encoding="utf-8") as fh:
    json.dump(artifact, fh, indent=2)
    fh.write("\n")

if not transition_seen:
    raise SystemExit("error: transition height was not observed in replay output")
PY

echo "artifact: ${ARTIFACT}"
echo "log: ${LOG_FILE}"
echo "completed: ${COMPLETED}"
echo "termination_reason: ${TERMINATION_REASON}"
echo "datadir: ${DATADIR}"
if [[ "${KEEP_DATADIR}" -eq 0 ]]; then
  echo "datadir_cleanup: enabled"
else
  echo "datadir_cleanup: disabled"
fi

exit 0
