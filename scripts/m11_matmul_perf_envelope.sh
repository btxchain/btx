#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m11_matmul_perf_envelope.sh [options]

Run MatMul solve + Metal digest benchmarks and verify they stay within a named
performance envelope profile.

Options:
  --build-dir <path>          Build directory (default: build-btx)
  --artifact <path>           Output JSON artifact path
  --log-dir <path>            Directory for benchmark logs
  --envelope <path>           Envelope profile JSON path
  --profile <name>            Envelope profile name (defaults to envelope default_profile)
  --min-time-solve <ms>       bench_btx min-time for solve benchmarks (default: 30)
  --min-time-digest <ms>      bench_btx min-time for digest benchmarks (default: 20)
  --require-bench             Fail if bench_btx is missing instead of emitting skip
  -h, --help                  Show this message
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
ARTIFACT_PATH="${ROOT_DIR}/.btx-production-readiness/matmul-perf-envelope.json"
LOG_DIR="${ROOT_DIR}/.btx-production-readiness/matmul-perf-envelope-logs"
ENVELOPE_PATH="${ROOT_DIR}/doc/matmul-perf-envelopes.json"
PROFILE_NAME=""
MIN_TIME_SOLVE=30
MIN_TIME_DIGEST=20
REQUIRE_BENCH=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --artifact)
      ARTIFACT_PATH="$2"
      shift 2
      ;;
    --log-dir)
      LOG_DIR="$2"
      shift 2
      ;;
    --envelope)
      ENVELOPE_PATH="$2"
      shift 2
      ;;
    --profile)
      PROFILE_NAME="$2"
      shift 2
      ;;
    --min-time-solve)
      MIN_TIME_SOLVE="$2"
      shift 2
      ;;
    --min-time-digest)
      MIN_TIME_DIGEST="$2"
      shift 2
      ;;
    --require-bench)
      REQUIRE_BENCH=1
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

if ! [[ "${MIN_TIME_SOLVE}" =~ ^[0-9]+$ ]] || [[ "${MIN_TIME_SOLVE}" -lt 1 ]]; then
  echo "error: --min-time-solve must be a positive integer" >&2
  exit 1
fi
if ! [[ "${MIN_TIME_DIGEST}" =~ ^[0-9]+$ ]] || [[ "${MIN_TIME_DIGEST}" -lt 1 ]]; then
  echo "error: --min-time-digest must be a positive integer" >&2
  exit 1
fi
if [[ ! -f "${ENVELOPE_PATH}" ]]; then
  echo "error: envelope file not found: ${ENVELOPE_PATH}" >&2
  exit 1
fi

mkdir -p "$(dirname "${ARTIFACT_PATH}")" "${LOG_DIR}"
BENCH_BIN="${BUILD_DIR}/bin/bench_btx"
SOLVE_LOG="${LOG_DIR}/matmul_solve_bench.log"
DIGEST_LOG="${LOG_DIR}/matmul_metal_digest_bench.log"

emit_terminal_artifact() {
  local status="$1"
  local reason="$2"
  python3 - <<'PY' "${ARTIFACT_PATH}" "${BUILD_DIR}" "${ENVELOPE_PATH}" "${PROFILE_NAME}" "${status}" "${reason}" "${SOLVE_LOG}" "${DIGEST_LOG}"
import json
import sys
from datetime import datetime, timezone

artifact_path = sys.argv[1]
build_dir = sys.argv[2]
envelope = sys.argv[3]
profile = sys.argv[4]
status = sys.argv[5]
reason = sys.argv[6]
solve_log = sys.argv[7]
digest_log = sys.argv[8]

payload = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "build_dir": build_dir,
    "envelope": envelope,
    "profile": profile,
    "overall_status": status,
    "reason": reason,
    "logs": {
        "solve": solve_log,
        "digest": digest_log,
    },
    "benchmarks": [],
}
with open(artifact_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
PY
}

if [[ ! -x "${BENCH_BIN}" ]]; then
  if [[ "${REQUIRE_BENCH}" -eq 1 ]]; then
    emit_terminal_artifact "fail" "bench_binary_missing"
    echo "MatMul perf envelope: FAIL (bench binary missing: ${BENCH_BIN})"
    exit 1
  fi
  emit_terminal_artifact "skip" "bench_binary_missing"
  echo "MatMul perf envelope: SKIP (bench binary missing: ${BENCH_BIN})"
  exit 0
fi

SOLVE_JSON="$(mktemp "${TMPDIR:-/tmp}/btx-matmul-solve-bench.XXXXXX.json")"
DIGEST_JSON="$(mktemp "${TMPDIR:-/tmp}/btx-matmul-digest-bench.XXXXXX.json")"
cleanup() {
  rm -f "${SOLVE_JSON}" "${DIGEST_JSON}"
}
trap cleanup EXIT

if ! "${BENCH_BIN}" \
    -filter='MatMulSolveMainnetDimensions|MatMulSolveTestnetDimensions' \
    -min-time="${MIN_TIME_SOLVE}" \
    -output-json="${SOLVE_JSON}" >"${SOLVE_LOG}" 2>&1; then
  emit_terminal_artifact "fail" "bench_command_failed:solve"
  echo "MatMul perf envelope: FAIL (solve benchmark command failed)"
  exit 1
fi

if ! "${BENCH_BIN}" \
    -filter='MatMulMetalDigestMainnetDimensions|MatMulMetalDigestTestnetDimensions' \
    -min-time="${MIN_TIME_DIGEST}" \
    -output-json="${DIGEST_JSON}" >"${DIGEST_LOG}" 2>&1; then
  emit_terminal_artifact "fail" "bench_command_failed:digest"
  echo "MatMul perf envelope: FAIL (digest benchmark command failed)"
  exit 1
fi

python3 - <<'PY' \
  "${SOLVE_JSON}" \
  "${DIGEST_JSON}" \
  "${ENVELOPE_PATH}" \
  "${PROFILE_NAME}" \
  "${ARTIFACT_PATH}" \
  "${BUILD_DIR}" \
  "${SOLVE_LOG}" \
  "${DIGEST_LOG}"
import json
import re
import sys
from datetime import datetime, timezone

solve_json = sys.argv[1]
digest_json = sys.argv[2]
envelope_path = sys.argv[3]
requested_profile = sys.argv[4]
artifact_path = sys.argv[5]
build_dir = sys.argv[6]
solve_log = sys.argv[7]
digest_log = sys.argv[8]

with open(envelope_path, encoding="utf-8") as fh:
    envelope = json.load(fh)

profiles = envelope.get("profiles", {})
profile_name = requested_profile or envelope.get("default_profile", "")
if not profile_name and profiles:
    profile_name = sorted(profiles.keys())[0]

if profile_name not in profiles:
    payload = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "build_dir": build_dir,
        "envelope": envelope_path,
        "profile": profile_name,
        "overall_status": "fail",
        "reason": "profile_not_found",
        "logs": {"solve": solve_log, "digest": digest_log},
        "benchmarks": [],
    }
    with open(artifact_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    print("MatMul perf envelope: FAIL (profile not found)")
    sys.exit(1)

profile = profiles[profile_name]
required_limits = {
    "MatMulSolveMainnetDimensions": "solve_mainnet_ms_max",
    "MatMulSolveTestnetDimensions": "solve_testnet_ms_max",
    "MatMulMetalDigestMainnetDimensions": "metal_digest_mainnet_ms_max",
    "MatMulMetalDigestTestnetDimensions": "metal_digest_testnet_ms_max",
}

missing_limits = [k for k in required_limits.values() if k not in profile]
if missing_limits:
    payload = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "build_dir": build_dir,
        "envelope": envelope_path,
        "profile": profile_name,
        "overall_status": "fail",
        "reason": "profile_missing_limits",
        "missing_limits": missing_limits,
        "logs": {"solve": solve_log, "digest": digest_log},
        "benchmarks": [],
    }
    with open(artifact_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    print("MatMul perf envelope: FAIL (profile missing required limits)")
    sys.exit(1)

def load_digest_results(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    out = {}
    for item in data.get("results", []):
        name = item.get("name")
        elapsed = item.get("median(elapsed)")
        if isinstance(name, str) and isinstance(elapsed, (int, float)):
            out[name] = float(elapsed) * 1000.0
    return out

measurements = {}

with open(solve_log, encoding="utf-8") as fh:
    solve_log_text = fh.read()

solve_mainnet_match = re.search(r"MatMulSolve\[n=512,b=16,r=8\].*mean_ms=([0-9]+(?:\.[0-9]+)?)", solve_log_text)
if solve_mainnet_match:
    measurements["MatMulSolveMainnetDimensions"] = float(solve_mainnet_match.group(1))

solve_testnet_match = re.search(r"MatMulSolve\[n=256,b=8,r=4\].*mean_ms=([0-9]+(?:\.[0-9]+)?)", solve_log_text)
if solve_testnet_match:
    measurements["MatMulSolveTestnetDimensions"] = float(solve_testnet_match.group(1))

measurements.update(load_digest_results(digest_json))

missing_benchmarks = [name for name in required_limits if name not in measurements]
if missing_benchmarks:
    payload = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "build_dir": build_dir,
        "envelope": envelope_path,
        "profile": profile_name,
        "overall_status": "fail",
        "reason": "missing_benchmark_results",
        "missing_benchmarks": missing_benchmarks,
        "logs": {"solve": solve_log, "digest": digest_log},
        "benchmarks": [],
    }
    with open(artifact_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    print("MatMul perf envelope: FAIL (missing benchmark results)")
    sys.exit(1)

benchmarks = []
overall_pass = True
for name, limit_key in required_limits.items():
    measured_ms = measurements[name]
    max_ms = float(profile[limit_key])
    within = measured_ms <= max_ms
    if not within:
        overall_pass = False
    benchmarks.append({
        "name": name,
        "measured_ms": round(measured_ms, 6),
        "max_ms": max_ms,
        "within_envelope": within,
    })

payload = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "build_dir": build_dir,
    "envelope": envelope_path,
    "profile": profile_name,
    "overall_status": "pass" if overall_pass else "fail",
    "reason": "within_envelope" if overall_pass else "envelope_regression_detected",
    "logs": {"solve": solve_log, "digest": digest_log},
    "benchmarks": benchmarks,
}
with open(artifact_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")

print(f"MatMul perf envelope: {'PASS' if overall_pass else 'FAIL'} (profile={profile_name})")
for entry in benchmarks:
    mark = "OK" if entry["within_envelope"] else "REGRESSION"
    print(f"  {entry['name']}: measured_ms={entry['measured_ms']:.6f} max_ms={entry['max_ms']:.6f} [{mark}]")

sys.exit(0 if overall_pass else 1)
PY
