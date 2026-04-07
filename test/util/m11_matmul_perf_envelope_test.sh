#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/m11_matmul_perf_envelope.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m11-envelope-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

FAKE_BUILD="${TMP_DIR}/build"
mkdir -p "${FAKE_BUILD}/bin"

cat > "${FAKE_BUILD}/bin/bench_btx" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

output_json=""
filter=""
for arg in "$@"; do
  case "${arg}" in
    -output-json=*)
      output_json="${arg#-output-json=}"
      ;;
    -filter=*)
      filter="${arg#-filter=}"
      ;;
  esac
done

if [[ -z "${output_json}" ]]; then
  echo "missing -output-json" >&2
  exit 2
fi

solve_mainnet="${FAKE_SOLVE_MAINNET_SEC:-0.066}"
solve_testnet="${FAKE_SOLVE_TESTNET_SEC:-0.047}"
metal_mainnet="${FAKE_METAL_MAINNET_SEC:-0.042}"
metal_testnet="${FAKE_METAL_TESTNET_SEC:-0.040}"

if [[ "${filter}" == *"MatMulSolveMainnetDimensions"* ]]; then
  cat > "${output_json}" <<JSON
{"results":[
  {"name":"MatMulSolveMainnetDimensions","median(elapsed)":${solve_mainnet},"unit":"op"},
  {"name":"MatMulSolveTestnetDimensions","median(elapsed)":${solve_testnet},"unit":"op"}
]}
JSON
  solve_mainnet_ms=$(python3 -c "print(${solve_mainnet}*1000.0)")
  solve_testnet_ms=$(python3 -c "print(${solve_testnet}*1000.0)")
  echo "MatMulSolve[n=512,b=16,r=8] samples=100 successes=100 mean_ms=${solve_mainnet_ms} median_ms=${solve_mainnet_ms} nBits=0x2100ffff"
  echo "MatMulSolve[n=256,b=8,r=4] samples=100 successes=100 mean_ms=${solve_testnet_ms} median_ms=${solve_testnet_ms} nBits=0x2100ffff"
elif [[ "${filter}" == *"MatMulMetalDigestMainnetDimensions"* ]]; then
  cat > "${output_json}" <<JSON
{"results":[
  {"name":"MatMulMetalDigestMainnetDimensions","median(elapsed)":${metal_mainnet},"unit":"digest"},
  {"name":"MatMulMetalDigestTestnetDimensions","median(elapsed)":${metal_testnet},"unit":"digest"}
]}
JSON
else
  cat > "${output_json}" <<JSON
{"results":[]}
JSON
fi
EOS
chmod +x "${FAKE_BUILD}/bin/bench_btx"

ENVELOPE_JSON="${TMP_DIR}/envelope.json"
cat > "${ENVELOPE_JSON}" <<'JSON'
{
  "profiles": {
    "test_profile": {
      "solve_mainnet_ms_max": 75.0,
      "solve_testnet_ms_max": 55.0,
      "metal_digest_mainnet_ms_max": 50.0,
      "metal_digest_testnet_ms_max": 48.0
    }
  }
}
JSON

PASS_ARTIFACT="${TMP_DIR}/pass.json"
"${SCRIPT}" \
  --build-dir "${FAKE_BUILD}" \
  --artifact "${PASS_ARTIFACT}" \
  --envelope "${ENVELOPE_JSON}" \
  --profile test_profile \
  --min-time-solve 1 \
  --min-time-digest 1

python3 - <<'PY' "${PASS_ARTIFACT}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "pass", data
checks = {entry["name"]: entry for entry in data["benchmarks"]}
assert checks["MatMulSolveMainnetDimensions"]["within_envelope"] is True
assert checks["MatMulMetalDigestMainnetDimensions"]["within_envelope"] is True
PY

FAIL_ARTIFACT="${TMP_DIR}/fail.json"
set +e
FAKE_SOLVE_MAINNET_SEC=0.120 "${SCRIPT}" \
  --build-dir "${FAKE_BUILD}" \
  --artifact "${FAIL_ARTIFACT}" \
  --envelope "${ENVELOPE_JSON}" \
  --profile test_profile \
  --min-time-solve 1 \
  --min-time-digest 1
rc=$?
set -e
if (( rc == 0 )); then
  echo "error: envelope regression scenario unexpectedly succeeded" >&2
  exit 1
fi

python3 - <<'PY' "${FAIL_ARTIFACT}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "fail", data
failures = [entry for entry in data["benchmarks"] if not entry["within_envelope"]]
assert failures, data
assert failures[0]["name"] == "MatMulSolveMainnetDimensions", failures
PY

SKIP_ARTIFACT="${TMP_DIR}/skip.json"
"${SCRIPT}" \
  --build-dir "${TMP_DIR}/missing-build" \
  --artifact "${SKIP_ARTIFACT}" \
  --envelope "${ENVELOPE_JSON}" \
  --profile test_profile \
  --min-time-solve 1 \
  --min-time-digest 1

python3 - <<'PY' "${SKIP_ARTIFACT}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "skip", data
assert data["reason"] == "bench_binary_missing", data
PY

echo "m11_matmul_perf_envelope_test: PASS"
