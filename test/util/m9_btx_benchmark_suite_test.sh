#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/m9_btx_benchmark_suite.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m9-bench-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

FAKE_BUILD="${TMP_DIR}/build"
mkdir -p "${FAKE_BUILD}/bin"

cat > "${FAKE_BUILD}/bin/btxd" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
trap 'exit 0' INT TERM
while true; do
  sleep 1
done
EOS
chmod +x "${FAKE_BUILD}/bin/btxd"

cat > "${FAKE_BUILD}/bin/btx-cli" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
cmd="${*: -1}"
case "${cmd}" in
  getblockcount)
    echo "0"
    ;;
  generatetodescriptor)
    echo '["blockhash"]'
    ;;
  stop)
    echo "stopping"
    ;;
  *)
    exit 0
    ;;
esac
EOS
chmod +x "${FAKE_BUILD}/bin/btx-cli"

cat > "${FAKE_BUILD}/bin/bench_btx" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${FAKE_BENCH_FAIL:-0}" == "1" ]]; then
  echo "bench failure" >&2
  exit 23
fi
echo "bench ok"
EOS
chmod +x "${FAKE_BUILD}/bin/bench_btx"

FAKE_M7="${TMP_DIR}/fake-m7.py"
cat > "${FAKE_M7}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${FAKE_M7_FAIL:-0}" == "1" ]]; then
  echo "m7 failure" >&2
  exit 31
fi
echo "m7 ok"
exit 0
EOS
chmod +x "${FAKE_M7}"

FAKE_M7_HANG="${TMP_DIR}/fake-m7-hang.py"
cat > "${FAKE_M7_HANG}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
sleep 30
EOS
chmod +x "${FAKE_M7_HANG}"

PASS_ARTIFACT="${TMP_DIR}/bench-pass.json"
PASS_LOG_DIR="${TMP_DIR}/logs-pass"

"${SCRIPT}" \
  --build-dir "${FAKE_BUILD}" \
  --m7-e2e-script "${FAKE_M7}" \
  --iterations 2 \
  --artifact "${PASS_ARTIFACT}" \
  --log-dir "${PASS_LOG_DIR}"

test -f "${PASS_ARTIFACT}"
python3 - <<'PY' "${PASS_ARTIFACT}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "pass", data
ids = {entry["id"] for entry in data["benchmarks"]}
required = {"bench_btx", "node_startup_latency", "mining_latency", "m7_e2e_latency"}
missing = required - ids
assert not missing, missing
for entry in data["benchmarks"]:
    assert entry["status"] in {"pass", "skip"}, entry
PY

FAIL_ARTIFACT="${TMP_DIR}/bench-fail.json"
FAIL_LOG_DIR="${TMP_DIR}/logs-fail"
set +e
FAKE_M7_FAIL=1 "${SCRIPT}" \
  --build-dir "${FAKE_BUILD}" \
  --m7-e2e-script "${FAKE_M7}" \
  --iterations 1 \
  --artifact "${FAIL_ARTIFACT}" \
  --log-dir "${FAIL_LOG_DIR}"
rc=$?
set -e

if (( rc == 0 )); then
  echo "error: failure scenario unexpectedly succeeded" >&2
  exit 1
fi

test -f "${FAIL_ARTIFACT}"
python3 - <<'PY' "${FAIL_ARTIFACT}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "fail", data
statuses = {entry["id"]: entry["status"] for entry in data["benchmarks"]}
assert statuses["m7_e2e_latency"] == "fail", statuses
assert statuses["node_startup_latency"] == "pass", statuses
PY

TIMEOUT_ARTIFACT="${TMP_DIR}/bench-timeout.json"
TIMEOUT_LOG_DIR="${TMP_DIR}/logs-timeout"
set +e
"${SCRIPT}" \
  --build-dir "${FAKE_BUILD}" \
  --m7-e2e-script "${FAKE_M7_HANG}" \
  --artifact "${TIMEOUT_ARTIFACT}" \
  --log-dir "${TIMEOUT_LOG_DIR}" \
  --command-timeout-seconds 1 \
  --skip-bench-btx \
  --skip-startup-latency \
  --skip-mining-latency
timeout_rc=$?
set -e

if (( timeout_rc == 0 )); then
  echo "error: timeout scenario unexpectedly succeeded" >&2
  exit 1
fi

test -f "${TIMEOUT_ARTIFACT}"
python3 - <<'PY' "${TIMEOUT_ARTIFACT}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "fail", data
statuses = {entry["id"]: entry["status"] for entry in data["benchmarks"]}
assert statuses["m7_e2e_latency"] == "fail", statuses
assert statuses["bench_btx"] == "skip", statuses
assert statuses["node_startup_latency"] == "skip", statuses
assert statuses["mining_latency"] == "skip", statuses
PY

rg -q 'timeout after 1s' "${TIMEOUT_LOG_DIR}/m7_e2e_latency.log"

echo "m9_btx_benchmark_suite_test: PASS"
