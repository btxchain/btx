#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/m7_mining_readiness.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m7-timeout-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

FAKE_BUILD="${TMP_DIR}/build-fake"
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
exit 1
EOS
chmod +x "${FAKE_BUILD}/bin/btx-cli"

set +e
BTX_M7_RPC_READY_TIMEOUT_SECONDS=0 "${SCRIPT}" "${FAKE_BUILD}" >"${TMP_DIR}/invalid-stdout.log" 2>"${TMP_DIR}/invalid-stderr.log"
invalid_rc=$?
set -e

if (( invalid_rc == 0 )); then
  echo "error: invalid timeout scenario unexpectedly succeeded" >&2
  cat "${TMP_DIR}/invalid-stdout.log" >&2
  cat "${TMP_DIR}/invalid-stderr.log" >&2
  exit 1
fi

rg -q 'BTX_M7_RPC_READY_TIMEOUT_SECONDS must be a positive integer' "${TMP_DIR}/invalid-stderr.log"

start_ts="$(date +%s)"
set +e
BTX_M7_RPC_READY_TIMEOUT_SECONDS=2 python3 - "${SCRIPT}" "${FAKE_BUILD}" <<'PY' >"${TMP_DIR}/timeout-stdout.log" 2>"${TMP_DIR}/timeout-stderr.log"
import os
import subprocess
import sys

script = sys.argv[1]
build_dir = sys.argv[2]

proc = subprocess.run(
    [script, build_dir],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    timeout=40,
    env=os.environ.copy(),
)

sys.stdout.write(proc.stdout)
sys.stderr.write(proc.stderr)
sys.exit(proc.returncode)
PY
rc=$?
set -e
end_ts="$(date +%s)"
elapsed=$((end_ts - start_ts))

if (( rc == 0 )); then
  echo "error: timeout scenario unexpectedly succeeded" >&2
  cat "${TMP_DIR}/timeout-stdout.log" >&2
  cat "${TMP_DIR}/timeout-stderr.log" >&2
  exit 1
fi

if (( elapsed > 35 )); then
  echo "error: timeout scenario took too long (${elapsed}s)" >&2
  cat "${TMP_DIR}/timeout-stdout.log" >&2
  cat "${TMP_DIR}/timeout-stderr.log" >&2
  exit 1
fi

rg -q 'timed out waiting for btxd RPC availability' "${TMP_DIR}/timeout-stderr.log"

echo "m7_mining_readiness_timeout_test: PASS"
