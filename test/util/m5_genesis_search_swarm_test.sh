#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SWARM_SCRIPT="${ROOT_DIR}/scripts/m5_genesis_search_swarm.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m5-swarm-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

FAKE_GENESIS="${TMP_DIR}/fake-btx-genesis.sh"
cat > "${FAKE_GENESIS}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

nonce64_start=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --nonce64-start)
      nonce64_start="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ "${nonce64_start}" == "200" ]]; then
  echo "status=found"
  echo "nonce64=200"
  echo "mixhash=deadbeef"
  echo "powhash=beadfeed"
  exit 0
fi

echo "error: no valid nonce found within max tries" >&2
exit 1
EOS
chmod +x "${FAKE_GENESIS}"

STATE_FILE="${TMP_DIR}/state.txt"
ARTIFACT_FILE="${TMP_DIR}/found.txt"

"${SWARM_SCRIPT}" \
  --genesis-bin "${FAKE_GENESIS}" \
  --workers 2 \
  --chunk-tries 100 \
  --max-rounds 5 \
  --start-nonce64 0 \
  --state-file "${STATE_FILE}" \
  --artifact "${ARTIFACT_FILE}" \
  --network test-harness

test -f "${ARTIFACT_FILE}"
rg -q '^status=found$' "${ARTIFACT_FILE}"
rg -q '^nonce64=200$' "${ARTIFACT_FILE}"

DRY_STATE_FILE="${TMP_DIR}/dry-state.txt"
DRY_ARTIFACT_FILE="${TMP_DIR}/dry-found.txt"
set +e
"${SWARM_SCRIPT}" \
  --genesis-bin "${FAKE_GENESIS}" \
  --workers 2 \
  --chunk-tries 100 \
  --max-rounds 1 \
  --start-nonce64 0 \
  --state-file "${DRY_STATE_FILE}" \
  --artifact "${DRY_ARTIFACT_FILE}" \
  --network dry-run \
  --dry-run
dry_rc=$?
set -e
test "${dry_rc}" -eq 0
test -f "${DRY_STATE_FILE}"
test "$(cat "${DRY_STATE_FILE}")" = "200"
test ! -f "${DRY_ARTIFACT_FILE}"

echo "m5_genesis_search_swarm_test: PASS"
