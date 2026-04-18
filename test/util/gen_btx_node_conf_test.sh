#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/contrib/devtools/gen-btx-node-conf.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-conf-test.XXXXXX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

FAST_CONF="${TMP_DIR}/fast.conf"
ARCH_CONF="${TMP_DIR}/archival.conf"
STRICT_CONF="${TMP_DIR}/archival-strict.conf"
MANAGED_CONF="${TMP_DIR}/archival-managed-local.conf"

"${SCRIPT}" fast > "${FAST_CONF}"
"${SCRIPT}" archival > "${ARCH_CONF}"
"${SCRIPT}" archival strict-connect > "${STRICT_CONF}"
"${SCRIPT}" archival managed-direct local > "${MANAGED_CONF}"

# Fast/scalable profile checks.
rg -q '^prune=4096$' "${FAST_CONF}"
rg -q '^dnsseed=1$' "${FAST_CONF}"
rg -q '^fixedseeds=1$' "${FAST_CONF}"
rg -q '^addnode=node\.btx\.tools:19335$' "${FAST_CONF}"
rg -q '^addnode=146\.190\.179\.86:19335$' "${FAST_CONF}"
rg -q '^addnode=164\.90\.246\.229:19335$' "${FAST_CONF}"
if rg -q '^connect=' "${FAST_CONF}"; then
  echo "unexpected connect= entry in default fast profile" >&2
  exit 1
fi

# Archival/scalable profile checks.
rg -q '^prune=0$' "${ARCH_CONF}"
rg -q '^dnsseed=1$' "${ARCH_CONF}"
rg -q '^fixedseeds=1$' "${ARCH_CONF}"
if rg -q '^connect=' "${ARCH_CONF}"; then
  echo "unexpected connect= entry in default archival profile" >&2
  exit 1
fi

# Strict-connect profile checks.
rg -q '^dnsseed=0$' "${STRICT_CONF}"
rg -q '^fixedseeds=0$' "${STRICT_CONF}"
rg -q '^connect=node\.btx\.tools:19335$' "${STRICT_CONF}"
rg -q '^connect=146\.190\.179\.86:19335$' "${STRICT_CONF}"
rg -q '^connect=164\.90\.246\.229:19335$' "${STRICT_CONF}"
if rg -q '^addnode=' "${STRICT_CONF}"; then
  echo "unexpected addnode entry in strict-connect profile" >&2
  exit 1
fi

# Managed-direct profile checks.
rg -q '^dnsseed=0$' "${MANAGED_CONF}"
rg -q '^fixedseeds=0$' "${MANAGED_CONF}"
rg -q '^addnode=178\.128\.135\.6:19335$' "${MANAGED_CONF}"
rg -q '^addnode=143\.244\.209\.243:19335$' "${MANAGED_CONF}"
rg -q '^addnode=68\.183\.240\.79:19335$' "${MANAGED_CONF}"
if rg -q '^connect=node\.btx' "${MANAGED_CONF}"; then
  echo "unexpected public strict-connect entry in managed-direct profile" >&2
  exit 1
fi

# Invalid args should fail.
set +e
"${SCRIPT}" fast broken-mode >/dev/null 2>&1
rc=$?
set -e
if (( rc == 0 )); then
  echo "expected invalid bootstrap mode to fail" >&2
  exit 1
fi

set +e
"${SCRIPT}" archival managed-direct unknown >/dev/null 2>&1
rc=$?
set -e
if (( rc == 0 )); then
  echo "expected unknown managed node name to fail" >&2
  exit 1
fi

echo "gen_btx_node_conf_test: PASS"
