#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_FILE="${1:-${ROOT_DIR}/doc/btx-matmul-pow-spec.md}"
OUT_FILE="${2:-${ROOT_DIR}/.btx-spec-coverage.json}"

if [[ ! -f "${SPEC_FILE}" ]]; then
  echo "error: spec file not found: ${SPEC_FILE}" >&2
  exit 1
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "error: rg is required" >&2
  exit 1
fi

tmp_tests="$(mktemp)"
tmp_missing="$(mktemp)"
trap 'rm -f "${tmp_tests}" "${tmp_missing}"' EXIT

# Extract canonical TEST IDs from lines such as:
# TEST: foo_bar
# TEST: foo_bar — description
sed -n 's/^TEST:[[:space:]]*\([A-Za-z0-9_][A-Za-z0-9_]*\).*$/\1/p' "${SPEC_FILE}" | sort -u > "${tmp_tests}"

total_tests="$(wc -l < "${tmp_tests}" | tr -d ' ')"
matched_tests=0

while IFS= read -r test_id; do
  if [[ -z "${test_id}" ]]; then
    continue
  fi
  if rg --fixed-strings --quiet "${test_id}" \
      "${ROOT_DIR}/src/test" \
      "${ROOT_DIR}/test/functional"; then
    matched_tests=$((matched_tests + 1))
  else
    printf '%s\n' "${test_id}" >> "${tmp_missing}"
  fi
done < "${tmp_tests}"

missing_tests=$((total_tests - matched_tests))
checked_items="$(grep -c '^- \[x\]' "${SPEC_FILE}" || true)"
unchecked_items="$(grep -c '^- \[ \]' "${SPEC_FILE}" || true)"
generated_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

{
  printf '{\n'
  printf '  "generated_utc": "%s",\n' "${generated_utc}"
  printf '  "spec_file": "%s",\n' "${SPEC_FILE}"
  printf '  "tests": {\n'
  printf '    "total": %d,\n' "${total_tests}"
  printf '    "matched": %d,\n' "${matched_tests}"
  printf '    "missing": %d\n' "${missing_tests}"
  printf '  },\n'
  printf '  "checklist": {\n'
  printf '    "checked": %d,\n' "${checked_items}"
  printf '    "unchecked": %d\n' "${unchecked_items}"
  printf '  },\n'
  printf '  "missing_test_ids": [\n'
  if [[ -s "${tmp_missing}" ]]; then
    awk '{printf "    \"%s\"", $0; if (NR < n) printf ","; printf "\n"} END{}' n="$(wc -l < "${tmp_missing}" | tr -d ' ')" "${tmp_missing}"
  fi
  printf '  ]\n'
  printf '}\n'
} > "${OUT_FILE}"

echo "spec coverage audit written: ${OUT_FILE}"
echo "tests: total=${total_tests} matched=${matched_tests} missing=${missing_tests}"
echo "checklist: checked=${checked_items} unchecked=${unchecked_items}"
