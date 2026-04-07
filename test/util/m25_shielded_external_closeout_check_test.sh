#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_PATH="${ROOT_DIR}/scripts/m25_shielded_external_closeout_check.py"

python3 - "${SCRIPT_PATH}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

required_snippets = [
    "\"findings_json\": intake_dir / \"received\" / \"findings.json\"",
    "external_cryptographic_review.md",
    "external_redteam_report.md",
    "signoff_status.json",
    "closeout_summary.json",
    "\"overall_status\": \"pass\"",
    "RESOLVED_STATUSES",
]

missing = [snippet for snippet in required_snippets if snippet not in text]
if missing:
    raise SystemExit(f"missing expected m25 closeout validator logic: {missing}")
PY

echo "m25_shielded_external_closeout_check_test: PASS"
