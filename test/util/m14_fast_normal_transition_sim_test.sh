#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_PATH="${ROOT_DIR}/scripts/m14_fast_normal_transition_sim.sh"

python3 - "${SCRIPT_PATH}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

required_snippets = [
    "fast_pattern = re.compile",
    "consensus\\.nFastMineHeight",
    "asert_pattern = re.compile",
    "consensus\\.nMatMulAsertHeight",
    "fast_pattern.subn(",
    "asert_pattern.subn(",
    "if fast_count == 0:",
    "if asert_count == 0:",
    "if fast_count != asert_count:",
]

missing = [snippet for snippet in required_snippets if snippet not in text]
if missing:
    raise SystemExit(f"missing expected m14 rewrite guards: {missing}")
PY

echo "m14_fast_normal_transition_sim_test: PASS"
