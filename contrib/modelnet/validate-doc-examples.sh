#!/usr/bin/env bash
# B0 DOC-01/02/04: run the documented CLI examples. Packaged CSV stays NOT_RUN.
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT/build-gcc13/bin}"
SCRATCH="$ROOT/e2e-scratch/doc-examples"
mkdir -p "$SCRATCH"
pass_n=0
pass() { pass_n=$((pass_n + 1)); printf 'ok %d - %s\n' "$pass_n" "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }

[[ -x "$BIN_DIR/btx-modelcheck" ]] || fail "btx-modelcheck missing"
[[ -x "$BIN_DIR/btx-open" ]] || fail "btx-open missing"
[[ -x "$BIN_DIR/btx-modeld" ]] || fail "btx-modeld missing"
pass "binaries present"

# DOC-04: docs must not claim packaged CSV PASS.
if grep -R --include='*.md' -n 'CSV PASS' "$ROOT/doc/modelnet" | grep -viE 'not csv pass|not a packaged' >/dev/null; then
  grep -R --include='*.md' -n 'CSV PASS' "$ROOT/doc/modelnet" >&2 || true
  fail "doc/modelnet claimed CSV PASS"
fi
pass "no CSV PASS claim in doc/modelnet"

grep -q 'dcc94d534964bca13fccb9a87c2b78808608d0a6bdcf3a72d3c22203bee5cb4b' "$ROOT/doc/modelnet/README.md" \
  || fail "README missing B0 SHA-384"
pass "README cites B0 SHA-384"

python3 - <<PY
import struct
from pathlib import Path
p = Path("$SCRATCH")
p.mkdir(parents=True, exist_ok=True)
header = b"{}"
(p / "model.safetensors").write_bytes(struct.pack("<Q", len(header)) + header)
PY

out="$("$BIN_DIR/btx-modelcheck" "$SCRATCH/model.safetensors")"
printf '%s\n' "$out"
[[ "$out" == STRUCTURE_VERIFIED* ]] || fail "btx-modelcheck expected STRUCTURE_VERIFIED"
pass "btx-modelcheck STRUCTURE_VERIFIED"

URI='btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25'
open_out="$("$BIN_DIR/btx-open" "$URI")"
printf '%s\n' "$open_out"
printf '%s\n' "$open_out" | grep -q 'action=preview-only' || fail "btx-open preview-only"
printf '%s\n' "$open_out" | grep -q 'wallet=not-opened' || fail "btx-open wallet"
set +e
"$BIN_DIR/btx-open" "$URI" extra >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 1 ]] || fail "btx-open extra args must fail"
pass "btx-open preview-only and refuses extra args"

{
  echo "g++: $(g++ --version | head -1)"
  echo "ninja: $(ninja --version 2>/dev/null || echo missing)"
  if [[ -x "${OPENSSL_BIN:-}" ]]; then
    echo "openssl: $("$OPENSSL_BIN" version)"
  elif command -v openssl >/dev/null; then
    echo "openssl: $(openssl version)"
  fi
} >"$SCRATCH/dependency-lock.observed.txt"
pass "recorded compiler/openssl versions (DOC-02 observe, not CSV PASS)"

echo "DOC examples PASS ($pass_n)"
