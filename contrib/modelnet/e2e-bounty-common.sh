#!/usr/bin/env bash
# Shared paths for bounty E2E (isolated regtest / tmpfs scratch only).
export LC_ALL=C
set -euo pipefail

BOUNTY_E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ -n "${BIN:-}" && -d "${BIN}" && -x "${BIN}/btxd" ]]; then
  BOUNTY_E2E_BIN="$BIN"
elif [[ -n "${BIN_DIR:-}" && -d "${BIN_DIR}" && -x "${BIN_DIR}/btxd" ]]; then
  BOUNTY_E2E_BIN="$BIN_DIR"
else
  BOUNTY_E2E_BIN="$BOUNTY_E2E_ROOT/build-gcc13/bin"
fi
BOUNTY_E2E_MODELD="${MODELD:-$BOUNTY_E2E_BIN/btx-modeld}"
BOUNTY_E2E_BTXD="$BOUNTY_E2E_BIN/btxd"
BOUNTY_E2E_CLI="$BOUNTY_E2E_BIN/btx-cli"
BOUNTY_PKG="$BOUNTY_E2E_ROOT/contrib/modelnet/bounty"
BOUNTY_EXPLORER="$BOUNTY_PKG/reference/explorer"

bounty_die() { printf 'e2e-bounty: %s\n' "$*" >&2; exit 1; }

bounty_require_binaries() {
  [[ -x "$BOUNTY_E2E_BTXD" ]] || bounty_die "missing $BOUNTY_E2E_BTXD (set BIN or build build-gcc13)"
  [[ -x "$BOUNTY_E2E_CLI" ]] || bounty_die "missing $BOUNTY_E2E_CLI"
  [[ -x "$BOUNTY_E2E_MODELD" ]] || bounty_die "missing $BOUNTY_E2E_MODELD"
}
