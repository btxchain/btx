#!/usr/bin/env bash
# Two-node demand-propagation retrieve.
#
# Proves default -modelseed=auto (no -modelseedupondownload, no seedmodel):
# an intentional import/getmodel is retained and re-advertised inside quota.
#
# Usage:
#   BTX_WAN_E2E=1 SEEDER=host:port URI=btx://... \
#     contrib/modelnet/e2e-two-node-demand.sh
#
# Run the fetcher on a non-production helper. Never SIGKILL production btxd.
# Never preserve_rare on the signer. Packaged CSV stays NOT_RUN.
set -euo pipefail
export LC_ALL=C
if [[ "${BTX_WAN_E2E:-0}" != "1" ]]; then
  echo "e2e-two-node-demand: skip (set BTX_WAN_E2E=1 SEEDER=host:port)"
  exit 0
fi
SEEDER="${SEEDER:?set SEEDER=host:port of a non-production helper}"
URI="${URI:?set URI=btx://... }"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export BTX_MODELD_ROOT="${BTX_MODELD_ROOT:-$HOME/.local/opt/btx-0.34.7-rc-modeld}"
export BTX_MODELD_DIRNAME="${BTX_MODELD_DIRNAME:-e2e-fetch}"
exec python3 "$ROOT/contrib/modelnet/granite_second_process_retrieve.py" --host "$SEEDER" --uri "$URI" --timeout "${WAN_TIMEOUT_S:-14400}" "$@"
