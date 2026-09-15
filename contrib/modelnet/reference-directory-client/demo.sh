#!/usr/bin/env bash
# Demo: searchmodels for "qwen coder" when MODELD_SOCK points at btx-modeld.
set -euo pipefail
export LC_ALL=C

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${MODELD_SOCK:-}" ]]; then
  cat <<'EOF'
Usage: MODELD_SOCK=/path/to/modeld.sock ./demo.sh

This explorer uses unix JSON-RPC only (see README.md).
Set MODELD_SOCK to your running btx-modeld RPC socket; without it this demo
prints usage and exits successfully.
EOF
  exit 0
fi

exec python3 "$DIR/directory_client.py" search "qwen coder"
