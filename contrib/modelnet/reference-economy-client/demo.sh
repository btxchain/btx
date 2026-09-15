#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${MODELD_SOCK:-}" ]]; then
  echo "Usage: MODELD_SOCK=/path/to/modeld.sock ./demo.sh"
  exit 0
fi
python3 "$DIR/economy_client.py" search "coding agent"
python3 "$DIR/economy_client.py" newest
python3 "$DIR/economy_client.py" nearly
python3 "$DIR/economy_client.py" unlocked
