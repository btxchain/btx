#!/usr/bin/env bash
# Run btx-modeld with bundled OpenSSL 3.5 when present (hosts whose
# system OpenSSL cannot do ML-KEM-768 / ML-DSA-44).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
if [[ -d "$ROOT/lib" ]]; then
  export LD_LIBRARY_PATH="$ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export PATH="$ROOT/bin:$PATH"
  if [[ -x "$ROOT/bin/openssl35" ]]; then
    export BTX_OPENSSL="${BTX_OPENSSL:-$ROOT/bin/openssl35}"
  fi
fi
exec "$HERE/btx-modeld" "$@"
