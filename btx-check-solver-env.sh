#!/usr/bin/env bash
# Show which BTX_MATMUL_* env vars actually reached the running solver process,
# and how the miner spawned it (to see if it sanitizes env).
pid=$(pgrep -f '[b]tx-gbt-solve' | head -1)
echo "solver pid: ${pid:-none}"
if [ -n "$pid" ]; then
  echo "=== BTX_MATMUL_* in solver environ ==="
  tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -E 'BTX_MATMUL|BTX_' | sort || echo "(none / unreadable)"
fi
echo "=== how dexbtx passes env: grep its source for env/Popen ==="
MAIN=$(python3 -c "import dexbtx_miner, os; print(os.path.dirname(dexbtx_miner.__file__))" 2>/dev/null)
echo "pkg dir: ${MAIN:-unknown}"
if [ -n "${MAIN:-}" ]; then
  grep -rIn -E 'BTX_MATMUL|env=|os\.environ|setdefault|Popen|subprocess' "$MAIN" 2>/dev/null | grep -iE 'env|matmul|popen' | head -25
fi
