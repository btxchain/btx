#!/usr/bin/env bash
# Show btxd's MatMul backend env + active backend from getmininginfo.
pid=$(pgrep -x btxd | head -1)
echo "btxd pid: ${pid:-not running}"
if [ -n "${pid:-}" ]; then
  tr '\0' '\n' < "/proc/$pid/environ" | grep -i MATMUL || echo "BTX_MATMUL_BACKEND not in environment (defaults to cpu)"
fi
/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx -rpcclienttimeout=5 getmininginfo 2>/dev/null \
  | grep -E 'active_backend|hashps' || echo "RPC not ready"
