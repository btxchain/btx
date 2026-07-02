#!/usr/bin/env bash
# Dump backend_runtime counters from getmininginfo.
/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx -rpcclienttimeout=20 getmininginfo 2>/dev/null \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get("backend_runtime", {}), indent=1)[:600]); print("generate_running:", d.get("generate", "n/a"))'
