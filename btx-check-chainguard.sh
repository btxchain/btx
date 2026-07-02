#!/usr/bin/env bash
# Print the mining chain guard block from getmininginfo.
/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx -rpcclienttimeout=8 getmininginfo 2>/dev/null \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get("miningchainguard", {}), indent=1)); print("active_backend:", d.get("active_backend"))'
