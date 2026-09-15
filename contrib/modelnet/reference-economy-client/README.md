# Reference economy client

Third-party explorer for BTX 0.34.7 model search, feed, and release
economics. Unix JSON-RPC only (`MODELD_SOCK`). No catalog files, no wallet,
no HTTP funding writes.

Schema 3 economy/feed cards. Coverage is always incomplete.

```bash
export MODELD_SOCK=/path/to/modeld.sock
python3 economy_client.py search "coding agent"
python3 economy_client.py newest
python3 economy_client.py nearly
python3 economy_client.py unlocked
./demo.sh
```
