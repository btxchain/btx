#!/usr/bin/env bash
# Diagnose what fast-sync inputs are available for recovering the BTX node.
set -u
echo "=== cached snapshot.dat on disk ==="
ls -la /mnt/d/BTX/snapshot.dat 2>/dev/null || echo "no cached snapshot.dat"
echo "=== cached manifest ==="
cat /mnt/d/BTX/snapshot.latest.manifest.json 2>/dev/null | head -c 500; echo
echo "=== faststart helper present? ==="
ls -la /mnt/d/BTX/contrib/faststart/btx-faststart.py 2>/dev/null || echo "MISSING faststart helper"
echo "=== existing datadir backups (possible good state) ==="
ls -dt /home/eldian/.btx.before-fast-sync-* /home/eldian/.btx.broken-* 2>/dev/null | head
echo "=== which btxchain/btx releases publish a snapshot ==="
UA="Mozilla/5.0 Chrome/124.0"
curl -fsSL -m 25 -A "$UA" "https://api.github.com/repos/btxchain/btx/releases?per_page=20" 2>/dev/null | python3 - <<'PY'
import json,sys
try:
    rels=json.load(sys.stdin)
except Exception as e:
    print("api parse failed:",e); sys.exit(0)
for r in rels:
    snaps=[a.get('name') for a in r.get('assets',[]) if 'snapshot' in (a.get('name','').lower())]
    if snaps:
        print(r.get('tag_name'), r.get('published_at','')[:10], snaps)
PY
echo "=== current node binary's accepted assumeutxo heights (strings in btxd) ==="
strings /home/eldian/btx-node/bin/btxd 2>/dev/null | grep -iE 'assumeutxo|m_assumeutxo|nChainTx' | head -5 || echo "(strings unavailable)"
