#!/usr/bin/env bash
# Does the dexbtx miner support solo / getblocktemplate mode (talk to a node
# directly), or is it pool/stratum-only? And what solo paths does btxd expose?
D=/home/eldian/.local/lib/python3.12/site-packages/dexbtx_miner
echo "=== dexbtx-miner: any solo / getblocktemplate / rpc / submitblock support? ==="
grep -rIn -iE 'solo|getblocktemplate|gbt(_|-)?(mode|solo)|submitblock|rpc_?url|node_?rpc|--solo|stratum.?bridge' "$D" 2>/dev/null | grep -viE 'gbt_solve|gbt-solve|btx-gbt-solve' | head -20
echo "=== dexbtx-miner __main__ full arg list ==="
grep -nE 'add_argument|add_parser|sys.argv\[1\]' "$D/__main__.py" | head -40
echo "=== btxd solo-relevant RPCs present? ==="
/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx help 2>/dev/null | grep -iE 'getblocktemplate|submitblock|generatetoaddress|generateblock' || echo "(node RPC down — checking help text instead)"
echo "=== btx-gbt-solve: does it emit a submittable block? (schema hint) ==="
/home/eldian/.dexbtx-miner/bin/btx-gbt-solve --help 2>&1 | grep -iE 'submit|block|emit|--daemon|stdout|json' | head -10
