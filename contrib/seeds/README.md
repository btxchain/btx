# Seeds

Utility to generate the seeds.txt list that is compiled into the client
(see [src/chainparamsseeds.h](/src/chainparamsseeds.h) and other utilities in [contrib/seeds](/contrib/seeds)).

BTX mainnet currently bootstraps from the live DNS seed `node.btx.tools` and
from the fixed public endpoints compiled from `nodes_main.txt`. Use this
workflow when you intentionally want to regenerate the fixed seed table after
verifying which public bootstrap nodes are still serving current BTX peers.

Update `PATTERN_AGENT` and `MIN_BLOCKS` in `makeseeds.py` as the BTX network
version/height evolves.

Collect crawler exports for each network into:
- `seeds_main.txt`
- `seeds_test.txt`
- `seeds_testnet4.txt`
- `seeds_signet.txt` (for custom signet only)

Each input line should match the DNS crawler output format consumed by
`makeseeds.py` (address, uptime, service flags, blocks, user agent, etc.).

Then run the following from `/contrib/seeds`:

```
curl https://raw.githubusercontent.com/asmap/asmap-data/main/latest_asmap.dat > asmap-filled.dat
python3 makeseeds.py -a asmap-filled.dat -s seeds_main.txt > nodes_main.txt
python3 makeseeds.py -a asmap-filled.dat -s seeds_test.txt > nodes_test.txt
python3 makeseeds.py -a asmap-filled.dat -s seeds_testnet4.txt -m 72600 > nodes_testnet4.txt
# Optional: only if operating a custom BTX signet
python3 makeseeds.py -a asmap-filled.dat -s seeds_signet.txt > nodes_signet.txt
python3 generate-seeds.py . > ../../src/chainparamsseeds.h
```
