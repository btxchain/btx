# Mainnet assumeutxo refresh — height 176'600

Generated 2026-08-01 from a synced archival mainnet node (`prune=0`,
`txindex=1`) via `dumptxoutset` rollback to height **176600**.

## Why

The previous published floor (155'700) left a large foreground catch-up gap.
Refreshing the compiled `m_assumeutxo_data` entry shrinks `snapshot→tip` work
for validators bootstrapping before activation. Combined with the net-processing
change that defers background genesis→snapshot downloads until the active
chain leaves IBD, tip usability is prioritized over background seal.

## Artifacts

| File | Role |
|---|---|
| `snapshot.manifest.json` | Published manifest (height, hashes, SHA256, file version) |
| `snapshot.report.json` | Generator report used by `scripts/apply_assumeutxo_report.py` |
| `SHA256SUMS` | Checksum for the external `snapshot.dat` blob |

The binary `snapshot.dat` (~431 MiB, SHA256 in `SHA256SUMS`) is **not** stored
in git. Distribute it with the release bundle.

## Chainparams updates (same commit)

- New assumeutxo entry at 176'600 (v9 + shielded pin)
- `nMinimumChainWork` / `defaultAssumeValid` / checkpoint / `chainTxData` refreshed to the same height

## Operator load

```bash
btx-cli -rpcclienttimeout=0 loadtxoutset /path/to/snapshot.dat
btx-cli getchainstates
```

Machine-class evidence only (no host identifiers).
