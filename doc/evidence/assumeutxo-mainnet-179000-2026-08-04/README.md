# Mainnet assumeutxo refresh — height 179'000

Generated 2026-08-04 from a synced archival mainnet node (`prune=0`,
`txindex=1`) via `dumptxoutset` rollback to height **179000**.

## Why

This release snapshot reduces foreground catch-up to fewer than 700 blocks at
generation time, so new 0.33.2 nodes can reach the live chain without replaying
the full history.

## Artifacts

| File | Role |
|---|---|
| `snapshot.manifest.json` | Published manifest (height, hashes, SHA256, file version) |
| `snapshot.report.json` | Sanitized generator report consumed by `scripts/apply_assumeutxo_report.py` |
| `mainnet-hardening.json` | Matching checkpoint, chainwork, and chain transaction metadata |
| `SHA256SUMS` | Checksum for the external `snapshot.dat` blob |

The binary `snapshot.dat` (452,282,113 bytes, SHA256 in `SHA256SUMS`) is not
stored in git. It is distributed with the v0.33.2 release.

## Chainparams updates (same freeze)

- New assumeutxo entry at 179'000 (snapshot v9 plus shielded-state pin)
- `nMinimumChainWork`, `defaultAssumeValid`, checkpoint, and `chainTxData`
  refreshed to the same height

## Operator load

```bash
btx-cli -rpcclienttimeout=0 loadtxoutset /path/to/snapshot.dat
btx-cli getchainstates
```

Machine-class evidence only; no host or operator identifiers are retained.
