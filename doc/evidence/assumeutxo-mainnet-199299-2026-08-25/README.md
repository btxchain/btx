# Mainnet assumeutxo refresh — height 199'299

Generated 2026-08-25 from a synced archival mainnet node (`prune=0`) via
`dumptxoutset type=latest` at height **199299**. File version remains **v9**
(shielded unshield-velocity section included). This is a consensus-pinned
`loadtxoutset` snapshot, not an attested-fast-forward blob.

## Why

The previous public pin was 191'266. This pin is the GPU-signed stall-recovery
flag day (`f12a27d0…`, parent `be78622c…`, bits `1e2b22b5`). Strict consensus
nodes (`-matmulvalidation=consensus`) must refuse `loadtxoutsetattested`, so
they need a post-199298 `loadtxoutset` pin on the canonical GPU chain to rejoin
without ExactReplay-ing thousands of EncDr bodies.

`loadtxoutset` still checks the consensus-pinned `hash_serialized` /
`blockhash` / shielded commitment, and the background chainstate still
validates from genesis.

## Artifacts

| File | Role |
|---|---|
| `snapshot.manifest.json` | Published manifest (height, hashes, SHA256, file version) |
| `snapshot.report.json` | Sanitized generator report consumed by `scripts/apply_assumeutxo_report.py` |
| `SHA256SUMS` | Checksum for the external `snapshot.dat` blob |

The binary `snapshot.dat` (452,893,568 bytes, SHA256 in `SHA256SUMS`) is not
stored in git. It is published as a GitHub prerelease asset.

## Operator load

Requires a binary that includes this height in `m_assumeutxo_data`.

```bash
curl -L -o snapshot.dat https://github.com/btxchain/btx/releases/download/assumeutxo-199299/snapshot.dat
sha256sum -c SHA256SUMS
btx-cli -rpcclienttimeout=0 loadtxoutset /path/to/snapshot.dat
btx-cli getchainstates
```

Do not use this file with `loadtxoutsetattested`. Attested snapshots remain
trusted-mirror only.

Machine-class evidence only; no host or operator identifiers are retained.
