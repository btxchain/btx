# WITHDRAWN — do not load this snapshot

`base_hash` `f12a27d01a4b5a1710efa4497adf6f4c7da311d1c7b4f6a79cbf80f0b3110ec5`
is on the withdrawn 0.34.1 branch, not the majority chain (issue 127).
0.34.5 removes this compiled assumeutxo entry. Historical dump notes follow.

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

**Do not run this.** 0.34.5 rejects this hash. Historical command only:

```bash
# WITHDRAWN — this strands the node on the 0.34.1 branch (issue 127)
# curl -L -o snapshot.dat https://github.com/btxchain/btx/releases/download/assumeutxo-199299/snapshot.dat
```

Do not use this file with `loadtxoutsetattested`. Attested snapshots remain
trusted-mirror only.

Machine-class evidence only; no host or operator identifiers are retained.
