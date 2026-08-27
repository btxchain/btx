# Mainnet assumeutxo refresh — height 199'300

Generated 2026-08-27 from a synced archival mainnet node (`prune=0`,
`txindex`, `retainshieldedcommitmentindex`) via `dumptxoutset type=latest`
at height **199300**. File version remains **v9**. This is a consensus-pinned
`loadtxoutset` snapshot, not an attested-fast-forward blob.

## Why

The previous public pin was 199'299. This pin is the first height at which
the shielded pool is closed (`nShieldedPoolDisableHeight`). Strict consensus
nodes (`-matmulvalidation=consensus`) must refuse `loadtxoutsetattested`, so
they need a post-close `loadtxoutset` pin on the canonical GPU chain.

`loadtxoutset` still checks the consensus-pinned `hash_serialized` /
`blockhash` / shielded commitment, and the background chainstate still
validates from genesis.

The `shielded_state_commitment` is byte-identical to the 199299, 191266, and
55000 pins (`94343b76…`). That is the frozen closed-section pin, not a zeroed
placeholder.

## Artifacts

| File | Role |
|---|---|
| `snapshot.manifest.json` | Published manifest (height, hashes, SHA256, file version) |
| `snapshot.report.json` | Sanitized generator report consumed by `scripts/apply_assumeutxo_report.py` |
| `SHA256SUMS` | Checksum for the external `snapshot.dat` blob |

The binary `snapshot.dat` (452,893,894 bytes, SHA256 in `SHA256SUMS`) is not
stored in git. It is published as a GitHub prerelease asset.

## Operator load

Requires **v0.34.1** (or later) so this height is in `m_assumeutxo_data`.
v0.34.0 cannot load it.

```bash
curl -L -o snapshot.dat https://github.com/btxchain/btx/releases/download/assumeutxo-199300/snapshot.dat
sha256sum -c SHA256SUMS
btx-cli -rpcclienttimeout=0 loadtxoutset /path/to/snapshot.dat
btx-cli getchainstates
```

Do not use this file with `loadtxoutsetattested`. Attested snapshots remain
trusted-mirror only.

Machine-class evidence only; no host or operator identifiers are retained.
