# Mainnet assumeutxo refresh — height 190'467

Generated 2026-08-16 from a synced canonical mainnet node (`prune=0`) via
`dumptxoutset type=latest` at height **190467**. File version remains **v9**
(shielded unshield-velocity section included). This is a consensus-pinned
`loadtxoutset` snapshot, not an attested-fast-forward blob.

## Why

The previous public pin was 189'307. That height aged below the
`NODE_NETWORK_LIMITED` 288-block serving window (tip − 288), so a fresh
`loadtxoutset` bootstrap could not fetch the next bodies from pruned peers.
This pin sits above that floor. Strict consensus nodes
(`-matmulvalidation=consensus`) must refuse `loadtxoutsetattested`, so they
could not use the 187798 / 188231 attested drops.

`loadtxoutset` still checks the consensus-pinned `hash_serialized` /
`blockhash` / shielded commitment, and the background chainstate still
validates from genesis.

## Artifacts

| File | Role |
|---|---|
| `snapshot.manifest.json` | Published manifest (height, hashes, SHA256, file version) |
| `snapshot.report.json` | Sanitized generator report consumed by `scripts/apply_assumeutxo_report.py` |
| `SHA256SUMS` | Checksum for the external `snapshot.dat` blob |

The binary `snapshot.dat` (452,995,692 bytes, SHA256 in `SHA256SUMS`) is not
stored in git. It is published as a GitHub prerelease asset.

## Operator load

Requires a binary that includes this height in `m_assumeutxo_data`.

```bash
curl -L -o snapshot.dat https://github.com/btxchain/btx/releases/download/assumeutxo-190467/snapshot.dat
sha256sum -c SHA256SUMS
btx-cli -rpcclienttimeout=0 loadtxoutset /path/to/snapshot.dat
btx-cli getchainstates
```

Do not use this file with `loadtxoutsetattested`. Attested snapshots remain
trusted-mirror only.

Machine-class evidence only; no host or operator identifiers are retained.
