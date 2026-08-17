# Mainnet assumeutxo refresh — height 191'266

Generated 2026-08-17 from a synced canonical mainnet node (`prune=0`) via
`dumptxoutset type=latest` at height **191266**. File version remains **v9**
(shielded unshield-velocity section included). This is a consensus-pinned
`loadtxoutset` snapshot, not an attested-fast-forward blob.

## Why

The previous public pin was 190'507. This pin is the live GPU-signed frontier
after the archive GETDATA / ExactReplay serve stall was fixed (`890e16a3`).
While that stall was live, catch-up ran at about one block per 12–15s (and
worse under msghand saturation), and one archive's `-fastshieldedstartup`
persist drifted onto the older 179000 shielded-state pin. Strict consensus
nodes (`-matmulvalidation=consensus`) must refuse `loadtxoutsetattested`, so
they need a post-split `loadtxoutset` pin on the canonical GPU chain.

`loadtxoutset` still checks the consensus-pinned `hash_serialized` /
`blockhash` / shielded commitment, and the background chainstate still
validates from genesis.

## Artifacts

| File | Role |
|---|---|
| `snapshot.manifest.json` | Published manifest (height, hashes, SHA256, file version) |
| `snapshot.report.json` | Sanitized generator report consumed by `scripts/apply_assumeutxo_report.py` |
| `SHA256SUMS` | Checksum for the external `snapshot.dat` blob |

The binary `snapshot.dat` (453,053,487 bytes, SHA256 in `SHA256SUMS`) is not
stored in git. It is published as a GitHub prerelease asset.

## Operator load

Requires a binary that includes this height in `m_assumeutxo_data`.

```bash
curl -L -o snapshot.dat https://github.com/btxchain/btx/releases/download/assumeutxo-191266/snapshot.dat
sha256sum -c SHA256SUMS
btx-cli -rpcclienttimeout=0 loadtxoutset /path/to/snapshot.dat
btx-cli getchainstates
```

Do not use this file with `loadtxoutsetattested`. Attested snapshots remain
trusted-mirror only.

Machine-class evidence only; no host or operator identifiers are retained.
