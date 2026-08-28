BTX version 0.33.4.2 is tagged from:

  <https://github.com/btxchain/btx/releases/tag/v0.33.4.2>

This is the current line on `main`. CLIENT_VERSION remains 0.33.4. Git describe
is **v0.33.4.2** (seal `c892f1a7`, freeze `400953c2`, fingerprint
`a427fb12c69841ed082e7d7604b17beaac8749932b50c646747ebf81d0309928`). EncDr
ExactReplay digest is unchanged (`b4777985…`).

0.33.4.2 is 0.33.4.1 plus the compiled **assumeutxo pin at height 199299**
(public #121) and a provenance reseal so CUDA attestors pass the GPU canary.
Consensus at 199299 is the same 1/1 stall-recovery as v0.33.4.1. Compact `F`,
`powLimit`, Epoch A (height 185000), and the 191714 dump-floor rule are
unchanged.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

Shut down the previous node cleanly, wait for it to exit, and replace
its `btxd`, `btx-cli`, and related binaries with the v0.33.4.2 binaries.
Back up wallets and configuration before upgrading. Keep Metal `.metallib`
files next to `btxd`.

| Asset | SHA256 |
|---|---|
| [linux-x86_64-cpu](https://github.com/btxchain/btx/releases/download/v0.33.4.2/btx-0.33.4.2-linux-x86_64-cpu.tar.gz) | `aecd0725a6799b2f7fa765521e592f8645512a2f80856f90384d248e054523a5` |
| [linux-x86_64-cuda](https://github.com/btxchain/btx/releases/download/v0.33.4.2/btx-0.33.4.2-linux-x86_64-cuda.tar.gz) | `3a1b27552ab442cc92d2575e770423a895eedaa6a607d5ffbbadedc546b9ee98` |
| [macos-arm64-metal](https://github.com/btxchain/btx/releases/download/v0.33.4.2/btx-0.33.4.2-macos-arm64-metal.tar.gz) | `d8c3e816aa012cb014bd1810d9134466c4d4539f7137c101903740e012d02eec` |

Checksums: [SHA256SUMS](https://github.com/btxchain/btx/releases/download/v0.33.4.2/SHA256SUMS).

v0.33.4.1 cannot `loadtxoutset` the 199299 snapshot. CUDA attestors must use
this sealed build, not unsealed `v0.33.4`.

# Fast-start snapshot

**Do not load this pin.** assumeutxo-199299 (`f12a27d0…`) is on the
withdrawn 0.34.1 branch ([issue 127](https://github.com/btxchain/btx/issues/127)).
Use [assumeutxo-191266](https://github.com/btxchain/btx/releases/tag/assumeutxo-191266)
or sync from genesis. Historical 0.33.4.2 text follows.

Published assumeutxo pin (v9): [assumeutxo-199299](https://github.com/btxchain/btx/releases/tag/assumeutxo-199299)

- height **199299**, blockhash `f12a27d01a4b5a1710efa4497adf6f4c7da311d1c7b4f6a79cbf80f0b3110ec5`
- `txoutset_hash` `db9e83156602927315d108a1ebce230b30eb78832e69db1947a21f5b5f2b8bf6`
- `snapshot.dat` SHA256 `3c9e52ff053cd183af239dfce42cd57d007bdf530fd48ba9783623662d15070f`

```bash
btx-cli -rpcclienttimeout=0 loadtxoutset snapshot.dat
```

Use `loadtxoutset`, not `loadtxoutsetattested`. Fresh chainstate only.

# Compatibility

Same platform and epoch matrix as 0.33.3: Linux, macOS 13+, Windows 10+.
Mainnet remains on MatMul v3 below height 185000; Epoch-A Profile 1
ExactReplay applies at and above height 185000. That Epoch-A tuple is
unchanged. The 191714 `nBits` dump floor (`0x1f0a3d70`) is unchanged.

# Notable Changes

## AssumeUTXO pin at 199299 (public #121)

The previous public pin was 191266, which is below many catching-up tips and
cannot be loaded there. v0.33.4.2 compiles the stall-recovery flag-day
snapshot so a fresh node can `loadtxoutset` onto the attested chain without
ExactReplay-ing thousands of EncDr bodies.

## EncDr stall recovery at 199299 (public #119)

Mainnet flag day **199299**, `num/den = 1/1` (copy parent bits, re-anchor ASERT).
Per-block `nTime` may not advance more than 1080s from the parent. Cap-sat
headers get clamped ASERT credit. 199298 is **not** dumped. See #117 for unique
EncDr templates and HeightOccupied GETDATA skip.

## Provenance reseal (public #120, then 0.33.4.2)

GPU attestors refuse an unsealed tree (`build_provenance_mismatch`). v0.33.4.1
resealed after the 199299 bake; v0.33.4.2 resealed after the assumeutxo pin.
ExactReplay digest unchanged.

## HEADER_ONLY equal-work lost twin GETDATA (public #117)

When two equal-work children share a parent and the local signer already
attested one of them, the HEADER_ONLY skip set suppressed `GETDATA` for
the unattested twin (`select=root_header_only_skip`, `in_flight=0`).
`GETMMATTEST` on that hash returns `not_canonical`, so archives could not
unstick the signer. Local signers now fetch that twin once a peer's
BestKnown has already extended it, ExactReplay it, and then fetch each
better-work descendant whose parent has a body, bounded to short-reorg
depth 1–6. Trusted mirrors still skip until the attestor signs. A lone
competing sibling with no descendant headers stays off the miner GPU.

## Signed-frontier GETDATA vs the active tip (public #112)

Catch-up `GETDATA` compared the next needed body against `m_best_header`.
When headers ran ahead of the attested active tip, that comparison
skipped the hole at `tip+1` and left archives HEADER_ONLY with
`in_flight=0`. Catch-up now compares against the active tip.

During signed-frontier catch-up, `GETMMATTEST` is issued only for the
first hole rather than a stale mid-suffix height. That unsticks
archives that already had a local quorum header but no body.

## Attestor BestKnown from MMATTEST (public #113)

Attestors now advance peer BestKnown from `MMATTEST` and from connected
bodies, so the signed frontier is not parked on a stale header while
the attested chain has already moved.

## Park-depth yield to the longer attested attestor (public #113)

After park-depth drift, a shorter local attestor yields to the longer
attested peer instead of mining or following the losing equal-work
branch.

## Lost-twin ExactReplay of the attested sibling (public #113)

When two equal-work children share a parent and the local signer
ExactReplay'd the later unattested twin, the node could remain
HEADER_ONLY on the attested winner because ExactReplay required
`pprev==tip` and retry preferred fossils. 0.33.4 ExactReplays the
attested sibling across that short reorg and cools budget-deferred
fossils while the frontier is off-chain.

# Included public work

- btxchain/btx #105 — 0.33.3 network stability (already released)
- btxchain/btx #112 — catch-up GETDATA vs active tip; GETMMATTEST first hole
- btxchain/btx #113 — BestKnown, attestor yield, lost-twin ExactReplay
- btxchain/btx #117 — HEADER_ONLY lost-twin GETDATA
- btxchain/btx #119 — EncDr stall recovery at 199299
- btxchain/btx #120 — provenance reseal after the 199299 bake
- btxchain/btx #121 — assumeutxo pin at 199299

Public #111 does not exist on btxchain/btx; the post-0.33.3 stack is
#112 and #113.

# Consensus

Mainnet EncDr stall recovery is active at height **199299** with `num/den = 1/1`
(inherit parent bits, no dump). Nodes below 0.33.4 keep the 191715 ASERT
anchor and `bad-diffbits` on every height at and above 199299.

Do not retune `F` or `powLimit` in this release. The five recovery knobs are
bound into `replay_authority_context` (schema 4). Clamped ASERT credit is
cached on `CBlockIndex` so header-sync cost does not grow with
`(tip - flag_day)`.

Mine 199300 only on attested parent
`f12a27d01a4b5a1710efa4497adf6f4c7da311d1c7b4f6a79cbf80f0b3110ec5`.
