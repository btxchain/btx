BTX version 0.33.4 is tagged from:

  <https://github.com/btxchain/btx>

This release includes the 0.33.3 network-stability line plus EncDr stall
recovery at mainnet height **199299** (`num/den = 1/1`). Compact `F`,
`powLimit`, Epoch A (height 185000), and the 191714 dump-floor rule are
unchanged. Nodes that remain on 0.33.3 stay valid through **199298** and
must upgrade **before 199299**. 0.33.4 also fixes signed-frontier catch-up,
attestor BestKnown, equal-work lost-twin ExactReplay, unique EncDr templates,
and HeightOccupied GETDATA skip.

The last 0.33.4.x binary line is **v0.33.4.2** (assumeutxo pin at 199299
plus provenance reseal). See
[release-notes-0.33.4.2.md](release-notes-0.33.4.2.md). 0.34 notes live in
[release-notes.md](../release-notes.md).

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

Shut down the previous node cleanly, wait for it to exit, and replace
its `btxd`, `btx-cli`, and related binaries with the v0.33.4 binaries.
Back up wallets and configuration before upgrading.

This release **does** change consensus at mainnet height 199299 (`1/1`
re-anchor plus the 1080s parent nTime cap). Installing it is required to
stay on the attested chain **from 199299**. It is recommended immediately
for attestors, public archives, and miners that follow the signed frontier.

# Compatibility

Same platform and epoch matrix as 0.33.3: Linux, macOS 13+, Windows 10+.
Mainnet remains on MatMul v3 below height 185000; Epoch-A Profile 1
ExactReplay applies at and above height 185000. That Epoch-A tuple is
unchanged. The 191714 `nBits` dump floor (`0x1f0a3d70`) is unchanged.

# Notable Changes

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

## HEADER_ONLY equal-work lost twin GETDATA (2026-08-24)

When two equal-work children share a parent and the local signer already
attested one of them, the HEADER_ONLY skip set suppressed `GETDATA` for
the unattested twin (`select=root_header_only_skip`, `in_flight=0`).
`GETMMATTEST` on that hash returns `not_canonical`, so archives could not
unstick the signer. Local signers now fetch that twin once a peer's
BestKnown has already extended it, ExactReplay it, and then fetch each
better-work descendant whose parent has a body, bounded to short-reorg
depth 1–6. Trusted mirrors still skip until the attestor signs. A lone
competing sibling with no descendant headers stays off the miner GPU.

## EncDr stall recovery at 199299 (public #119)

Mainnet flag day **199299**, `num/den = 1/1` (copy parent bits, re-anchor ASERT).
Per-block `nTime` may not advance more than 1080s from the parent. Cap-sat
headers get clamped ASERT credit. 199298 is **not** dumped. Upgrade before
199299. See #117 for unique EncDr templates and HeightOccupied GETDATA skip.

# Included public work

- btxchain/btx #105 — 0.33.3 network stability (already released)
- btxchain/btx #112 — catch-up GETDATA vs active tip; GETMMATTEST first hole
- btxchain/btx #113 — BestKnown, attestor yield, lost-twin ExactReplay

Public #111 does not exist on btxchain/btx; the post-0.33.3 stack is
#112 and #113.

# Consensus

Mainnet EncDr stall recovery activates at height **199299** with `num/den = 1/1`
(inherit parent bits, no dump). Height **199298** is unchanged from 0.33.3 so
the live EncDr lottery stays valid. Installing v0.33.4 is a **mandatory
unsignalled upgrade before 199299 exists**. Unupgraded nodes keep the 191715
ASERT anchor and `bad-diffbits` on every height at and above 199299.

Do not retune `F` or `powLimit` in this release. The five recovery knobs are
bound into `replay_authority_context` (schema 4). Clamped ASERT credit is
cached on `CBlockIndex` so header-sync cost does not grow with
`(tip - flag_day)`.
