BTX version 0.33.4rc1 is staged from:

  <https://github.com/btxchain/btx>

This is a **non-consensus** refinement on the 0.33.3 line. Compact `F`,
ASERT, `powLimit`, Epoch A (height 185000), and the 191714 dump-floor
rule are unchanged. Nodes that remain on 0.33.3 stay consensus-valid.
0.33.4 fixes signed-frontier catch-up, attestor BestKnown, and equal-work
lost-twin ExactReplay so attestors, archives, and miners follow the
attested tip without wedging.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

Shut down the previous node cleanly, wait for it to exit, and replace
its `btxd`, `btx-cli`, and related binaries with the v0.33.4 binaries.
Back up wallets and configuration before upgrading.

This release does **not** change consensus parameters. Installing it is
not required to stay on the attested chain after 191714. It is
recommended for attestors, public archives, and miners that follow the
signed frontier.

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

# Included public work

- btxchain/btx #105 — 0.33.3 network stability (already released)
- btxchain/btx #112 — catch-up GETDATA vs active tip; GETMMATTEST first hole
- btxchain/btx #113 — BestKnown, attestor yield, lost-twin ExactReplay

Public #111 does not exist on btxchain/btx; the post-0.33.3 stack is
#112 and #113.

# Consensus

Unchanged from 0.33.3. Do not retune `F`, ASERT, or `powLimit` in this
release.
