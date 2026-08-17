BTX version 0.33.3 is released from:

  <https://github.com/btxchain/btx/releases>

This release lands Phase 1 of the GPU-verified full-node transition:
the mainnet MatMul ASERT dump floor, P2P catch-up so CPU archives can
follow a GPU attestor, and removal of local extra-work pins now that
compact `F` is consensus. Epoch A remains at height 185000. See
`doc/btx-gpu-verified-network-transition.md`.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

Shut down the previous node cleanly, wait for it to exit, and replace
its `btxd`, `btx-cli`, and related binaries with the v0.33.3 binaries.
Back up wallets and configuration before upgrading.

This release changes consensus at height 191714. Every validating node
on the attested chain must complete the upgrade before that height is
mined. A 191714 block produced under the pre-floor `nBits` is invalid
under the new rule. The dump-floor height was pulled forward from the
earlier 200000 schedule so installing this binary does not leave a
multi-day window of easy ASERT `nBits` (lottery twins / difficulty
collapse) before the clamp. Compact `F` is unchanged.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+. Mainnet remains
on MatMul v3 below height 185000; Epoch-A Profile 1 ExactReplay applies
at and above height 185000. That Epoch-A tuple is unchanged.

From height 191714, header `nBits` cannot be easier than compact
`0x1f0a3d70`. Nodes that have not upgraded will still accept that harder
target, but they will also accept easier `nBits` that this release
rejects. Mixed versions at 191714 therefore split the attested chain.
Upgrade before that height is mined.

Production Profile 1 ExactReplay remains a qualified-accelerator path.
CPU ExactReplay is still an explicit pre-activation or diagnostic path,
not an automatic production fallback. Phase 1 public CPU archives
continue to follow signed ExactReplay verdicts; they are not
independently validating full nodes.

# Notable Changes

## Phase 1 of GPU-verified full nodes

This is Phase 1 of the topology in
`doc/btx-gpu-verified-network-transition.md`: stop easy-ASERT dump
inflation and keep public CPU seeds able to follow the attested chain.
It is not a new consensus epoch. Epochs B–D remain separately reviewed.

Still 1-of-1 attestation in this release. M-of-N is already in the
binary: repeat `-matmultrustedpubkey=<hex>` for distinct compressed
secp256k1 keys and set `-matmultrustedthreshold=M` with
`1 <= M <= N`. Phase 2 is adding GPUs and raising `M`. Phase 3 is
converting archives to GPU ExactReplay. Do not drop
`-matmultrustedpubkey` on the seed layer in this phase.

## Mainnet MatMul ASERT dump floor

| Item | Value |
|---|---|
| Dump-floor height `nMatMulPowLimitUpgradeHeight` | `191714` |
| Floor compact `powLimitUpgrade` (`F`) | `0x1f0a3d70` (unchanged) |
| ASERT half-life | `14400` at height `191715` |
| Profile 1 ExactReplay digest | unchanged (`b4777985…`) |
| Epoch A | still `185000` |

Header `nBits` at and after 191714 cannot be easier than compact
`0x1f0a3d70`. `F` is not retuned. Half-life lengthening is height
191715 so a stall after the floor cannot unwind many short half-lives
back toward historical `powLimit`. Historical `powLimit` is not mutated.

Public `getblocktemplate` `bits`/`target` follow `GetNextWorkRequired`.
Local extra-work pins (`-signermintargetcompact`) are removed in this
release because `F` is now consensus.

The production golden manifest re-seals source slots `[7]` (revision)
and `[8]` (tree fingerprint) after the logic commit. Digest slot `[4]`
is unchanged (`b4777985…`). That reseal is a fingerprint of the landing
tree, not a MatMul change.

## P2P catch-up for CPU archives and GPU attestors

- `GETHEADERS` is served from claimed chain work or when the active tip
  has a configured attestation quorum. A stale `nAuthenticatedChainWork`
  is no longer the only gate: an ExactReplay-valid attestor must not
  return empty headers to CPU archives.
- Authenticated chain work is promoted when ExactReplay or a trusted
  quorum is recorded, including descendants, so the serve gate and
  trust-adjusted ranking follow the attested prefix.
- GPU attestors ignore unsolicited inbound `BLOCK`/`HEADERS` from
  non-authority peers. Outbound `GETDATA` replies from seeds still
  count. Random lottery headers must not steal ExactReplay from the
  attestor.
- CPU seeds keep requesting headers from the GPU attestor after the
  VERSION handshake height. A one-shot BestKnown seed at connect time
  must not stop pulls for blocks minted later.

## Roll order

Upgrade public CPU archives first, then public miners, GPU attestor
last, so block 191714 is produced under the new `nBits`. A 191714 mined
under the old `nBits` is invalid on the new rule.

## SignAuthoritative: one hash per height

`SignAuthoritative` mints at most one hash per height for the local
key. If that key already signed a different hash at the same height, the
result is `HeightOccupied`. The bound survives hot-cache eviction: an
in-memory durable-load map still refuses a second signature after the
bounded attestation cache has dropped the original bucket.

# Known Limitations

- Phase 1 remains 1-of-1. Compromise of that single attestation key can
  make configured trusted mirrors accept false MatMul work. Independent
  `-matmulvalidation=consensus` nodes ignore those signatures as
  authority.
- Trusted CPU archives and RPC mirrors are not independently validating
  full nodes. Do not describe or expose them as such.
- M-of-N is compiled in, but this release does not add attestor GPUs
  or raise `M`. That is Phase 2.
- Public seeds are not converted to GPU ExactReplay in this release.
  That is Phase 3.

# Credits

Thanks to the contributors and reviewers of the dump-floor consensus
change, P2P catch-up for CPU archives and GPU attestors, attestation
height occupancy, golden-manifest handling, testing, documentation, and
release engineering.

# Previous release

v0.33.2 notes: [`doc/release-notes/release-notes-0.33.2.md`](release-notes/release-notes-0.33.2.md).
