# BTX 0.34.14 — Scheduled security activation

**Status:** release. `CLIENT_VERSION` is **0.34.14** with
`CLIENT_VERSION_RC=0` and `CLIENT_VERSION_IS_RELEASE=true`. `btxd -version`
prints `v0.34.14`. P2P subversion is `/BTX:0.34.14/`. Do not recut
`v0.34.13` or `v0.34.12`.

0.34.13 enforced the 32-byte HTLC preimage check from genesis. A block
that 0.34.12 accepts could then split 0.34.13 nodes from the rest of the
network. 0.34.14 keeps that check as standard policy immediately and makes
it a consensus rule at mainnet block **244000**. Blocks below that height
validate the same way they did on 0.34.12.

Two further consensus checks use the same height. Recovery-proof
verification joins the shielded block budget at 244000, so older blocks
stay valid. From 244000, a MatMul header that has only passed the
compact-target precheck cannot become the best header, including when the
header index is loaded or recalculated. A body that reaches full
transaction validation can still lead. Stored historical chainwork is not
rewritten. A qualified GPU digest mismatch is a retryable local failure.
Portable CPU confirmation does not run on the calling thread while that
thread holds the accelerator lease.

## What applies on the first run

These are not height-gated:

- Snapshot bootstrap uses the checksum-verified local manifest, rejects
  unsafe filenames, and audits a snapshot chainstate with the same shielded
  checks as a normal chainstate.
- An unset `-reorgpolicy` stays legacy. The 0.34.13 hard ceiling is opt-in
  with `-reorgpolicy=bounded`.
- A structurally rejected block body is not fetched again. A PQ attestation
  reply spends the same serve token as a classical reply. A catch-up
  attestation is signed only after ExactReplay on the active chain.
- Park uses body-authenticated work. A far-behind competing twin that is
  not on the followed best-header chain stays on the budgeted ExactReplay
  path.
- Each free-grant use is consumed once. A release that is not downloadable
  is not seeded or served as plaintext. A malformed model feed object is
  skipped instead of stopping `btx-modeld`.
- Encrypted wallets store PQ descriptor seeds as ciphertext. Reorg
  notifications keep only wallet-relevant transaction ids, capped per wallet.

## Unchanged

Block subsidy, difficulty adjustment, ExactReplay arithmetic, and
`automatic_spend_atoms` are unchanged. Pay With Compute remains an
off-consensus access ledger. Regtest still enforces the HTLC preimage rule
from height 0 unless `-regtesthtlcpreimage32height` sets another height.
