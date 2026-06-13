# Recovery-exit CPU plan

Date: 2026-06-14

## Problem

Post-sunset shielded recovery exits are intentionally one-note exits today. That
keeps user funds recoverable, but it also means a large legacy wallet can create
hundreds of independent shielded recovery-exit transactions. Even without a full
shielded proof envelope, each exit still requires membership, ownership,
nullifier, commitment-retirement, and block-template readiness checks. If those
transactions are cheap, miners rationally prefer empty blocks because the fee
does not compensate for the extra CPU and stale-template risk.

## Immediate policy fix

The current branch keeps recovery exits consensus-valid, but changes default
policy so they are not treated as cheap byte-sized transactions:

- Recovery exits receive `RECOVERY_EXIT_POLICY_VERIFY_UNITS` in policy virtual
  size.
- Mempool relay fee checks use shielded policy virtual size for shielded
  transactions.
- Wallet fee estimation and `z_sweeptotransparent` use the same shielded policy
  virtual size.
- Block template package scoring and `-blockmintxfee` checks use the same
  shielded policy virtual size.
- Template construction still caps recovery-exit work per block, so fee pricing
  cannot make an unbounded CPU block.
- Full shielded mempool cleanup remains a fallback at shielded height-gate
  boundaries; ordinary block connects use exact touched nullifier/commitment
  eviction.

This is policy-only. It does not invalidate old blocks and does not make
low-fee recovery exits consensus-invalid if a miner manually includes them.

## Why fees alone are not enough

Fees solve incentives, not verification cost. They make miners more willing to
include expensive exits, but every validating node still has to verify whatever
the block contains. The permanent design should reduce validation work per
recovered note, not merely charge more for it.

## Protocol design for low-CPU exits

The next recovery-exit format should aggregate many note exits into one
consensus object:

1. Freeze the post-sunset shielded membership root used for recovery.
2. Let a wallet or external recovery service build a batch off-chain from many
   notes.
3. Publish public nullifiers, retired commitments, and transparent outputs.
4. Attach one aggregate certificate proving that every listed note:
   - belongs to the frozen root,
   - is owned by the claimed key material,
   - derives the listed nullifier/commitment pair,
   - pays the declared transparent outputs and fee,
   - creates no shielded outputs and no pool credit.
5. Verify the aggregate certificate once during block validation, then perform
   only cheap public set checks for duplicate nullifiers/commitments.

Useful building blocks:

- Merkle multiproofs remove duplicated authentication nodes when proving many
  leaves from the same root. Ethereum's consensus specs define multiproofs as
  the minimal subset needed to authenticate a set of leaves against a root.
- Utreexo-style hash accumulators show the same owner-supplied-proof model for
  large sets: full nodes keep compact roots while owners carry inclusion
  witnesses.
- Recursive proof systems such as Halo or Nova let many checks be folded into a
  single succinct proof, so consensus verification can be close to one proof
  instead of N independent checks.

## Recommended roadmap

1. Ship the policy fix in the emergency branch so the current network stops
   underpricing recovery exits.
2. Keep `z_sweeptotransparent` one-note-per-transaction for now; it is simple,
   auditable, and cannot create shielded change.
3. Start a separate consensus branch for `V2_RECOVERY_EXIT_AGGREGATE`.
4. Prototype the batch certificate off-chain first:
   - begin with Merkle multiproof plus batch public checks,
   - benchmark verification time for 8, 16, 32, and 64 notes,
   - then evaluate recursive proof wrapping if multiproof-only is still too
     expensive.
5. Activate the aggregate format only after archive nodes, miners, and wallets
   have upgraded. Until then, rely on policy caps and CPU-priced fees.

## References

- Halo: Recursive Proof Composition without a Trusted Setup:
  https://eprint.iacr.org/2019/1021
- Electric Coin Company Halo 2 explainer:
  https://electriccoin.co/blog/explaining-halo-2/
- Nova: Recursive Zero-Knowledge Arguments from Folding Schemes:
  https://eprint.iacr.org/2021/370
- Ethereum consensus Merkle multiproof format:
  https://ethereum.github.io/consensus-specs/ssz/merkle-proofs/
- Utreexo: A dynamic hash-based accumulator optimized for the Bitcoin UTXO set:
  https://eprint.iacr.org/2019/611
