# RECOVERY_EXIT — transparent-claim stranded-note recovery (post-125,000)

**Decision (owner):** preserve stranded-note rescue after the 125,000 sunset, but only as a
**transparent claim that reveals the spent note** — DS-4-immune by construction, with no dependency on
the (unwired, audit-gated) bound-mode ring path. Chosen over the ring-based "unique nullifier" form,
which carries a bounded DS-4 over-drain residual because legacy cm-v1 notes cannot be anchor-bound.

**Hard safety constraint:** `RECOVERY_EXIT` must not be activated until it also closes the cross-path
double-spend between normal `V2_SEND` unshield and revealed-commitment recovery. A pre-snapshot note may
be spendable by both paths; therefore a recovery claim must retire the note's revealed commitment **and**
the exact normal-path nullifier that a `V2_SEND` spend would have produced. A claimant-supplied nullifier
is not sufficient.

## Current branch status

This branch activates `V2_RECOVERY_EXIT` on production-like networks at the same `125000` height as the
shielded sunset. The feature is intentionally narrow: it only pays an existing note to transparent
outputs, reveals the recovered note, appends no shielded outputs, and retires both spend identifiers.

Implemented in the audit branch:

- wire/data layer for `V2_RECOVERY_EXIT` and `RecoveryExitPayload`;
- persistent reorg-safe spent-commitment set;
- deterministic derivation of both identifiers retired by a claim: the revealed note commitment `cm` and
  the canonical SMILE2 normal-exit nullifier `normal_nf`;
- claim predicate checks for value, pure transparent outflow, PQ ownership binding, membership proof,
  prior nullifier spend, and prior commitment claim;
- `ConnectBlock`/`DisconnectBlock` collection, insertion, and undo for the derived nullifier and
  revealed commitment;
- membership verification against `nShieldedRecoveryExitFrozenRoot` when that root is hardcoded, otherwise
  against the immutable live tree root after the zero-output sunset rule freezes the tree;
- mempool reservation of both derived identifiers, so pending recovery claims conflict with normal
  spends of the same note and with duplicate recovery claims before block construction;
- full mempool claim validation using the same ownership, membership, value, and package-conflict rules
  as block validation;
- wallet-side builder for a recovery claim; and
- unit/regtest-style coverage of ownership, membership, binding-hash sensitivity, spent-set undo, and the
  connect-flow sequence.

Production posture:

- `nShieldedRecoveryExitActivationHeight == nShieldedSunsetHeight == 125000` on mainnet, testnet,
  testnet4, signet, and shielded-v2 dev.
- Normal spendable notes exit through strict pure `V2_SEND` transparent unshield: `value_balance > fee`
  and zero shielded outputs.
- Stranded notes exit through `V2_RECOVERY_EXIT` if the wallet has the note opening, spending key, and
  Merkle witness needed for the transparent claim.
- This has internal AI-assisted review and tests, not independent external cryptographer sign-off.

## 1. Philosophy

Recovery is legacy shielded value **leaving** the pool — not moved, refreshed, or re-created. A
RECOVERY_EXIT openly identifies one pre-snapshot note, proves ownership, pays the value out to
transparent, and permanently retires that note. Because the spent commitment is **revealed**, consensus
deduplicates on the commitment itself, so there is no hidden ring and no forgeable key-image: **DS-4 is
structurally impossible on this path.** The cost is the recovered note's value/linkage becoming public —
acceptable, since the value is exiting the pool.

## 2. New consensus operation

A new shielded operation `V2_RECOVERY_EXIT` is gated by
`nShieldedRecoveryExitActivationHeight`. Once activated, it is the **second** permitted post-sunset
shielded operation, alongside the strict pure `V2_SEND` transparent unshield (`value_balance > fee` and
zero shielded outputs). All other families remain rejected (`bad-shielded-sunset-non-exit` or a more
specific sunset reject).

### Revealed fields (the claim)
- `value` (CAmount), `recipient_pk_hash` (uint256), `rho` (uint256), `rcm` (uint256) — the full opening
  of the note, so `cm` is recomputable:
  `inner = SHA256("BTX_Note_Inner_V1" || LE64(value) || recipient_pk_hash)`,
  `cm = SHA256("BTX_Note_Commit_V1" || inner || rho || rcm)`.
- `spend_pubkey` — the full PQ public key with `SHA256(spend_pubkey) == recipient_pk_hash`.
- `ownership_sig` — a PQ signature by `spend_pubkey` over the claim's transparent-binding hash (the tx /
  outputs / `cm`), proving the claimant controls the note.
- `membership_proof` — a Merkle path proving `cm` was in the shielded commitment tree at or before the
  frozen 125,000 snapshot. Validation uses a hardcoded `nShieldedRecoveryExitFrozenRoot` when present;
  otherwise it uses the live tree root after the sunset zero-output rule has made that root immutable.
- No user-provided nullifier is trusted. Consensus reconstructs the `ShieldedNote` from the revealed
  fields and derives the canonical normal-exit nullifier itself, using the same deterministic note-to-SMILE
  derivation as the `V2_SEND` path (`ComputeSmileNullifierFromNote(SMILE_GLOBAL_SEED, note)`). If the note
  is not eligible for a consensus-derivable normal-exit nullifier, `RECOVERY_EXIT` is invalid for that note
  until a reviewed derivation exists.

## 3. Consensus validation rules (ALL must hold)

At `height >= nShieldedRecoveryExitActivationHeight` (which must be `>= 125,000`), accept a
`V2_RECOVERY_EXIT` iff:

1. **Recompute & bind:** `cm` recomputes from `(value, recipient_pk_hash, rho, rcm)` as above.
2. **Pre-snapshot membership:** `membership_proof` validates `cm` against the **frozen 125,000 commitment
   root**: either the pinned root or the live immutable post-sunset root. A note that did not exist at the
   snapshot cannot be recovered.
3. **Ownership:** `SHA256(spend_pubkey) == recipient_pk_hash` and `ownership_sig` verifies under
   `spend_pubkey` over the claim binding hash.
4. **Pure transparent exit:** `value_balance == value` and `value_balance > fee`; the bundle has
   **zero shielded outputs**; exactly one (or the designated) transparent output with
   `transparent_out == value - fee`. (No re-shield, no change note.)
5. **Cross-path single-spend:** consensus derives `normal_nf`, the exact nullifier that a normal
   post-sunset `V2_SEND` SMILE2 unshield would reveal for this note. Both `cm` and `normal_nf` must be
   unspent before acceptance. On connect, consensus records **both**:
   - `cm` in a persistent spent-commitment set, preventing a second `RECOVERY_EXIT`; and
   - `normal_nf` in the existing shielded nullifier set, preventing a later normal `V2_SEND` spend.

   Conversely, if the note was already spent normally, `normal_nf` is already in the nullifier set and the
   recovery claim is rejected. This is the authoritative double-spend guard. A claimant-provided nullifier,
   or a commitment-only guard, is invalid because it leaves the normal-spend and recovery-spend keyspaces
   disconnected.
6. **Velocity cap:** `value` counts as net pool egress for the block and is subject to
   `nShieldedUnshieldVelocityCapBps` over the trailing window, exactly like a `V2_SEND` unshield.
7. **Bounded lifetime:** rejected if `pool_balance == 0` (nothing left to recover) and, optionally,
   after a fixed `nShieldedRecoveryExitExpiryHeight` — so the path closes once the wind-down completes.
8. **Turnstile:** the pool debit `value` flows through `ShieldedPoolBalance::ApplyValueBalance`; net
   transparent supply still cannot exceed shielded-in (the existing firewall).

DisconnectBlock reverses the spent-commitment insertion, the `normal_nf` insertion, and the velocity entry
(reorg-safe, mirroring the existing nullifier/velocity undo). Block validation and mempool policy must
check same-block/same-mempool conflicts across both identifiers: `RECOVERY_EXIT(cm, normal_nf)` conflicts
with another recovery claim for `cm`, another recovery claim for `normal_nf`, and any normal shielded spend
whose collected nullifier is `normal_nf`.

## 4. Why this is DS-4-immune and inflation-safe

- **No ring → no key image → no DS-4.** The spent note is revealed and deduped on `cm` via a permanent
  spent-commitment set; one note can be claimed at most once. The whole DS-4 class (forge a second
  nullifier for a hidden note) does not exist here.
- **No cross-path double-spend.** The recovery claim also retires the note's canonical `V2_SEND` nullifier.
  A note spent through normal unshield cannot later recover, and a recovered note cannot later unshield.
- **No new shielded value.** Zero shielded outputs, pool-debit-only, turnstile-bounded → cannot inflate
  the pool or keep the shielded state machine alive. Monotone-decreasing invariant preserved.
- **Cannot exceed legitimate value.** `value` is bound to the revealed note and gated by pre-snapshot
  membership, so an attacker cannot claim more than a note that actually existed and that they own.

## 5. Implementation components

1. Consensus: `nShieldedRecoveryExitActivationHeight` + the validation predicate above in
   `validation.cpp`, called from the same sites as the sunset gate.
2. New persistent **spent-commitment set** in the shielded nullifier/commitment DB (ever-existed guard +
   reorg undo), plus atomic insertion/removal of the consensus-derived `normal_nf` through the existing
   nullifier set.
3. Frozen 125,000 commitment-root source for the membership check: use the hardcoded
   `nShieldedRecoveryExitFrozenRoot` when available, otherwise use the live tree root after the strict
   zero-output sunset rule has made the tree immutable. A later release may still hardcode the emitted
   DS-3 frozen-ceiling value for defense in depth.
4. Wire/bundle encoding for `V2_RECOVERY_EXIT` (revealed fields + ownership sig + membership proof) and
   serialization.
5. Prover / wallet builder for the claim (PQ-sign the binding, assemble the membership proof).
6. Tests: unit constraints, wire round trips, spent-set undo, mined-block connect path, package/mempool
   identifier reservation, production activation parameter checks, and sunset rejection of mixed
   unshield-plus-shielded-output transactions.
7. External review remains recommended for the consensus debit path, PQ-auth binding, and membership
   soundness, but is not available for this emergency activation.

## 6. Interaction with the sunset

At and after `125000`, permitted shielded operations are exactly:

- strict pure `V2_SEND` transparent unshield: `value_balance > fee` and zero shielded outputs; and
- `V2_RECOVERY_EXIT` transparent claim: revealed note, ownership signature, membership proof, zero
  shielded outputs, dual retirement of `cm` and `normal_nf`.

Everything else stays rejected. Both permitted operations only drain the frozen pool, both are
velocity-capped, and the pool remains strictly monotone-decreasing toward zero.
