# BTX v0.31 — Shielded (SMILE2) C-002 / R5 migration guide

This release hard-forks the shielded confidential-transaction layer to close a
value-conservation / inflation hole (C-002) and add a real amount range proof
(R5). It activates at **block height 123,000**. This guide explains what changes,
why **no user action is required**, and that **no honest funds are lost or stuck**.

## TL;DR for users
- **Do nothing.** Your wallet handles everything automatically.
- **Your existing shielded notes are safe and remain spendable.** There is NO
  note migration, NO re-shielding, NO moving funds. Note commitments on-chain are
  untouched.
- After height 123,000, when you spend any shielded note (old or new), your wallet
  automatically builds the new hardened (v3) spend proof from data it already has
  (amount, opening, spend key). You won't notice the difference.
- Just upgrade all your nodes/wallets to v0.31 before height 123,000.

## What actually changes
C-002 is a **spend-proof upgrade, not a note migration**. A shielded note is a
commitment on-chain; spending it requires a zero-knowledge proof. v0.31 changes
the *proof format* required at spend time:

- **Before height 123,000:** shielded spends use the legacy proof format (v2),
  wire-compatible with v0.30. v0.31 nodes accept and produce v2 in this window.
- **At/after height 123,000:** shielded spends MUST use the hardened format (v3),
  which carries the value-conservation relation, the amount **range proof**, the
  nullifier↔key binding, and a mandatory transcript binding. v2 is rejected.

The switch is automatic and height-driven on both sides:
- **Wallet/prover** emits v2 before the height and v3 at/after it
  (`CreateSmileProof → TryProveCT`, threaded with the target block height).
- **Verifier** (`ValidateSmile2Proof`) requires the matching version for the block
  height, on every spend path (direct send, ingress batch, verifier-set).

`SmileCTProof::C002_ACTIVATION_HEIGHT = 123000` is the single source of truth.

The same activation height co-activates the rest of the v0.31 post-quantum
hardening, all keyed on this one constant: rejection of legacy secp256k1
ECDSA/Schnorr signatures at consensus, the FIPS-205 SLH-DSA signature scheme
(script-verify flags and the bridge attestor verification), and the self-serve
shielded→transparent (z→t) unshield. There is one flag day for the whole bundle.

## Fund-safety guarantees (no lost/stuck funds)
- **Every honest legacy note is spendable under v3.** Honest amounts are canonical
  and `≤ MAX_MONEY (2.1e15) < 4^26`, which always satisfies the R5 range proof. The
  wallet re-proves from the note's known amount/opening/key — no migration needed.
- **The only notes that become unspendable** are non-canonical / out-of-range ones,
  which can ONLY be produced by exploiting the pre-fix hole (value minted from
  nothing). Trapping these is intended — it prevents laundering forged value out.
  No honest wallet ever creates such a note.
- If a note somehow cannot be upgraded, the wallet surfaces a clear error — it
  never silently drops or loses funds.

## Operator / node-runner checklist
1. **Upgrade all nodes to v0.31 before height 123,000.** Because the v3 proof
   format is not parseable by v0.30, the network must be fully upgraded before the
   cutover (standard for a mandatory hard fork). During the pre-activation window,
   v0.31 nodes remain wire-compatible with each other and with any remaining v0.30
   nodes (both speak v2).
2. No reindex, no wallet rescan, no datadir migration is required.
3. After height 123,000, confirm shielded sends succeed (they will emit v3).

## Developer notes
- Dual-format is implemented across prover / verifier / serializer / decoder,
  keyed on the wire version (`is_v3`); see `src/shielded/smile2/ct_proof.cpp`,
  `serialize.cpp`, `verify_dispatch.cpp`.
- The verifier gate is at the single chokepoint `ValidateSmile2Proof`, covering
  V2_SEND, V2_INGRESS_BATCH, and the verifier-set path.
- Crypto soundness is covered by the offline forge harness (`rtx1_f3_forge_tests`):
  v3 honest accepts, all v3 forges (balance/Γ/coin-binding/range) reject, and the
  v2 path builds/verifies/round-trips (`rtx1_12`).
- See `src/shielded/smile2/C002_ACTIVATION_SAFETY.md` for the full activation +
  fund-safety analysis and the remaining regtest test-vector checklist.
