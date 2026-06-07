# BTX C-002 Internal Lattice Review

Date: 2026-06-07
Branch: `audit/v2-rebalance-pool-credit-probe`
Scope: post-`123000` SMILE2 anonset-bound spend verification and post-`125000` transparent
exit-only containment.

## Conclusion

The reviewed code path closes the C-002/F3 decoupled-serial/nullifier class for live
post-`123000` anonset-bound SMILE2 spends. The verifier requires C-002 wire v3 at and after
`SmileCTProof::C002_ACTIVATION_HEIGHT` (`123000`) and enforces the additional v3 relations
needed to bind the revealed serial/nullifier to the same secret key opened by the proof.

This is an internal cryptographic code review, not an independent external cryptographer
sign-off. It should not be represented as external assurance.

## Reviewed Code Path

Primary files reviewed:

- `src/shielded/smile2/ct_proof.h`
- `src/shielded/smile2/ct_proof.cpp`
- `src/shielded/smile2/serialize.cpp`
- `src/shielded/smile2/verify_dispatch.cpp`
- `src/shielded/v2_send.cpp`
- `src/shielded/v2_ingress.cpp`
- `src/shielded/v2_proof.cpp`
- `src/shielded/validation.cpp`
- `src/test/smile2_integration_tests.cpp`
- `src/test/smile2_extreme_adversarial_tests.cpp`

## Security Model Cross-Check

The design requirement matches the core shielded/ring-signature pattern used in other privacy
systems: each spend must reveal one public, consensus-deduplicated spend tag, and the proof must
force that tag to be the unique tag for the hidden spent note/key.

Comparative references:

- Zcash Orchard nullifier rationale: nullifiers must deterministically depend only on note data
  committed by the note commitment so consensus can reject a second spend without learning the
  note being spent. See the Zcash Orchard Book, [Nullifiers](https://zcash.github.io/orchard/design/nullifiers.html).
- Zcash protocol specification: Sapling/Orchard nullifiers are derived from note/spend-key
  material and are tracked publicly by consensus. See the [Zcash protocol specification](https://qed-it.github.io/zips/protocol/protocol.pdf).
- Monero key images: a key image is the public linkability tag used to detect double spends
  while preserving signer ambiguity. See Monero Docs,
  [Private Key Image](https://docs.getmonero.org/cryptography/asymmetric/key-image/).
- Lattice Fiat-Shamir-with-aborts background: transcript binding and challenge derivation must
  cover all values whose relation is being proved. Dilithium is a useful audited reference
  family for this pattern; see the [CRYSTALS-Dilithium specification](https://pq-crystals.org/dilithium/data/dilithium-specification.pdf).

BTX C-002 follows the same high-level invariant in the SMILE2 setting: the revealed serial must
be forced by the proof to come from the same witness key as the hidden ring member, not from an
attacker-chosen value in a separate namespace.

## Findings

1. `ValidateSmile2Proof` gates anonset-bound proofs by validation height. At and after
   `123000`, v3 (`WIRE_VERSION_C002_HARDENED`) is mandatory. A post-`123000` v2 proof is
   rejected as `bad-smile2-proof-wire-version`.

2. The prover emits v3 only when anonset context binding is active and the validation height is
   at or above `123000`. This preserves historical v2 compatibility below the boundary and
   avoids a retroactive chain rewrite.

3. v3 serial-to-key binding is explicit. The prover computes `w_sn[inp] = <b_sn, y0_inp>`.
   The verifier checks:

```text
<b_sn, z0_inp> == w_sn[inp] + c0 * serial_number[inp]
```

   Since `z0 = y0 + c0 * witness_secret`, this pins the revealed serial/nullifier to the same
   opened secret used by the proof. A forged serial that is not tied to the hidden witness key
   fails this relation.

4. `w_sn` is Fiat-Shamir-bound before `c0` on both prover and verifier paths. This prevents a
   prover from adapting `w_sn` after seeing the challenge.

5. v3 carries `seed_z` on wire and makes the step-12 binding mandatory. A missing, zeroed, or
   mismatched `seed_z` fails verification rather than silently downgrading to legacy behavior.

6. v3 carries and verifies the balance/range auxiliary values (`balance_w`, `balance_carry`).
   The verifier checks public-fee-adjusted value conservation and the carry polynomial
   constraints. This is separate from serial binding but important for inflation resistance.

7. Consensus callers pass the real validation height through `VerifySmile2CTFromBytes` into
   `ValidateSmile2Proof`. The reviewed V2_SEND and ingress paths reach the same verifier gate
   before acceptance/state mutation.

8. Post-`125000`, `RejectShieldedSunsetViolation` keeps normal legacy holders able to unshield
   through transparent V2_SEND exits while rejecting shielded-to-shielded transfers, new shielded
   credits, lifecycle/rebalance lanes, and recovery reshielding. That reduces the remaining
   blast radius to legacy transparent exits from the frozen pool.

## Test Evidence

Focused tests run on this branch:

- `smile2_integration_tests/c002_activation_gate_v2_v3`
- `smile2_integration_tests/c002_max_shape_zsize_exceeds_legacy_caps_and_roundtrips`
- `smile2_integration_tests/c002_v3_context_mismatch_rejects`
- `smile2_extreme_adversarial_tests/f1_forged_serial_number`
- `smile2_extreme_adversarial_tests/f2_forged_serial_with_recomputed_seeds`
- `smile2_extreme_adversarial_tests/f3_same_key_serial_determinism`
- `smile2_extreme_adversarial_tests/f4_different_key_serial_uniqueness`
- `smile2_extreme_adversarial_tests/f5_null_serial_number_rejection`

All focused C-002 tests passed locally.

## Residual Risk

- This review does not prove the underlying SMILE2 lattice relation in a formal model.
- This review does not replace an independent third-party cryptographer review.
- Historical pre-`123000` proofs are not retroactively revalidated under v3.
- Any future activation of dormant recovery paths must preserve the same one-spend-tag invariant
  or atomically retire both the revealed commitment and the canonical normal-path nullifier.

Given the height-`125000` shielded sunset, the remaining C-002 risk is constrained to legacy
transparent exits from the frozen shielded pool. It is not a path for new shielded balances or
post-sunset shielded-to-shielded transfers.
