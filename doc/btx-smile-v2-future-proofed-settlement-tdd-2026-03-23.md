# BTX SMILE V2 Future-Proofed Settlement TDD

Date: 2026-03-23

Status:
- merged on `main`
- originally landed on stacked PR `#114`
- ported and merged onto `main` via PR `#116`

Purpose:
- preserve the current Smile-only reset-chain launch surface
- add consensus-visible upgrade slack now so a later multi-user settlement path
  can be added without introducing new proof or binding enums that old launch
  nodes would reject at parse time
- make the bridge settlement surface hash and relay the aggregate roots needed
  for a later scaling path

## Problem Statement

The current launch-ready mainline is production safe, but the bridge ingress
surface still commits one user authorization per `BridgeBatchLeaf`. A later
multi-user settlement object would need new authenticated roots and a proof-side
binding surface. If those bytes are not part of the launch consensus format,
adding them later is likely a hard fork instead of a tightening soft fork.

## Design Goal

Ship a future-proofed launch surface now by extending the live consensus data
with opaque, versioned, authenticated aggregate-settlement commitments while
keeping the current direct-send / ingress / egress / rebalance semantics
unchanged.

## Required Implementation

1. Bridge-side aggregate commitment
   - Add a versioned aggregate settlement commitment object to the live bridge
     statement / commitment surface.
   - The object must include:
     - `action_root`
     - `data_availability_root`
     - `recovery_or_exit_root`
     - `extension_flags`
     - `policy_commitment`
   - Current launch flows must be able to populate it deterministically from
     existing batch data without changing user-visible semantics.

2. Proof/header extension binding
   - Add a generic opaque `extension_digest` to the live shielded proof/header
     surface.
   - It must be hashed into the transaction header through the proof envelope.
   - Current launch validators must accept both `null` and non-null digests so
     a later soft fork can tighten the meaning without requiring a new enum.

3. Bridge proof claim compatibility
   - Ensure the bridge proof claim path can bind the future-proofed aggregate
     settlement surface without inventing a new claim enum.
   - The minimal requirement is that the statement hash and claim hashing change
     when aggregate commitment contents change.

4. Live launch compatibility
   - Current launch-safe `DIRECT_SMILE`, `BATCH_SMILE` ingress, egress, and
     rebalance flows must remain valid on the new wire.
   - No current launch transaction family may require a non-zero future-proof
     field.

5. Documentation and tracker updates
   - Record the exact upgrade slack added.
   - Record what later work would still be needed for true multi-user
     settlement:
     - aggregate action semantics
     - succinct proof relation
     - data availability / recovery / exit enforcement

## Test-Driven Acceptance Criteria

1. Bridge serialization / hashing
   - `BridgeBatchStatement` roundtrips with the new aggregate commitment.
   - `BridgeBatchCommitment` roundtrips with the new aggregate commitment.
   - Mutating any aggregate commitment field changes the statement hash and
     commitment hash.

2. Validation invariants
   - Zero/default future-proof fields remain valid for the current launch path.
   - Structurally valid non-zero future-proof fields also remain valid on the
     current launch path.
   - Invalid aggregate commitment shapes reject.

3. Proof/header binding
   - `ProofEnvelope` roundtrips with `extension_digest`.
   - Transaction header ids change when `extension_digest` changes.
   - Current proof-statement validation still passes with both null and non-null
     `extension_digest`.

4. Launch regression coverage
   - `shielded_v2_send_tests`
   - `shielded_v2_ingress_tests`
   - `shielded_v2_egress_tests`
   - `shielded_v2_bundle_tests`
   - `shielded_v2_proof_tests`
   - `shielded_bridge_tests`
   - `smile2_proof_redesign_framework_tests`

5. Reporting
   - The redesign tracker and optimization tracker must explicitly say:
     - launch remains production ready
     - future-proofed bridge/proof upgrade slack is live
     - true multi-user settlement is not activated yet

## Non-Goals For This Branch

- activating true multi-user settlement semantics on L1
- adding a new succinct aggregate proof system
- solving data availability or user exit logic for a future rollup path
- changing the current measured launch throughput numbers in a material way

## Implementation Result

Landed on `main`:

- `BridgeBatchStatement version = 5` now serializes and hashes a live
  `aggregate_commitment`
- `BridgeBatchCommitment version = 3` now serializes and hashes a live
  `aggregate_commitment` when an external anchor is present
- the aggregate commitment object is versioned and carries:
  - `action_root`
  - `data_availability_root`
  - `recovery_or_exit_root`
  - `extension_flags`
  - `policy_commitment`
- current shared-ring ingress / egress builders populate a deterministic
  default aggregate commitment from the existing launch statement
- the proof/header surface now carries opaque `extension_digest`, and
  transaction header ids already bind it
- wallet RPC encode/decode paths now expose aggregate commitments, and external
  statement builders can override them without changing proof kinds or
  settlement-binding enums
- aggregate commitment validation now rejects inconsistent optional
  field/flag combinations

## Verification

Verified on the merged-main implementation:

- `cmake --build build-btx -j8 --target test_btx generate_smile2_proof_redesign_report`
- `test_btx --run_test=shielded_bridge_tests`
- `test_btx --run_test=shielded_v2_wire_tests`
- `test_btx --run_test=shielded_v2_proof_tests`
- `test_btx --run_test=shielded_v2_ingress_tests`
- `test_btx --run_test=shielded_v2_egress_tests`
- `test_btx --run_test=shielded_v2_bundle_tests`
- `test_btx --run_test=smile2_proof_redesign_framework_tests`
- `test_btx --run_test=bridge_wallet_tests`
- `gen_smile2_proof_redesign_report --profile=fast --samples=1`
- `gen_smile2_proof_redesign_report --profile=baseline --samples=1`

## Launch Conclusion

`main` is launch-ready for the current Smile-only reset-chain surface and now
already carries this future-proofed bridge/proof upgrade slack.

What is ready now:

- current launch transaction families and proofs stay valid
- aggregate settlement roots are already consensus-visible and authenticated
- the proof/header surface already has a generic opaque binding slot

What remains intentionally later work:

- define true multi-user action semantics under `action_root`
- add a succinct many-user settlement proof relation
- define and enforce DA / recovery / exit rules for that later settlement path
