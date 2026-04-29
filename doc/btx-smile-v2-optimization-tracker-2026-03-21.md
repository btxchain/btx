# BTX SMILE V2 Post-Launch Optimization Tracker

Date: 2026-03-21

Status: open follow-on workstream on top of the merged `main` launch surface.

Historical note:
- the account-registry activation, transaction-family transition, and
  future-proofed settlement slack referenced below are now merged on `main`
- branch names in this file are retained as implementation history and for
  follow-on optimization context, not as current deployment guidance
- use `doc/btx-shielded-production-status-2026-03-20.md` for the current live
  architecture and benchmark baseline

Current merged-main transaction-family state:
- wallet-built transparent-edge and mixed send families already run on the
  reset-chain `v2_send` / `DIRECT_SMILE` launch surface
- legacy MatRiCT proof code remains in-tree only as compatibility / tooling /
  adversarial coverage, not as the active wallet backend
- transaction-family report:
  [doc/btx-smile-v2-transaction-family-transition-2026-03-23.md](doc/btx-smile-v2-transaction-family-transition-2026-03-23.md)
- current measured wallet-path benchmark:
  - deposit `v2_send`: `19,172` bytes, `1,251` / `24 MB`, `13.90 TPS`
  - direct `1x2 v2_send`: `60,218` bytes, `398` / `24 MB`, `4.42 TPS`
  - mixed unshield `v2_send`: `44,330` bytes, `541` / `24 MB`, `6.01 TPS`

Baseline branch:
- `codex/smile-shared-ring-fix`
- PR `#108`

Current stacked follow-on branch for the next aggressive size-reduction wave:
- `codex/smile-v2-optimization-wave3`
- stable roadmap:
  [doc/btx-postlaunch-optimization-roadmap.md](doc/btx-postlaunch-optimization-roadmap.md)
- shared proof-redesign gate:
  - `build-btx/bin/test_btx --run_test=smile2_proof_redesign_framework_tests/*`
  - `build-btx/bin/gen_smile2_proof_redesign_report --profile=baseline --samples=1`

Merged-main architecture-design checkpoint for the next tx-size step:
- redesign spec:
  [doc/btx-smile-v2-shielded-account-registry-redesign-2026-03-22.md](doc/btx-smile-v2-shielded-account-registry-redesign-2026-03-22.md)
- current checkpoint:
  - Phase 0 / Phase 1 scaffold landed on PR `#113`
  - registry state now commits the full shielded account-leaf payload
    (`compact_public_key` + `compact_public_coin`) instead of only the leaf
    hash, so snapshot restore and full-node validation can rebuild
    `CompactPublicAccount` state from committed consensus data
  - direct-send spends and ingress consumed spends now carry lean
    account-registry spend witnesses on wire:
    `leaf_index + account_leaf_commitment + sibling_path`
  - the live direct-send SMILE CT relation binds the consumed registry leaf to
    the hidden spender via `z_leaf`, while full nodes recover the committed
    public-account payload locally from authenticated registry state
  - wallet-owned notes still persist `AccountLeafHint`, so scan / restore can
    reconstruct future consumed leaf commitments locally
  - family-specific value accounting remains split correctly between tx fee
    accounting and shielded pool-state accounting, and the registry snapshot
    path now rebuilds `m_shielded_smile_public_accounts` and
    `m_shielded_account_leaf_commitments` directly from the committed registry
    state
  - measured direct-send launch surface on this head:
    - `1x2`: `60,110` tx bytes, `51,099` proof bytes, `399` / `24 MB`
    - `2x2`: `70,272` tx bytes, `61,091` proof bytes, `341` / `24 MB`
    - `2x4`: `101,918` tx bytes, `84,111` proof bytes, `235` / `24 MB`
  - measured direct-send projection with minimal outputs preserved as a
    follow-on optimization:
    - `1x2`: `53,886` tx bytes, `445` / `24 MB`, `4.94 TPS`
    - `2x2`: `63,996` tx bytes, `375` / `24 MB`, `4.17 TPS`
    - `2x4`: `89,453` tx bytes, `268` / `24 MB`, `2.98 TPS`
  - current-head CT proof measurements now expose the added direct-send
    leaf-binding surface explicitly:
    - `ct_1x1 tuple_z_leaf_bytes = 230`
    - `ct_2x2 tuple_z_leaf_bytes = 456`
  - source-of-truth correction after rebasing on `main`:
    - PRs `#108`, `#110`, and `#111` already completed the reset-chain
      `DIRECT_SMILE` launch surface; older branch-local notes that still
      treated the Figure 17 public-coin rewrite as a remaining launch blocker
      were stale
  - corrected launch-surface checkpoint:
    - direct send and shared-ring `BATCH_SMILE` ingress are the live reset-
      chain proof surfaces
    - the redesign harness now measures the live ingress ceiling at
      `63` leaves / `8` spend inputs / `8` proof shards with one reserve
      output
    - the default-8 launch baseline therefore stops at the proven
      `8`-spend ceiling today, while larger shared rings remain supported on
      the same wire surface if policy is raised later
    - the earlier leaf-only minimal-output blocker is resolved for launch by
      committing the full leaf payload in registry state and using lean
      consumed-leaf witnesses on transaction wire

### Launch Readiness Report (2026-03-22)

Current readiness checkpoint:
- PR: `#113`
- scope: rebased `main` plus the account-registry redesign measurements and
  executable blocker checks recorded below

Status:
- `launch_ready = true`
- `base_direct_smile_launch_ready = true`
- `account_registry_activation_ready = true`

Verified in the current checkpoint:
- `cmake --build build-btx -j8 --target test_btx generate_smile2_proof_redesign_report`
- `test_btx --run_test=shielded_v2_proof_tests`
- `test_btx --run_test=smile2_proof_redesign_framework_tests`
- `test_btx --run_test=shielded_v2_send_tests`
- `test_btx --run_test=shielded_v2_ingress_tests`
- `test_btx --run_test=shielded_v2_egress_tests`
- `test_btx --run_test=shielded_v2_bundle_tests`
- `test_btx --run_test=shielded_account_registry_tests`
- `test_btx --run_test=shielded_wallet_chunk_discovery_tests`
- `test_btx --run_test='smile2_ct_tests/p4_g0_committed_public_key_slots_*'`
- `test_btx --run_test=validation_chainstatemanager_tests/chainstatemanager_reloads_version5_snapshot_account_registry_state`
- `test_btx --run_test=validation_chainstatemanager_tests/chainstatemanager_reloads_persisted_account_registry_state`
- `gen_smile2_proof_redesign_report --profile=fast --samples=1`
- `gen_smile2_proof_redesign_report --profile=baseline --samples=1`

Verified safe on this branch:
- direct-send `DIRECT_SMILE` now proof-binds the public consumed
  `account_leaf_commitment` to the hidden spender witness
- the rebased `main` launch surface remains the correct source of truth for
  reset-chain `DIRECT_SMILE`; this tracker no longer treats the Figure 17
  public-coin rewrite as an open launch blocker
- shared-ring `BATCH_SMILE` ingress is live on the reset-chain launch surface,
  and the corrected redesign baseline now measures the proven ceiling at
  `63` leaves / `8` spend inputs / `8` proof shards with one reserve output
- registry roots, snapshots, and light-client inclusion proofs are implemented
  and covered by dedicated tests
- registry state now commits the full shielded account-leaf payload, and
  snapshot restore rebuilds public-account and leaf-commitment indexes from
  that authenticated state without replay fallbacks
- consumed-leaf transaction witnesses are now lean on wire:
  - sample light-client proof: `13,554` bytes
  - sample spend witness: `106` bytes
  - stale spend witnesses are rejected after state transitions
- wallet scan / restore preserves `AccountLeafHint`, so local note recovery can
  reconstruct future consumed leaf commitments

Launch result:
- the account-registry activation surface is now launch ready on this branch
- the live proof relation is:
  `direct_send_smile_and_batch_smile_live_with_committed_registry_payload_recovery_and_lean_spend_witnesses`
- the remaining leaf-only minimal-output variant is optional follow-on
  optimization, not a launch blocker

Merged-main future-proofing checkpoint for later settlement scaling:
- TDD / implementation doc:
  [doc/btx-smile-v2-future-proofed-settlement-tdd-2026-03-23.md](doc/btx-smile-v2-future-proofed-settlement-tdd-2026-03-23.md)
- current checkpoint:
  - bridge batch statements now have a live `version = 5` aggregate-settlement
    surface, and bridge batch commitments now have a live `version = 3`
    aggregate-settlement surface when an external anchor is present
  - the committed aggregate object now carries:
    - `action_root`
    - `data_availability_root`
    - `recovery_or_exit_root`
    - `extension_flags`
    - `policy_commitment`
  - shared-ring ingress and egress builders populate that object
    deterministically from the existing launch statement:
    - `action_root = batch_root`
    - `data_availability_root = data_root`
    - `policy_commitment = proof_policy.descriptor_root` when committed
  - the live proof/header wire now carries an opaque `extension_digest`, and
    transaction header ids change when it changes
  - wallet RPC encode/decode surfaces now expose the aggregate commitment
    object, and external statement builders can override it while staying on
    the existing launch proof kinds and settlement-binding enums
  - structurally inconsistent aggregate commitments now reject if optional
    recovery/policy fields and flags disagree

### Future-Proofed Settlement Readiness Report (2026-03-23)

Status:
- `launch_ready = true`
- `future_proofed_settlement_ready = true`
- `multi_user_l1_settlement_active = false`

Verified on the current checkpoint:
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

Launch-safe conclusion:
- the current Smile-only launch semantics and measured throughput remain
  unchanged
- the bridge/proof consensus surface now already commits the opaque roots
  needed for a later high-aggregation settlement design
- a later upgrade can tighten semantics around `aggregate_commitment` and
  `extension_digest` without first adding a new proof-kind or
  settlement-binding enum to carry those bytes

Still intentionally out of scope on this branch:
- activating true multi-user settlement semantics on L1
- adding a succinct aggregate proof relation for many-user settlement batches
- enforcing data availability / exit / recovery logic for a future rollup path

Measured non-launch residuals:
- legacy `DIRECT_MATRICT` direct send is still unsafe under the redesign:
  - `shielded_v2_send_tests/matrict_direct_send_account_leaf_substitution_attack_can_be_reproven`
  - `shielded_v2_send_tests/matrict_direct_send_real_ring_member_substitution_attack_can_be_reproven`
- legacy native MatRiCT ingress is still unsafe under the redesign:
  - `shielded_v2_ingress_tests/matrict_ingress_account_leaf_substitution_survives_without_reproof`
- receipt-backed ingress still does not replace the hidden-spend proof relation:
  - `shielded_v2_ingress_tests/receipt_backed_ingress_accepts_garbage_ring_members_and_wrong_tree`
- shared-ring ingress currently rejects once the schedule crosses into the
  `16th` spend input:
  - `gen_shielded_ingress_proof_runtime_report --backend=smile --samples=1 --reserve-outputs=1 --leaf-count=120`
    returns `bad-shielded-v2-ingress-smile-proof`

Least-bad next move:
- treat PR `#108` / `#110` / `#111` plus PR `#113` as the completed hard-fork
  launch context for `DIRECT_SMILE` + `BATCH_SMILE` with account-registry
  recovery from committed state
- keep every registry-unsafe legacy direct-send / ingress backend off the
  reset-chain production surface
- treat any future leaf-only minimal-output transport as post-launch
  optimization work, not a launch-readiness dependency

Measured checkpoint on this head:
- direct send live bytes:
  - `1x2`: `60,110` tx bytes / `51,099` proof bytes / `399` tx per `24 MB`
  - `2x2`: `70,272` tx bytes / `61,091` proof bytes / `341` tx per `24 MB`
  - `2x4`: `101,918` tx bytes / `84,111` proof bytes / `235` tx per `24 MB`
- projected minimal-output follow-on if further output compression lands:
  - `1x2`: `53,886`
  - `2x2`: `63,996`
  - `2x4`: `89,453`

Previous stacked wave:
- `codex/smile-v2-optimization-wave2`
- historical work now summarized under the stable roadmap:
  [doc/btx-postlaunch-optimization-roadmap.md](doc/btx-postlaunch-optimization-roadmap.md)

## Goal

Optimize the reset-chain SMILE v2 implementation for smaller proof payloads,
smaller serialized direct shielded transactions, and higher direct shielded TPS
without weakening:

- cryptographic soundness
- anonymity set size
- post-quantum security assumptions
- the launch-surface consensus model shipped in PR `#108`

Because this is a restart-from-genesis hard fork, these optimizations may use
clean wire-format and proof-object replacements. No backward compatibility with
earlier prototype or launch-surface encodings is required.

## Current Measured Baseline

From the production-ready launch surface:

| Shape | Serialized bytes | Proof bytes | Mean build | Mean verify | 24 MB fit | TPS @ 90 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `1x2` | `123,450` | `93,792` | `1.25 s` | `195.86 ms` | `194` | `2.16` |
| `2x2` | `149,275` | `119,488` | `2.92 s` | `345.55 ms` | `160` | `1.78` |
| `2x4` | `201,751` | `142,644` | `1.48 s` | `403.00 ms` | `118` | `1.31` |

The direct-send launch surface is currently serialization-bound, not
verification-budget-bound.

## Landed Optimization Checkpoints

### Checkpoint 1: remove duplicate output-coin witness serialization

Status: landed on `codex/smile-v2-optimization`

Change:
- `V2SendWitness` no longer serializes `smile_output_coins`
- direct-send proof binding and verification now derive output coins from the
  canonical `payload.outputs[i].smile_account->public_coin`
- the duplicated witness copy of the same public coin object is deleted from
  the reset-chain wire format

Why it is safe:
- no anonymity-set reduction
- no change to lattice parameters or challenge distributions
- no removal of tuple / public-coin / opening bindings
- output coins remain consensus-visible and authenticated through the canonical
  payload output object rather than a duplicated witness object

Measured result on the optimized branch:

| Shape | Old tx bytes | New tx bytes | Old proof bytes | New proof bytes | Old TPS | New TPS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `1x2` | `123,450` | `101,941` | `93,792` | `72,283` | `2.16` | `2.61` |
| `2x2` | `149,275` | `127,766` | `119,488` | `97,979` | `1.78` | `2.08` |
| `2x4` | `201,751` | `158,734` | `142,644` | `99,627` | `1.31` | `1.68` |

This checkpoint alone reduced direct-send serialized size by about `14%` to
`21%`, reduced proof payload bytes by about `18%` to `30%`, and improved direct
serialized-cap TPS by about `17%` to `28%`.

### Checkpoint 2: fixed-layout CT codec and removal of serialized `key_w0`

Status: landed on `codex/smile-v2-optimization`

Change:
- `SmileCTProof` no longer serializes `key_w0_vals`
- the prover still computes the raw `combined_w0` witness surface locally, but
  the wire format now binds the committed `W0` rows through the canonical
  `aux_commitment.t_msg` slots instead of shipping a second explicit copy
- `DeserializeCTProof()` is now reset-chain fixed-layout and keyed by
  `(num_inputs, num_outputs)` rather than self-describing count fields for the
  launch-surface CT object
- redundant serialized count headers for fixed launch-surface families were
  removed from the reset-chain wire format
- the live verifier/parser path now rejects any non-launch-surface recursive CT
  shape instead of carrying larger latent layouts in the reset-chain codec

Why it is safe:
- no anonymity-set reduction
- no weakened challenge distributions or smaller lattice parameters
- no dropped tuple / public-coin / opening bindings
- no loss of verifier binding: the removed `key_w0` rows are derivable from the
  committed CT state the verifier already authenticates
- the reset-chain format is smaller because it removes duplicated and
  self-describing surfaces that are unnecessary on a hard-fork genesis launch

Measured result on the optimized branch:

| Shape | Checkpoint 1 tx bytes | Checkpoint 2 tx bytes | Checkpoint 1 proof bytes | Checkpoint 2 proof bytes | Checkpoint 1 TPS | Checkpoint 2 TPS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `1x2` | `101,941` | `98,785` | `72,283` | `69,127` | `2.61` | `2.69` |
| `2x2` | `127,766` | `122,562` | `97,979` | `92,775` | `2.08` | `2.17` |
| `2x4` | `158,734` | `153,530` | `99,627` | `94,423` | `1.68` | `1.73` |

Net result versus the original PR `#108` launch baseline:

| Shape | Baseline tx bytes | Checkpoint 2 tx bytes | Baseline proof bytes | Checkpoint 2 proof bytes | Baseline TPS | Checkpoint 2 TPS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `1x2` | `123,450` | `98,785` | `93,792` | `69,127` | `2.16` | `2.69` |
| `2x2` | `149,275` | `122,562` | `119,488` | `92,775` | `1.78` | `2.17` |
| `2x4` | `201,751` | `153,530` | `142,644` | `94,423` | `1.31` | `1.73` |

This brings the cumulative improvement versus the PR `#108` launch baseline to:

- serialized direct-send size down about `20%` to `24%`
- proof payload bytes down about `26%` to `34%`
- direct serialized-cap TPS up about `22%` to `32%`

Verification completed on this checkpoint:

- focused `test_btx` batch:
  - `smile2_ct_tests/*`
  - `smile2_adversarial_tests/*`
  - `smile2_deep_adversarial_tests/*`
  - `smile2_extreme_adversarial_tests/*`
  - `smile2_comprehensive_gap_tests/*`
  - `shielded_v2_proof_tests/*`
  - `shielded_v2_send_tests/*`
- functional:
  - `wallet_smile_v2_full_lifecycle.py --descriptors`
  - `wallet_bridge_happy_path.py --descriptors`
- benchmark:
  - `gen_shielded_v2_send_runtime_report --warmup=1 --samples=3 --scenarios=1x2,2x2,2x4`

### Checkpoint 3: canonical output wire shape and derivable CT seed removal

Status: landed on `codex/smile-v2-optimization`

Change:
- `OutputDescription` now serializes the canonical SMILE account object exactly
  once and derives `note_commitment` from `smile_account` during
  deserialization instead of shipping both forms on the reset-chain wire
- `OutputDescription::IsValid()` now requires `smile_account` on the reset-chain
  hard-fork launch surface instead of treating it as optional
- `SmileCTProof` now omits derivable Fiat-Shamir seeds `fs_seed`, `seed_c0`,
  and `seed_z`; the verifier recomputes them from the public statement and
  proof body and only keeps `seed_c` on-wire
- the CT codec now uses exact centered fixed-layout serialization for bounded
  launch-surface proof families that still need to stay explicit on the wire
- direct MatRiCT failover fixtures were updated to prove against the same
  canonical output note-commitment surface the live `v2_send` path now uses

Why it is safe:
- no anonymity-set reduction
- no weakened challenge distributions or lattice parameters
- no dropped tuple / public-coin / opening bindings
- outputs are more canonical, not less: the chain-visible note commitment is
  derived from the canonical SMILE account object instead of being duplicated
  beside it
- verifier soundness is preserved because the removed seeds are transcript
  derivable and are still checked when present in older in-memory fixtures

Measured result on the optimized branch:

| Shape | Checkpoint 2 tx bytes | Checkpoint 3 tx bytes | Checkpoint 2 proof bytes | Checkpoint 3 proof bytes | Checkpoint 2 TPS | Checkpoint 3 TPS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `1x2` | `98,785` | `98,688` | `69,127` | `69,096` | `2.69` | `2.70` |
| `2x2` | `122,562` | `122,480` | `92,775` | `92,759` | `2.17` | `2.17` |
| `2x4` | `153,530` | `153,382` | `94,423` | `94,407` | `1.73` | `1.73` |

Net result versus the original PR `#108` launch baseline:

| Shape | Baseline tx bytes | Checkpoint 3 tx bytes | Baseline proof bytes | Checkpoint 3 proof bytes | Baseline TPS | Checkpoint 3 TPS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `1x2` | `123,450` | `98,688` | `93,792` | `69,096` | `2.16` | `2.70` |
| `2x2` | `149,275` | `122,480` | `119,488` | `92,759` | `1.78` | `2.17` |
| `2x4` | `201,751` | `153,382` | `142,644` | `94,407` | `1.31` | `1.73` |

This checkpoint is intentionally smaller than checkpoint 2. The exact-centered
codec pass by itself was not a large win on several near-uniform CT surfaces,
but in combination with the structural wire cleanup above it still produced a
modest net improvement while making the reset-chain output format cleaner and
more canonical.

Verification completed on this checkpoint:

- focused `test_btx` batch:
  - `shielded_tx_check_tests/*`
  - `shielded_v2_bundle_tests/*`
  - `shielded_v2_proof_tests/*`
  - `shielded_v2_send_tests/*`
  - `shielded_v2_wire_tests/*`
- selected SMILE proof/regression coverage:
  - `smile2_ct_tests/p4_g1_balance_proof`
  - `smile2_ct_tests/p4_g5_amortized_membership`
  - `smile2_audit_tests/a14_serialization_roundtrip`
  - `smile2_audit_tests/b5_proof_size_scaling`
  - `smile2_adversarial_tests/c3_tampered_w0_vals_rejected`
  - `smile2_adversarial_tests/c5_malformed_output_coin_shape_rejected`
  - `smile2_deep_adversarial_tests/d2_w0_vals_cross_proof_substitution`
- functional:
  - `python3 test/functional/test_runner.py wallet_smile_v2_full_lifecycle.py wallet_bridge_happy_path.py --jobs=1 --descriptors`
- benchmark:
  - `build-btx/bin/gen_shielded_v2_send_runtime_report --warmup=1 --samples=3 --scenarios=1x2,2x2,2x4`

## Approved Optimization Workstreams

Only the following workstreams are in scope for this branch family:

1. Replace full-width polynomial serialization with compressed encodings where
   the proof system already permits it.
2. Stop serializing reconstructable CT row tensors when the verifier can derive
   them from transcript seeds, commitments, and compact tuple-opening data.
3. Make the tuple / public-account / public-coin object fully canonical and
   remove duplicated serialized representations that can be derived from it.
4. Repack the shielded output layer so ciphertext and public-account framing is
   tighter on the reset-chain wire format.

The branch should pursue these aggressively where the reset-from-genesis hard
fork makes them possible:

- remove output fields that are derivable from the canonical SMILE public
  account object instead of continuing to serialize both forms;
- replace generic proof-object serialization with object-class-specific codecs
  for every bounded launch-surface polynomial family;
- make verifier-reconstructable CT mask / row families transcript-derived
  rather than shipping explicit full tensors on the wire;
- treat public-account framing and ciphertext/header framing as part of the
  same size budget as the proof instead of optimizing only the proof blob.

The following are explicitly out of scope:

- lowering anonymity-set size
- weakening challenge distributions or lattice parameters
- loosening tuple / opening / public-coin bindings
- changing consensus block limits as a throughput shortcut
- relying on batching as a substitute for direct-send efficiency

## Expected Outcome

If workstreams `1-4` land cleanly, the expected result is:

- proof payload reduction of about `40%` to `55%`
- full direct tx size reduction of about `35%` to `45%`
- direct shielded TPS improvement of about `1.5x` to `1.9x`

That implies an approximate target range of:

| Shape | Target tx bytes | Target TPS |
| --- | ---: | ---: |
| `1x2` | `65k` to `82k` | `3.2` to `4.1` |
| `2x2` | `80k` to `100k` | `2.7` to `3.3` |
| `2x4` | `110k` to `135k` | `2.0` to `2.4` |

These are branch planning targets, not yet verified measurements.

## Primary Code Areas

- `src/shielded/smile2/serialize.cpp`
- `src/shielded/smile2/serialize.h`
- `src/shielded/smile2/ct_proof.cpp`
- `src/shielded/smile2/ct_proof.h`
- `src/shielded/smile2/public_account.h`
- `src/shielded/smile2/public_account.cpp`
- `src/shielded/v2_bundle.h`
- `src/shielded/v2_send.cpp`
- `src/shielded/v2_types.h`

## Execution Order

1. Compression pass on proof polynomials and compact public-account fields.
2. CT proof-object rewrite to eliminate serialized reconstructable row tensors.
3. Canonical public-account / public-coin serialization cleanup.
4. Shielded output envelope repack and ciphertext framing cleanup.
5. Full benchmark and regression rerun on the new wire format.

Current next target after checkpoint 3:
- focus on the remaining bigger wins, not more blanket bitpacking:
  - eliminate additional reconstructable CT proof surfaces from the wire format
  - repack `OutputDescription` / encrypted-note framing to cut non-proof bytes
  - use selective object-specific codecs only where coefficient distributions
    are narrow enough to pay for their headers

## Additional Hard-Fork Efficiency Targets

These are acceptable only because backward compatibility is not required:

- make `OutputDescription` serialize the canonical SMILE account object once
  and derive any duplicated chain-visible hash/commitment fields from it;
- replace the legacy encrypted-note payload framing with a reset-chain format
  that minimizes per-output headers and avoids transitional duplication;
- specialize proof serialization by object type rather than using the same
  full-width polynomial encoding across bounded and unbounded surfaces;
- push more of the CT first-round and auxiliary row material behind
  transcript-bound deterministic reconstruction when the verifier can recover
  it exactly from already-committed state.

## Success Criteria

- launch-surface direct SMILE remains the default path
- unit, adversarial, functional, and benchmark suites stay green
- proof bytes and tx bytes both materially decline versus the PR `#108`
  baseline
- README and production-status docs are updated with the new measured numbers
