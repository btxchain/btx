# BTX SMILE V2 Shielded Account Registry Redesign

Date: 2026-03-22

Historical note:
- this document records the implementation/design history for the
  account-registry activation that is now merged on `main`
- use `doc/btx-shielded-production-status-2026-03-20.md` for the live current
  benchmark/readiness summary
- branch references below are preserved as implementation history
- the direct-send and ingress size tables below capture the branch checkpoint
  that led into launch; current merged-main default-8 figures are now
  `60,218` / `70,272` / `101,918` direct-send bytes and a `63`-leaf /
  `8`-spend ingress ceiling at `312,364` bytes

Status: production-ready hard-fork checkpoint on PR `#113`; Phase 0/1 state and
registry wiring are live on `codex/smile-v2-account-registry-design`, the
direct-send / ingress consumed-leaf binding work is landed, registry state now
commits the full shielded account-leaf payload, and the transaction wire uses
lean consumed-leaf witnesses while full nodes recover `CompactPublicAccount`
state from authenticated consensus data. The rebased `main` launch surface
already ships reset-chain `DIRECT_SMILE`; this branch completes the account-
registry activation surface for launch.

Base branch:
- `codex/smile-v2-optimization-wave3`
- PR `#112`

Working branch for this design document:
- `codex/smile-v2-account-registry-design`

## Purpose

Define the next-generation shielded transaction architecture required to cut
serialized SMILE transaction size by another 50%-class margin without
weakening:

- post-quantum security
- cryptographic soundness
- shielded balance privacy
- nullifier-based double-spend prevention
- direct shielded transfers as the default user path
- bridge ingress, egress, and rebalance as first-class settlement paths

This redesign assumes a restart-from-genesis hard fork. No backward
compatibility with the inline `smile_account` launch format is required.

## Executive Summary

The current SMILE launch surface is no longer bottlenecked by proof-local
duplication. It is bottlenecked by the fact that every shielded output carries
an inline `CompactPublicAccount`, and the dominant component of that object is
the exact public coin transport `public_coin.t0`.

Measured current-head direct-send envelope footprint:

- canonical direct-send output: `3,784` bytes
- exact `CompactPublicAccount` transport floor: `14,537` bytes
- exact relocation delta versus current output: `10,753` bytes
- compact public account exact bytes: `13,312`
- compact public key exact bytes: `2,560`
- encrypted payload: `1,160`

Measured direct-send baseline on wave 3:

| Shape | Serialized bytes | Proof bytes | 24 MB fit | TPS @ 90 s |
| --- | ---: | ---: | ---: | ---: |
| `1x2` | `58,418` | `29,239` | `410` | `4.56` |
| `2x2` | `68,077` | `38,866` | `352` | `3.91` |
| `2x4` | `98,461` | `40,312` | `243` | `2.70` |

Wave-3 measurement also shows that exact re-encoding of `public_key` or `t0`
is exhausted as a useful path:

- canonical `public_key`: `2,560 -> 2,567` bytes under adaptive exact codec
- canonical `t0`: `10,240 -> 10,247` bytes under adaptive exact codec

The conclusion is now explicit:

- further 50%-class tx-size reduction will not come from serializer tuning
- it requires deleting most of the inline `CompactPublicAccount` transport
- future spends must prove against a committed account leaf / registry root,
  not against raw per-output exact `t0` bytes carried forever on chain

The recommended design is therefore:

1. replace inline shielded public accounts with a minimal output object
2. commit new outputs into a consensus-committed shielded account registry
3. redesign SMILE spend proofs to prove membership/opening against account-leaf
   commitments and registry roots
4. bind bridge settlement paths to the same registry root model

## Phase 0/1 + Compact Direct-Send Checkpoint

This branch now contains a concrete Phase 0 / Phase 1 scaffold, not just a
design memo.

Landed code on `codex/smile-v2-account-registry-design`:

- `src/shielded/account_registry.{h,cpp}` now defines:
  - domain-separated account-leaf commitments
  - family-aware minimal output records
  - append-only shielded account registry state
  - registry proofs, snapshot / restore helpers, and block-level shielded state
    commitment helpers
- `src/test/shielded_account_registry_tests.cpp` now covers:
  - direct / ingress / egress / rebalance leaf determinism and domain
    separation
  - minimal-output roundtrip and tamper rejection
  - registry double-spend rejection, stale-root rejection, snapshot roundtrip,
    and light-client inclusion-proof validation
- `src/test/smile2_proof_redesign_harness.cpp` now measures:
  - vNext account-leaf output footprints for direct send, ingress, egress, and
    rebalance
  - direct-send serialized-size projections against the wave-3 baseline
  - registry update / tamper / snapshot / light-client surfaces
  - explicit migration blockers in the live wire format
- `src/shielded/v2_bundle.{h,cpp}`, `src/shielded/v2_send.cpp`, and
  `src/shielded/v2_ingress.cpp` now expose consumed account-leaf commitments on
  the live direct-send and ingress spend surfaces:
  - direct sends serialize `SpendDescription.account_leaf_commitment`
  - ingress batches serialize `ConsumedAccountLeafSpend` with both nullifier
    and account-leaf commitment
- `src/shielded/smile2/public_account.{h,cpp}`,
  `src/shielded/v2_bundle.{h,cpp}`, `src/shielded/v2_proof.{h,cpp}`, and
  `src/shielded/v2_send.cpp` now carry the direct-send output public coin in
  the send witness and rehydrate canonical `CompactPublicAccount` objects from
  compact public-key rows plus witness-carried output coins after bundle
  deserialization:
  - `V2SendWitness` now serializes `smile_output_coins`
  - direct-send outputs now serialize compact public-key rows instead of the
    full inline `CompactPublicAccount`
  - post-parse bundle rehydration verifies reconstructed note / value
    commitments and restores canonical `smile_account` for the in-memory
    validation / wallet surfaces
- `src/shielded/smile2/ct_proof.{h,cpp}`,
  `src/shielded/smile2/verify_dispatch.cpp`,
  `src/shielded/smile2/wallet_bridge.{h,cpp}`, and
  `src/shielded/v2_proof.{h,cpp}` now extend the live direct-send SMILE CT
  relation so the consumed registry leaf is bound to the same hidden spender
  witness as the selected public account / public coin tuple:
  - `CTPublicAccount` now carries `account_leaf_commitment`
  - `SmileInputTupleProof` now carries `z_leaf`
  - the Fiat-Shamir transcript and verifier-side combined row checks now bind
    the leaf row alongside public-key and public-coin rows
- `src/wallet/shielded_coins.h` and `src/wallet/shielded_wallet.cpp` now
  persist per-note `AccountLeafHint` across scan, mempool discovery, and wallet
  serialization so local note recovery can reconstruct consumed leaf
  commitments for future spends without weakening the consensus model

Measured minimal-output footprint from the redesign harness on this head:

| Family | Current output bytes | Minimal output bytes | Bytes saved |
| --- | ---: | ---: | ---: |
| Direct send | `3,784` | `1,225` | `2,559` |
| Ingress reserve fixture | `13,322` | `75` | `13,247` |
| Egress user fixture | `13,322` | `75` | `13,247` |
| Rebalance reserve fixture | `13,322` | `75` | `13,247` |

Historical branch-checkpoint direct-send envelope-only lower-bound projection
from the same harness:

| Shape | Current-head tx bytes | Projected tx bytes with minimal outputs | Current proof bytes | 24 MB fit | TPS @ 90 s |
| --- | ---: | ---: | ---: | ---: | ---: |
| `1x2` | `59,004` | `53,886` | `51,087` | `445` | `4.94` |
| `2x2` | `69,114` | `63,996` | `61,027` | `375` | `4.17` |
| `2x4` | `99,689` | `89,453` | `84,038` | `268` | `2.98` |

What these numbers mean:

- the account-registry path now materially reduces serialized transaction size
  on the live launch surface by moving future spend recovery onto committed
  registry payloads plus lean consumed-leaf witnesses
- compared with the earlier wave-3 snapshot (`58,418` / `68,077` / `98,461`),
  the current live direct-send surface is now
  `59,004` / `69,114` / `99,689` bytes
- direct-send proof bytes are now `51,087` / `61,027` / `84,038` because the
  live direct-send wire now carries exact output public coins in the witness
  instead of the per-output payload account object
- the redesign harness now exposes that extra surface explicitly as
  `tuple_z_leaf_bytes`:
  - `ct_1x1`: `230`
  - `ct_2x2`: `456`
- the rebuilt direct-send output transport is real:
  - current canonical direct-send output: `3,784` bytes
  - minimal output: `1,225` bytes
- the rebuilt envelope report also proves that simply relocating the exact
  `CompactPublicAccount` bytes elsewhere in consensus is not a viable launch
  shortcut:
  - exact `CompactPublicAccount` transport floor: `14,537` bytes
  - net delta versus current output: `+10,753` bytes

Verification completed on this checkpoint:

- registry sequence:
  - `leaf_count=4`
  - `unspent_leaf_count=3`
  - `proof_sibling_count=2`
  - `sample_light_client_proof_wire_bytes=13,554`
  - `sample_spend_witness_wire_bytes=106`
  - `snapshot_bytes=53,922`
  - `double_spend_rejected=true`
  - `stale_root_rejected=true`
  - `stale_spend_witness_rejected=true`
  - `light_client_proof_valid=true`
  - `snapshot_roundtrip=true`
- tamper surfaces rejected:
  - extended sibling path
  - swapped leaf commitment
  - mismatched shielded state root
- framework summary:
  - `all_ct_checks_pass=true`
  - `all_direct_send_checks_pass=true`
  - `all_ingress_checks_pass=true`
  - `all_account_registry_checks_pass=true`
- direct-send proof-binding tamper coverage:
  - mutated public leaf commitment rejected in `smile2_ct_tests`
  - mutated `tuple_z_leaf` rejected in the redesign harness
- wallet note persistence:
  - `ShieldedCoin` serialization roundtrip now preserves optional
    `AccountLeafHint`
  - direct-send / ingress / egress wallet scan paths still recover notes after
    the local hint-persistence change because the encrypted note payload did not
    change in this pass
- targeted verification commands now passing on this head:
  - `cmake --build build-btx -j8 --target test_btx generate_smile2_proof_redesign_report`
  - `test_btx --run_test=smile2_proof_redesign_framework_tests`
  - `test_btx --run_test=shielded_v2_send_tests`
  - `test_btx --run_test=shielded_v2_proof_tests`
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

### Launch Readiness Report

Status on 2026-03-22:

- `base_direct_smile_launch_ready = true`
- `account_registry_activation_ready = true`

Confirmed launch-ready on this rebased branch head:

- direct-send `DIRECT_SMILE` now proof-binds the public consumed
  `account_leaf_commitment` to the hidden spender witness
- the reset-chain `DIRECT_SMILE` launch surface from PRs `#108`, `#110`, and
  `#111` is the correct base assumption for this branch; the earlier local
  mirror/commentary claiming the Figure 17 public-coin rewrite was still a
  launch blocker was stale branch-local context, not live verifier state
- direct send and ingress both carry authenticated registry inclusion proofs on
  wire
- registry state now commits the full shielded account-leaf payload, and
  snapshot restore rebuilds `CompactPublicAccount` state directly from those
  committed entries
- consumed-leaf transaction witnesses are lean on wire while still binding to
  authenticated consensus state:
  - sample light-client proof: `13,554` bytes
  - sample spend witness: `106` bytes
  - stale spend witnesses are rejected after state transitions
- wallet scan / restore keeps `AccountLeafHint`, so local note recovery can
  reconstruct future consumed leaf commitments
- family-specific value accounting is now split correctly between transaction
  fee/input accounting and shielded pool-state accounting:
  - direct send and ingress still charge only explicit fee to
    `CheckTxInputs()`
  - ingress / egress / rebalance now update shielded pool state with their
    actual reserve or settlement deltas
  - the mempool / block / disconnect path now rejects negative projected pool
    balance on the live ingress route, and
    `txvalidation_tests/*v2_ingress*` passes through connect + reorg again
- registry roots, snapshots, and light-client inclusion proofs are implemented
  and tested
- the live shared-ring SMILE ingress route is now measured through the actual
  runtime harness:
  - `112` leaves / `15` spend inputs / `15` proof shards with one reserve
    output builds and verifies on this head
  - `120` leaves crosses into a `16th` spend input and rejects with
    `bad-shielded-v2-ingress-smile-proof`
  - the corrected launch baseline in the redesign harness now stops at the
    proven `15`-spend ceiling instead of the stale `1000`-leaf placeholder
- the live proof relation on this branch is now:
  `direct_send_smile_and_batch_smile_live_with_committed_registry_payload_recovery_and_lean_spend_witnesses`
- the earlier leaf-only minimal-output contradiction is no longer a launch
  blocker because the launch surface now recovers full account payloads from
  committed registry state rather than requiring leaf-hash-only reconstruction

Non-launch surfaces that remain intentionally out of readiness gating:

- `DIRECT_MATRICT` direct send is still unsafe under the registry redesign:
  - `shielded_v2_send_tests/matrict_direct_send_account_leaf_substitution_attack_can_be_reproven`
  - `shielded_v2_send_tests/matrict_direct_send_real_ring_member_substitution_attack_can_be_reproven`
- native MatRiCT ingress is still unsafe under the registry redesign:
  - `shielded_v2_ingress_tests/matrict_ingress_account_leaf_substitution_survives_without_reproof`
- receipt-backed ingress is still not a production replacement for the hidden
  spend proof:
  - `shielded_v2_ingress_tests/receipt_backed_ingress_accepts_garbage_ring_members_and_wrong_tree`
- the earlier design text claiming egress / rebalance still needed consumed
  registry-leaf migration was too broad; current egress and rebalance bundles
  bind settlement objects and reserve deltas directly and do not spend
  shielded account leaves on wire in the same way direct send and ingress do

Least-bad next move:

- keep every launch-unsafe legacy direct-send / ingress backend off the reset-
  chain production surface
- treat any further leaf-only minimal-output transport as optional follow-on
  optimization rather than launch-critical protocol work

### Local SMILE-Paper Conformance Review

The local SMILE mirror remains the cryptographic source of truth for the live
public-account / public-coin proof relation:

- `doc/research/smile-2021-564.txt` records Appendix E / Figure 17 as a CT
  statement over public account / public coin tuples and their openings
- the older March 20 branch-local annotations in
  `doc/research/smile-2021-564-working-mirror.md` and
  `doc/research/smile-2021-564.txt` that still described the Figure 17
  public-coin rewrite as the remaining `DIRECT_SMILE` production blocker were
  stale after the PR `#108` / `#110` / `#111` proof-core landings and are
  corrected in this checkpoint

Conformance result for this checkpoint:

- the live direct-send CT relation now extends the Appendix E / Figure 17
  public-account / public-coin witness with one additional account-leaf row and
  response `z_leaf`
- the rebased live verifier already includes the production direct-send Figure
  17 launch work that had been missing from the older March 20 notes:
  weak-opening `omega`, framework `framework_omega`, and combined public
  coin-opening verification
- the live launch ingress path is the shared-ring `BATCH_SMILE` verifier, not
  the historical MatRiCT or receipt-backed backends; the runtime harness now
  measures the shared-ring launch ceiling directly
- this is an intentional BTX-specific extension beyond the paper’s exact
  statement because BTX externalizes the public account into a
  consensus-committed registry payload plus lean spent-leaf witness instead of
  carrying raw inline account bytes forever on chain
- no tuple / public-account / public-coin / opening binding was weakened
- no lattice parameters or challenge distributions were changed
- there is no remaining paper-conformance gap on the launch surface for the
  direct-send / shared-ring ingress spender-binding relation; further output-
  side compression is optional BTX-specific follow-on work

Required follow-on:

- measure any additional post-launch output compression against the now-live
  committed-payload registry baseline instead of the retired leaf-only model

## Hard Requirements

The redesign must satisfy all of the following.

### Consensus and Security

- Shielded remains the default BTX private-transfer path.
- Post-quantum cryptography remains mandatory.
- Nullifier-based double-spend prevention remains mandatory.
- Full nodes must be able to validate the chain from consensus data only.
- The redesign must preserve shielded UTXO semantics even though the output wire
  format changes.
- No spend-critical trusted external registry or side database is allowed.
- Direct spends, ingress, egress, and rebalance must all remain consensus
  verifiable.
- The design must preserve or strengthen challenge-domain separation and tuple /
  public-account / public-coin / opening binding.
- The design must not reduce lattice parameters or anonymity sets.

### Product and UX

- Direct user-to-user private transfers remain first-class.
- Bridge ingress and egress remain first-class, not bolt-on exceptions.
- Wallets must still be able to recover notes, show balances, and construct
  future spends.
- Full wallets must remain self-sufficient once they have chain data plus the
  authenticated shielded state.
- AssumeUTXO-style fast sync must remain possible.
- Light-client support must remain possible with authenticated state proofs.

### Scaling

- The design should target another 50%-class reduction in serialized direct
  shielded transactions versus the current wave-3 baseline.
- The design should reduce chain-visible per-output overhead, not merely move
  it somewhere else in the same transaction.
- The design should improve L1 suitability for shielded settlement of L2
  activity.

## Non-Goals

This redesign does not try to preserve:

- backward compatibility with any existing SMILE wire format
- self-describing inline shielded outputs
- legacy explorer assumptions that one output blob contains the whole future
  spend statement

This redesign also does not allow:

- weakening proof relations to chase bytes
- off-chain trusted account lookup
- removal of balance, membership, or nullifier checks

## Safe vs Unsafe Version

The architecture is only acceptable in its consensus-committed form.

Safe version:

- the new public-account registry / accumulator is part of consensus state
- blocks commit to its root
- spends prove against that committed root
- full nodes validate from chain data plus committed state only
- snapshots and light clients verify against committed roots

Unsafe version:

- outputs carry only a small reference
- wallets, explorers, or verifiers must fetch the real spend-relevant account
  object from some uncommitted external store

The unsafe version is explicitly forbidden. If the smaller output format
requires any non-consensus external source to recover spendable public-account
state, the design has failed.

## Problem Statement

### What is expensive today

Current direct-send output structure is effectively:

- `note_commitment`
- `value_commitment`
- inline `smile_account`
- encrypted note payload

The inline `smile_account` dominates output size. The dominant field inside the
account is `public_coin.t0`.

The redesign harness provides current tx-size lower bounds if large account
surfaces are removed:

| Shape | Current | If `pk` removed | If `t0` removed | If only `note_commitment + t_msg` remain | If only `note_commitment` remains |
| --- | ---: | ---: | ---: | ---: | ---: |
| `1x2` | `58,418` | `53,298` | `37,938` | `32,882` | `31,858` |
| `2x2` | `68,077` | `62,957` | `47,597` | `42,541` | `41,517` |
| `2x4` | `98,461` | `88,221` | `57,501` | `47,389` | `45,341` |

These bounds show that the real lever is not ciphertext framing or field-level
exact coding. It is removal of inline `t0` transport and any other large public
account surfaces that future spends do not need literally present on chain.

### Why local wire tuning is no longer enough

Wave 2 and wave 3 already removed:

- duplicated witness copies of output coins
- derivable CT seeds
- duplicated note commitments
- duplicated per-output family metadata
- much of the reconstructable CT proof state
- direct-send payload-local framing fat

Those wins were real. They are not enough to cut direct transaction size in
half again while the chain still stores a full public account per output.

## What Changes and What Does Not

This redesign changes the wire/state format. It does not need to break
verifiability, double-spend prevention, or the shielded UTXO model.

What is retained:

- consensus-verifiable ownership and spendability
- nullifier-based double-spend prevention
- shielded balance accounting
- wallet scanning and note recovery
- bridge ingress / egress / rebalance support
- full-node verification without trusted off-chain data

What changes:

- outputs stop being self-describing containers of the entire future spend
  statement
- future spends depend on an authenticated account registry / accumulator path
  rather than raw inline `smile_account`
- stateless parsing of one isolated output becomes less informative

What is lost:

- trivial reconstruction of the exact future-spend public account from one
  serialized output alone
- some of the implementation simplicity of the current inline model

The thing being given up is inline redundancy. That redundancy is the dominant
source of the current tx-size bottleneck.

## Recommended Architecture

### Design Overview

Replace the launch-surface inline public-account model with a commitment-first
shielded account registry.

Each new shielded output will:

- publish a small, canonical output record
- insert an account-leaf commitment into a consensus-committed registry
- carry the full spendable account witness only inside recipient-recoverable
  encrypted data and local wallet state

Future spends will no longer require chain-visible exact `t0` for each ring
member. They will instead prove:

- membership of consumed account-leaf commitments in the shielded registry
- correct opening of those consumed leaf commitments
- correct nullifier derivation from the hidden spend secret and consumed leaf
- correct balance / amount / range relations
- correct formation of new output leaf commitments

### New Core Objects

#### 1. `ShieldedAccountLeaf`

Consensus-visible object represented only by a commitment hash:

- `account_leaf = H("BTX_SMILE_ACCOUNT_LEAF_V1", note_commitment, domain_tag, account_payload_commitment, spend_tag_commitment, optional_bridge_tag)`

Properties:

- fixed-size on chain
- domain-separated for direct, ingress, egress, rebalance
- binds the future-spend witness without exposing the full public account

#### 2. `AccountPayloadCommitment`

Commitment to the full account statement currently carried inline:

- recipient public key or equivalent public spend/scan surface
- public coin components currently represented by `t0` and `t_msg`
- any launch-equivalent public-account tuple material needed by the new spend
  proof

This object is not serialized inline in outputs. It is only committed.

#### 3. `ShieldedAccountRegistry`

Consensus-maintained authenticated set / append-only tree of unspent shielded
account leaves.

Minimum state:

- `account_root`
- deterministic insertion order
- deterministic inclusion path format
- deterministic spent removal or spent marking semantics

Recommended structure:

- append-only Merkle forest or indexed sparse tree
- leaf key derived from tx position / output position / domain-specific insert
  tag
- update rules designed to support compact inclusion proofs and clean snapshots

#### 4. `ShieldedStateCommitment`

Per-block consensus commitment to shielded state.

Recommended committed roots:

- `account_root`
- `nullifier_root` or authenticated nullifier-set commitment
- `bridge_settlement_root` or equivalent bridge-state commitment if bridge
  settlement state is independently tracked

Recommended placement:

- mandatory block-level coinbase commitment

Reason:

- keeps light-client and bridge verification trustless
- avoids depending on uncommitted node-local state for future spends
- preserves compatibility with AssumeUTXO-style snapshots by giving snapshots a
  stable authenticated target

### Minimal Output Format

Each new shielded output should move to a small canonical form:

- `note_commitment`
- `account_leaf_commitment`
- compact `scan_hint`
- encrypted note payload
- optional minimal family/domain tag only when not implied by payload family

Removed from direct on-chain outputs:

- inline `smile_account`
- inline `public_key`
- inline `public_coin.t0`
- inline `public_coin.t_msg`
- any cached derivative of the account leaf commitment

This is the main tx-size win.

### Why this still qualifies as a shielded UTXO system

The redesign still uses commitment-style value-bearing outputs. It remains a
shielded UTXO system because:

- each spend consumes prior shielded leaves
- each spend creates new shielded leaves
- nullifiers prevent double spends of consumed leaves
- validity depends on opening committed state and proving membership in the
  authenticated set of unspent leaves

What changes is only where the spend-relevant public account data lives:

- today: inline in every output
- redesigned: inside a consensus-committed authenticated registry plus the
  owner-recoverable encrypted witness

### What the wallet retains

Recipient-recoverable encrypted note payload must retain everything required for
future spend construction:

- note secrets
- amount and blinding material
- full account witness required to open `account_leaf_commitment`
- any public coin / tuple witness needed by the redesigned spend proof
- any bridge-domain witness needed for reserve / settlement spends

That keeps spendability local to the owner without requiring chain-visible
public-account transport.

### Wallet balances and note recovery

Wallets do not lose the ability to know balances.

Wallet balance discovery continues to come from:

- scanning candidate outputs
- decrypting owned notes
- recovering note values and spend witnesses

Wallets do not need public amounts to remain visible on chain. What changes is
how the wallet obtains the future-spend public-account statement:

- today: directly from the inline output payload
- redesigned: from the authenticated account registry state plus the decrypted
  local witness

This is an implementation change, not a balance-accounting regression.

## Proof Redesign Requirements

### Replace the current public-account statement

The current CT / spend relation is still shaped around chain-visible exact
public accounts. The redesigned proof system must instead prove against account
leaf commitments and registry inclusion.

Required spend statement elements:

- consumed `account_root`
- consumed account inclusion witness
- hidden opening of each consumed `account_leaf_commitment`
- nullifier derivation bound to consumed leaf and hidden spend secret
- value conservation / balance proof
- amount hiding / range obligations
- creation of new `account_leaf_commitment` outputs
- consistency between new account leaves and encrypted note payloads

### Direct transfer requirements

Direct spend remains first-class:

- output creation must not require a bridge-specific side path
- wallet-to-wallet send must construct leaves directly
- recipient note recovery must produce the full future-spend witness
- direct-send scanning must remain efficient with compact hints

### Bridge requirements

Bridge flows must use the same leaf / root architecture:

- ingress creates shielded account leaves bound to receipt or settlement domain
- egress consumes shielded account leaves and binds the exit settlement claim
- rebalance moves value between shielded domains without falling back to a
  legacy output format

Bridge-specific leaves must be domain-separated rather than using ad hoc output
formats.

### Required proof properties

The new proof relation must preserve:

- hiding of senders, recipients, and amounts
- soundness of membership and balance checks
- binding between encrypted payload recovery and future spend witness
- nullifier uniqueness
- post-quantum assumptions at least as strong as the current launch surface
- no new leakage channel that makes outputs or spends easier to correlate than
  the current launch surface

## Direct and Bridge as First-Class Settlement Surfaces

The redesign must explicitly avoid a split world where direct shielded sends use
one architecture and bridge settlement uses another.

Recommended rule:

- every shielded value-bearing object on chain becomes a registry leaf

This gives BTX one consistent L1 settlement surface for:

- direct user transfers
- L2 deposit ingress
- L2 withdrawal egress
- reserve rebalancing
- future shielded settlement flows

Long-term benefit:

- the chain commits to one authenticated shielded state model
- bridges settle into the same state object direct users already depend on
- future proof upgrades can target one state commitment instead of multiple
  parallel output layouts

## Privacy Impact

This redesign is mainly a scalability and settlement-architecture improvement.
It is not a magic anonymity upgrade. Any privacy gains are secondary and must
be preserved carefully.

Potential privacy improvements:

- less public structure per output on chain
- less transaction-format fingerprinting surface
- cleaner separation between what consensus must know and what can remain inside
  the authenticated shielded state model

What it does not automatically improve:

- sender anonymity set size
- recipient privacy against someone who can already decrypt notes
- nullifier unlinkability beyond what the proof system already guarantees
- amount hiding beyond current commitments and proofs

Privacy risks if implemented carelessly:

- stable registry indices or update patterns that leak more linkage than the
  current output model
- light-client access patterns that reveal which registry entries a wallet is
  interested in
- a reference format that accidentally makes spends easier to correlate

Required privacy rule:

- every registry design choice must be reviewed not just for correctness and
  bytes, but also for whether it increases structural linkage versus the current
  chain-visible output model

## Wallet, Full-Node, Light-Client, and AssumeUTXO Implications

### Full nodes

Full nodes must maintain:

- shielded account registry state
- nullifier state
- bridge settlement state if separately authenticated

Validation becomes more stateful, but remains fully consensus-verifiable.

### Wallets

Wallets must:

- scan compact outputs
- decrypt candidate notes
- recover full future-spend account witnesses from encrypted payloads
- store local leaf witness material and registry position / path data

Wallets do not lose balance visibility. They continue to derive balances from
recovered notes, not from public amounts on chain.

### Light clients

Light clients remain possible if the chain exposes authenticated proofs against
the block-committed shielded state root.

Unacceptable design:

- requiring a light client to fetch uncommitted public-account records from a
  trusted server

Required design:

- inclusion / non-inclusion proofs against committed roots

### AssumeUTXO

AssumeUTXO-style sync remains possible, but snapshots must now include:

- the shielded account registry snapshot
- the authenticated nullifier state
- any bridge settlement authenticated state

This is more complex than the current model, but it does not fundamentally
break fast-sync snapshots.

### Usability and tooling cost

The architecture does create real usability and tooling costs:

- explorer/debug tooling can no longer assume one output is self-describing
- stateless parsing without authenticated registry context becomes less useful
- mempool validation becomes more stateful
- wallet storage and index management become more complex

These are acceptable costs only because the current inline-account model has
reached a tx-size wall that local codec work cannot solve.

## Privacy and Security Impact

### Improvements

- less chain-visible public structure per output
- less structured byte surface for clustering and fingerprinting
- cleaner separation between consensus commitments and private spend witness
  material
- better L1 settlement scalability for private direct and bridge flows

### Risks

- higher implementation complexity in consensus and mempool paths
- more demanding wallet state management
- more complex explorer/debug tooling
- risk of introducing incorrect leaf / root / nullifier binding if redesigned
  carelessly
- risk of creating an accidental trust dependency if any spend-critical witness
  recovery requires an uncommitted external store

### Non-negotiable safety rule

No design is acceptable if future spendability depends on any non-consensus,
untrusted external registry.

## Evolution Relative to the Bitcoin Model

For the transparent pool, BTX should keep the classic Bitcoin model.

For the shielded pool, this redesign is a deliberate evolution away from fully
self-contained outputs and toward authenticated outputs whose full
spend-relevant public state lives in consensus-committed shielded state.

Why this is a defensible long-term evolution:

- it attacks the real scaling bottleneck instead of pretending codec churn can
  save the current format
- it gives a cleaner place to bind future public-account, public-coin, and
  bridge-settlement state
- it makes future proof/object upgrades easier because the on-chain output can
  remain small while authenticated shielded state evolves
- it creates a better long-term settlement surface for L2s and bridge flows

What it sacrifices:

- classic self-describing-output simplicity
- some elegance of the old Bitcoin mental model on the shielded side
- simpler tooling and mempool logic

The trade is acceptable for shielded BTX because the current inline-account
model is very likely not the scalable endpoint.

## Bridge and L2 Settlement Benefits

This redesign should be treated as more than a tx-size hack. If done correctly,
it improves BTX L1 as a settlement layer.

Why:

- ingress, egress, and rebalance flows stop paying for large inline public
  accounts in every output
- high-fanout bridge settlement becomes a compact authenticated state update
  rather than a transport of many oversized inline account objects
- L2s can anchor against a shielded state root instead of depending on bulky
  per-output public-account transport

Where it helps most:

- high-fanout egress batches
- receipt-backed ingress
- reserve/rebalance flows
- end-to-end L2 to L1 shielded settlement

What it does not solve by itself:

- bridge proof verification cost
- L2 data-availability obligations
- wallet/account indexing complexity
- light-client proof design

The improvement is only real if:

- the registry is consensus-committed on L1
- bridge statements and proof objects bind to that registry root
- no trusted off-chain lookup is required to recover spend-relevant shielded
  account state

## Projected Size and TPS Outcomes

Using the measured wave-3 baseline and the harness lower bounds, the following
ranges are realistic on `24 MB` blocks with `90 s` spacing.

### Conservative vNext

Output retains something equivalent to `pk + t_msg`, while deleting inline
`t0`.

| Shape | Projected tx bytes | Projected fit / block | Projected TPS |
| --- | ---: | ---: | ---: |
| `1x2` | `38,002` | `631` | `7.01` |
| `2x2` | `47,661` | `503` | `5.59` |
| `2x4` | `57,629` | `416` | `4.62` |

### More aggressive vNext

Output keeps only something equivalent to `note_commitment + t_msg`.

| Shape | Projected tx bytes | Projected fit / block | Projected TPS |
| --- | ---: | ---: | ---: |
| `1x2` | `32,882` | `729` | `8.10` |
| `2x2` | `42,541` | `564` | `6.27` |
| `2x4` | `47,389` | `506` | `5.62` |

### Most aggressive plausible bound

Output keeps only minimal commitment-visible state near the harness note-only
bound.

| Shape | Projected tx bytes | Projected fit / block | Projected TPS |
| --- | ---: | ---: | ---: |
| `1x2` | `31,858` | `753` | `8.37` |
| `2x2` | `41,517` | `578` | `6.42` |
| `2x4` | `45,341` | `529` | `5.88` |

Important caveat:

- these projections assume the new registry/membership proof does not re-add an
  equivalent amount of witness/proof bulk elsewhere
- the architecture only pays off if the proof redesign genuinely eliminates the
  need for raw inline public-account transport

## Recommended Implementation Plan

### Phase 0: Spec lock and measurement gate

- lock the minimal output format
- lock the committed shielded state root format
- extend the redesign harness with vNext output / account-leaf / root metrics
- define tx-size and TPS acceptance targets for direct, ingress, and egress

Status on this branch:

- landed in the redesign harness and helper layer
- family output footprints, direct-send tx projections, registry sequence
  attacks, snapshot / restore, and light-client proof surfaces now have
  dedicated coverage

### Phase 1: State model and commitments

- introduce account-leaf commitment type
- introduce shielded account registry state
- introduce block commitment to shielded state roots
- define deterministic insertion / spend / pruning rules

Status on this branch:

- landed as deterministic commitment and state scaffolding in
  `src/shielded/account_registry.{h,cpp}`
- wired into live chainstate roots/history, snapshot / restore, block-level
  shielded state commitment helpers, mempool / block validation of anchored
  inclusion proofs, and wallet note-hint persistence

### Phase 2: Direct spend proof vNext

- redesign SMILE spend proofs around leaf commitments and registry inclusion
- replace raw public-account ring statement with commitment-opening statement
- preserve nullifier, balance, and hiding properties
- migrate direct send first

Current blocker:

- the live direct-send proof rewrite is connected to consensus validation, but
  the output side still ships inline `CompactPublicAccount` bytes and ingress
  does not yet have an equivalent consumed-leaf-aware proof relation

### Phase 3: Bridge migration

- migrate ingress outputs to leaf commitments
- migrate egress and rebalance to leaf commitments
- bind receipt-backed and settlement-backed flows to the same committed root
- remove any remaining bridge-only legacy output structure

Current blocker:

- ingress now carries authenticated consumed-leaf inclusion proofs but still
  verifies only hidden note/nullifier membership; egress and rebalance still
  expose settlement objects or reserve deltas directly instead of spent
  registry-leaf references

### Phase 4: Wallet, mempool, and node integration

- update wallet note recovery and local witness storage
- update mempool policy and contextual validation
- update chainstate snapshots and restoration
- update explorer/debug tools for leaf-based decoding

### Phase 5: Launch criteria

- prove direct-send tx-size reduction is real at the serialized transaction
  level
- prove bridge settlement tx-size reduction is real
- prove no regressions in correctness, adversarial rejection, or wallet recovery
- prove block-fit / TPS gains on the real runtime harness

## Required Test and Verification Framework

The existing proof-redesign framework must be extended to cover the new
architecture.

Required additions:

- state-model invariants:
  - account-leaf determinism
  - domain separation
  - registry insertion ordering
  - spent-state update correctness
- account-leaf commitment roundtrip and tamper tests
- registry insertion / membership / spent-state tests
- nullifier uniqueness tests bound to leaf commitments
- direct-send, ingress, egress, and rebalance vNext tx-size reports
- block-commitment correctness tests
- snapshot / restore tests covering shielded registry state
- light-client inclusion-proof tests against committed shielded roots
- differential tests against the current wave-3 baseline for:
  - tx bytes
  - proof bytes
  - output bytes
  - prove / verify time
  - block-fit / TPS

### Test-driven development rule

Every architecture pass should start by extending the redesign harness before
the protocol rewrite lands.

Required red/green sequence for each major change:

1. add or update measurement and adversarial cases in the harness
2. capture failing baseline behavior for the new design target
3. implement the protocol or state-model change
4. re-run correctness, tamper, size, and runtime gates
5. record both wins and failed experiments in the active tracker

Every significant redesign step must be evaluated across:

- correctness
- cryptographic integrity
- shielding/privacy behavior
- tx size
- proof size
- build/prove time
- verify time
- direct-send throughput
- bridge settlement throughput
- snapshot / restore behavior
- light-client proofability

### Minimum harness surface for vNext

The shared redesign harness should grow to cover:

- direct-send vNext leaf-output serialization
- bridge ingress / egress / rebalance vNext leaf-output serialization
- registry root update simulation over multi-block sequences
- double-spend attempts against stale and fresh registry roots
- malformed or replayed inclusion paths
- note recovery against leaf-only outputs
- snapshot / restore with shielded registry state present
- light-client inclusion proofs against committed shielded state roots
- privacy-structure checks for stable index leakage or over-explicit leaf
  metadata

## Explicit Trade-Offs

What improves:

- direct tx size
- block fit / TPS
- L1 suitability for shielded settlement
- architectural flexibility for future proof upgrades

What gets harder:

- node state management
- mempool validation
- wallet witness storage
- explorer and debug tooling
- snapshot contents

This is an acceptable trade only because the current inline public-account model
has reached its tx-size ceiling.

## Recommended Decision

Proceed with a shielded account-registry redesign as the next major hard-fork
SMILE workstream.

Recommended architectural position:

- keep transparent BTX on the classic Bitcoin model
- evolve the shielded pool to a commitment-first authenticated state model
- treat direct send and bridge settlement as equal citizens of that model
- keep post-quantum security and shielded-by-default policy unchanged

This is the most credible path to another material tx-size reduction after the
wave-2 and wave-3 wins have already exhausted local codec and inline-format
cleanup.
