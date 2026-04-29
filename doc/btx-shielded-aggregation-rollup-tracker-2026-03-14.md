# BTX Shielded Aggregation And Rollup Tracker

Date: 2026-03-14
Branch: `codex/shielded-aggregation-rollup-study`

## Objective

Study and implement a scalable path for BTX shielded activity where many user
actions can settle through one bridge / batch event instead of consuming one
full L1 shielded spend per user.

The immediate design target is not "shrink the current MatRiCT proof a little";
it is "standardize a batch-settlement surface that can carry a Merkle root of
many off-chain user actions plus one L1 settlement transaction."

## Execution Stance

- Prioritize the highest-difficulty, highest-impact scalability problems first.
  This branch should not intentionally decompose the work into trivial or
  low-risk slices when a larger blocker can be attacked directly and validated
  in the same branch.
- Treat "next steps" as active hard blockers to solve in-branch, not as a
  parking lot for difficult work to defer indefinitely.
- Consensus compatibility is not a protected constraint on this branch.
  If maximum BTX performance and scalability require a hard-fork consensus
  change, that is acceptable and should be analyzed and implemented directly.
- Wallet-layer and bridge-layer tooling remain useful here only when they
  unblock immediate measurements, reduce design uncertainty, or sharpen the
  case for a larger consensus-level redesign.

## Local Code Baseline

- `src/shielded/ringct/range_proof.cpp`
  - One output range proof currently dominates proof size.
- `src/shielded/ringct/matrict.cpp`
  - A full shielded spend bundles ring signature, balance proof, and one range
    proof per output.
- `src/consensus/validation.h`
  - Shielded bundle bytes are charged as non-witness bytes in transaction
    weight.
- `src/shielded/bridge.*`
  - BTX already has a bridge settlement layer, but it is oriented around one
    plan per settlement event and does not yet standardize batch roots for many
    user actions.
- `src/wallet/bridge_wallet.*`
  - Wallet helpers already build deterministic bridge-in / bridge-out plans and
    P2MR settlement PSBTs.
- `src/wallet/shielded_rpc.cpp`
  - Bridge RPCs exist today for single-plan flows.
- `src/bench/pq_verify.cpp`
  - Existing PQ verification microbenches give a local baseline for the
    marginal cost of verifying user batch authorizations.

## Measured Current Sizes

Measured directly from current unit tests in `build-btx/bin/test_btx`:

- `ringct_range_proof_tests/serialized_size_is_compact`
  - Range proof serialized size: `472704` bytes
- `ringct_matrict_tests/proof_size_target_for_2in_2out`
  - MatRiCT 2-in / 2-out serialized size: `1162672` bytes

These measurements match the chain-level capacity finding that the current
shielded proof shape is too large to support high-volume direct-on-L1 shielded
payments.

## Research Themes

1. Recursive / aggregated proof systems for many private actions per L1 proof.
2. Rollup-style state root updates with net settlement instead of per-user L1
   state transitions.
3. Off-chain privacy networks that keep private execution outside the base
   chain and only publish attestations / commitments to L1.
4. BTX-specific design constraints:
   - post-quantum transparent signatures,
   - non-witness charging of shielded bytes,
   - storage growth of note commitments and nullifiers,
   - CPU/GPU proving and verification cost envelopes.

## Candidate Architecture Tracks

### Track A: Keep Current MatRiCT On L1, Tune Limits

Status: rejected as the primary scaling path.

Reason:

- The size bottleneck is structural.
- Even a moderate improvement to the current proof encoding would still leave
  BTX far from the throughput needed for mass shielded usage on L1.

### Track B: Consensus-Level New Succinct Shielded Proof

Status: fully in scope; hard fork acceptable if it wins on throughput.

Reason:

- This would likely require a new proving system, a new verifier, new trusted
  assumptions or recursion machinery, and a more invasive consensus migration.
- That migration cost is not a blocker on this branch if the resulting design
  materially outperforms bridge-only settlement surfaces.

### Track C: Bridge / Rollup Batch Settlement

Status: primary implementation track.

Shape:

- Off-chain user actions are hashed into a canonical Merkle root.
- BTX L1 accepts one bridge settlement event that commits to that root and
  settles only the net amount.
- External bridges can attach recursive proofs, committee attestations, or user
  authorization bundles off-chain while BTX core standardizes the settlement
  commitment format.

## First Implementation Slice

Add a canonical bridge batch commitment/report surface:

- canonical leaf hashing for off-chain user actions,
- canonical batch root computation,
- canonical batch commitment serialization and hashing,
- wallet plan support so one bridge-in or bridge-out settlement can carry one
  batch commitment instead of implying one user action,
- bridge RPC support to build and inspect batch commitments and plans.

This is the minimum useful substrate for future recursive proofs, committee
verification, or operator-specific execution engines.

## Second Implementation Slice

Add wallet-signed batch authorizations beneath the batch leaf layer:

- standardize a canonical authorization message that binds:
  - bridge direction,
  - bridge ids,
  - leaf kind,
  - wallet id,
  - destination id,
  - amount,
  - authorization nonce,
  - authorizer PQ key;
- sign that message with a wallet-owned P2MR PQ key;
- derive the leaf `authorization_hash` from the canonical message hash rather
  than the signature bytes, so re-signing the same authorization does not
  perturb the batch root;
- let `bridge_buildbatchcommitment` accept signed authorizations directly and
  derive canonical leaves after signature verification.

## Third Implementation Slice

Add aggregated bridge-in planning and direct benchmark coverage:

- `bridge_planbatchin` builds one shielded bridge-in settlement plan from many
  canonical leaves or signed bridge-in authorizations;
- the plan total is derived from the batch leaves, so a bridge can settle many
  off-chain credits for wallets that have not previously appeared on BTX L1;
- a new functional test compares one aggregated bridge-in settlement note
  against many single bridge-in notes;
- a new benchmark file measures:
  - canonical batch Merkle root cost,
  - and authorization verification cost for ML-DSA-44 and SLH-DSA-128s.

## Fourth Implementation Slice

Add a generic external batch anchor that binds BTX settlement to off-chain DA
and/or proof systems without baking Celestia, Nillion, SP1, or RISC Zero
directly into consensus-facing structs:

- batch commitments now optionally carry:
  - `domain_id`,
  - `source_epoch`,
  - `data_root`,
  - `verification_root`;
- bridge-in can embed that anchored commitment directly in the memo-bound batch
  settlement note;
- bridge-out lifts the same anchor into attestation v3 so the CSFS message
  binds:
  - the payout template,
  - the batch root,
  - and the external DA / proof reference;
- a new functional test confirms anchored batch commitments and anchored
  attestations round-trip with deterministic sizes.

## Fifth Implementation Slice

Add a receipt-backed verifier / committee layer above the generic external
anchor:

- standardize a canonical pre-anchor `BridgeBatchStatement` that binds:
  - bridge direction,
  - bridge ids,
  - entry count,
  - total amount,
  - batch root,
  - and the external `domain_id` / `source_epoch` / `data_root`;
- standardize a signed `BridgeBatchReceipt` so committee members, prover
  operators, or bridge-domain verifiers can attest to that statement without
  circularly signing the final `verification_root`;
- derive `verification_root` from the signed receipt set only after receipt
  verification;
- reject duplicate attestors so one signer cannot inflate the witness set;
- let `bridge_buildexternalanchor` enforce simple verifier policy:
  - minimum receipt count,
  - and required attestor membership for known committee sets.

## Sixth Implementation Slice

Bind committee membership itself into the signed batch statement instead of
leaving it only in RPC-local policy:

- add a canonical `BridgeVerifierSetCommitment` carrying:
  - `attestor_count`,
  - `required_signers`,
  - and `attestor_root`;
- lift batch statements to `version = 2` when they commit to one verifier set;
- add `bridge_buildverifierset` so bridge software can derive the commitment
  once and reuse it across statements;
- require `bridge_buildexternalanchor` to validate receipt membership against a
  revealed attestor list whose commitment matches the statement;
- keep the BTX-facing settlement object compact while making committee policy
  canonical and signed.

## Seventh Implementation Slice

Replace full verifier-set disclosure with compact membership proofs on the
ordinary receipt path:

- add canonical `BridgeVerifierSetProof` witnesses against `attestor_root`;
- extend `bridge_buildverifierset` so it can emit proofs for a selected signer
  subset;
- let `bridge_buildexternalanchor` validate one proof per receipt instead of
  requiring the whole verifier set to be revealed;
- keep `revealed_attestors` as a compatibility fallback while bridges move to
  the smaller proof-backed flow.

## Eighth Implementation Slice

Add a generic imported-proof receipt path under the same `verification_root`
slot so BTX can bind one batch settlement to zkVM or DA-bridge outputs without
carrying full proof artifacts on L1:

- standardize a compact `BridgeProofReceipt` carrying:
  - `statement_hash`,
  - `proof_system_id`,
  - `verifier_key_hash`,
  - `public_values_hash`,
  - and `proof_commitment`;
- keep the signed batch statement as the shared settlement preimage, but let
  imported proof receipts reference it by hash instead of embedding the full
  statement in every receipt;
- derive `verification_root` from a canonical Merkle root over proof receipts,
  parallel to the committee-receipt path;
- add `bridge_buildproofreceipt`, `bridge_decodeproofreceipt`, and
  `bridge_buildproofanchor` so bridges can deterministically construct,
  inspect, and policy-check imported proof bundles before reusing the resulting
  anchor in normal batch commitment / attestation flows;
- expose lightweight policy checks for proof bundles:
- minimum receipt count,
  - required proof-system ids,
  - and required verifier-key / program hashes.

## Ninth Implementation Slice

Bind imported-proof acceptance policy into the signed batch statement itself,
instead of leaving it entirely to RPC-local allowlists:

- add canonical proof descriptors over:
  - `proof_system_id`,
  - and `verifier_key_hash`;
- add a canonical `BridgeProofPolicyCommitment` carrying:
  - `descriptor_count`,
  - `required_receipts`,
  - and `descriptor_root`;
- add compact `BridgeProofPolicyProof` membership witnesses so one imported
  proof receipt can prove its descriptor belongs to the committed policy set
  without disclosing the full set every time;
- extend batch statements to carry a proof-policy commitment:
  - `version = 3` for proof-policy only,
  - and `version = 4` when both verifier-set and proof-policy commitments are
    present;
- add `bridge_buildproofpolicy` plus proof-backed enforcement in
  `bridge_buildproofanchor`:
  - `descriptor_proofs` as the preferred compact path,
  - `revealed_descriptors` as the compatibility fallback.

## Tenth Implementation Slice

Bind committee receipts and imported proof receipts into one canonical hybrid
verification bundle so BTX can accept bridge domains that require both bounded
operator signatures and imported zk / DA receipts at the same settlement
boundary:

- add canonical `BridgeVerificationBundle` carrying:
  - `signed_receipt_root`,
  - and `proof_receipt_root`;
- derive `verification_root` for hybrid statements from that bundle hash rather
  than from either witness set alone;
- require statements that commit to both:
  - `verifier_set`,
  - and `proof_policy`
  to use a dedicated hybrid anchor path instead of silently downcasting into
  committee-only or proof-only validation;
- add `bridge_buildhybridanchor` with nested policy enforcement for:
  - committee receipts,
  - imported proof receipts,
  - compact attestor membership proofs,
  - and compact proof-descriptor membership proofs;
- add functional coverage that:
  - rejects one-sided anchor builders for `version = 4` statements,
  - verifies the hybrid anchor path with compact proofs,
  - verifies the full-set disclosure fallbacks,
  - and reuses the resulting anchor in the normal bridge-out settlement flow;
- add benchmark coverage for:
  - verification-bundle hashing,
  - and hybrid anchor derivation from both witness sets.

## Eleventh Implementation Slice

Standardize imported-proof family ids with canonical proof profiles so bridge
integrators no longer have to invent ad hoc `proof_system_id` hashes for SP1,
RISC Zero, Blobstream-style DA proofs, or future imported-proof families:

- add canonical `BridgeProofSystemProfile` carrying:
  - `family_id`,
  - `proof_type_id`,
  - and `claim_system_id`;
- derive `proof_system_id` as a domain-separated hash of that profile instead
  of relying on undocumented local conventions;
- add `bridge_buildproofprofile` and `bridge_decodeproofprofile` so bridges can
  deterministically build and inspect named proof-family profiles;
- extend `bridge_buildproofpolicy` and `bridge_buildproofreceipt` so they
  accept:
  - raw `proof_system_id` as the low-level path,
  - `proof_profile_hex` as the canonical high-level path,
  - or inline `proof_profile` objects when bridge software wants one-shot RPC
    assembly;
- add functional coverage for SP1-, RISC Zero-, and Blobstream-shaped profile
  labels flowing through:
  - profile building,
  - descriptor building,
  - proof policy commitments,
  - imported proof receipts,
  - and proof-backed anchoring;
- add benchmark coverage for proof-system-id hashing from a canonical profile.

## Twelfth Implementation Slice

Canonicalize imported-proof public outputs with BTX proof claims so bridge
integrators can derive `public_values_hash` from explicit batch metadata rather
than passing an opaque digest:

- add canonical `BridgeProofClaim` carrying a statement-bound BTX claim over:
  - `batch_tuple_v1`,
  - `settlement_metadata_v1`,
  - or `data_root_tuple_v1`;
- derive `public_values_hash` as a domain-separated hash of that claim rather
  than relying on undocumented bridge-local hashing conventions;
- add `bridge_buildproofclaim` and `bridge_decodeproofclaim` so bridges can
  deterministically build and inspect claim digests from a canonical batch
  statement;
- extend `bridge_buildproofreceipt` so it accepts:
  - raw `public_values_hash` as the low-level path,
  - `claim_hex` as the canonical high-level path,
  - or inline `claim` objects for one-shot RPC assembly;
- enforce that a supplied proof claim actually matches the bound batch
  statement before a proof receipt can be built;
- add functional coverage for SP1-, RISC Zero-, and Blobstream-shaped imported
  receipts built from canonical BTX proof claims;
- add benchmark coverage for proof-claim hashing over both settlement-metadata
  and data-root-tuple variants.

## Thirteenth Implementation Slice

Bind proof-family profiles and BTX claim kinds into canonical named proof
adapters so bridge software can select one recognized imported-proof shape with
one selector rather than recombining local profile and claim conventions:

- add canonical `BridgeProofAdapter` carrying:
  - one `BridgeProofSystemProfile`,
  - and one `BridgeProofClaimKind`;
- derive a stable `adapter_id` as the compact hash of that adapter;
- add `bridge_listproofadapters`, `bridge_buildproofadapter`, and
  `bridge_decodeproofadapter`;
- extend imported-proof RPCs so they accept:
  - `proof_adapter_name`,
  - `proof_adapter_hex`,
  - or inline `proof_adapter` objects;
- have `bridge_buildproofpolicy` derive proof descriptors from adapters rather
  than requiring callers to manually recombine:
  - proof-family labels,
  - proof type,
  - claim-system labels,
  - and BTX claim-kind knowledge;
- have `bridge_buildproofreceipt` derive both:
  - `proof_system_id`,
  - and `public_values_hash`
  from the bound statement plus the canonical adapter;
- ship built-in adapter templates for:
  - SP1 `compressed`, `plonk`, and `groth16` over
    `settlement_metadata_v1` and `batch_tuple_v1`,
  - RISC Zero `composite`, `succinct`, and `groth16` over the same BTX claim
    families,
  - and Blobstream-style `sp1` / `risc0` adapters over `data_root_tuple_v1`;
- add functional coverage for named and explicit adapters flowing through:
  - proof-policy construction,
  - proof-receipt construction,
  - proof-anchor construction,
  - and the existing bridge settlement path;
- add benchmark coverage for canonical proof-adapter hashing.

## Fourteenth Implementation Slice

Add self-contained proof artifacts so imported bridge / rollup proofs can be
tracked as off-chain bundles with explicit byte counts while still regenerating
the existing compact BTX receipt and descriptor surfaces:

- add canonical `BridgeProofArtifact` carrying:
  - one canonical `BridgeProofAdapter`,
  - statement hash,
  - verifier identity hash,
  - canonical public-values hash,
  - proof commitment,
  - full artifact-bundle commitment,
  - and byte counts for proof, public values, and auxiliary sidecar data;
- derive a stable `proof_artifact_id` plus total storage bytes for each
  imported-proof bundle;
- add `bridge_buildproofartifact` and `bridge_decodeproofartifact`;
- extend imported-proof RPCs so they accept:
  - `proof_artifact_hex`,
  - or inline `proof_artifact` objects;
- allow `bridge_buildproofpolicy` to regenerate descriptors from proof artifacts
  after the underlying statement exists;
- allow `bridge_buildproofreceipt` to reconstruct the canonical compact receipt
  directly from a proof artifact while enforcing statement-hash and
  public-values consistency;
- make canonical adapter parsing accept already-materialized canonical
  `profile` ids, not only label-based selectors, so decoded artifacts can be
  reused as inputs without bridge-local translation;
- fix `test/functional/create_cache.py` to accept wallet-type flags such as
  `--descriptors`, which unblocks the normal functional runner path for the new
  bridge tests;
- add functional coverage for:
  - artifact building,
  - artifact decoding,
  - artifact-backed descriptor regeneration,
  - artifact-backed receipt regeneration,
  - and proof-anchor / batch-settlement flow from artifact-backed receipts;
- add benchmark coverage for canonical proof-artifact hashing.

## Fifteenth Implementation Slice

Add a generic bridge settlement capacity estimator so BTX can compare actual
finalized L1 settlement footprints against control-plane bytes and off-chain
proof storage rather than relying on ad hoc spreadsheet math:

- add canonical `BridgeCapacityFootprint` and `EstimateBridgeCapacity`;
- add `bridge_estimatecapacity` for scenario-based block-fit estimates over:
  - L1 serialized bytes,
  - L1 weight,
  - control-plane bytes,
  - off-chain storage bytes,
  - and represented user count per settlement;
- allow an optional baseline footprint so one measured bridge path can be
  compared directly against the current native shielded-spend bottleneck;
- add unit coverage for:
  - weight-bound native shielded capacity,
  - batched-user scaling,
  - and off-chain storage accumulation;
- add functional coverage that:
  - finalizes real single bridge-out settlements,
  - finalizes one batched bridge-out settlement,
  - finalizes one proof-anchored batched bridge-out settlement,
  - feeds those measured tx bytes and weights into `bridge_estimatecapacity`,
  - and checks the resulting users-per-block gain against the measured native
    shielded baseline;
- register the new functional scenario in `test_runner.py` and refresh the
  build-tree script links via CMake so the normal runner path stays green.

## Sixteenth Implementation Slice

Extend the generic settlement-capacity model so BTX can also answer whether a
given proving stack can keep up with the compact L1 settlement path:

- add canonical `BridgeProverLane`, `BridgeProverFootprint`,
  `BridgeProverLaneEstimate`, and `EstimateBridgeProverCapacity`;
- extend `bridge_estimatecapacity` with an optional `prover` object covering:
  - native pre-proof work,
  - CPU proving,
  - GPU proving,
  - and remote prover / prover-network lanes;
- report, for each lane:
  - settlements and users sustained per BTX block interval,
  - settlements and users sustained per hour,
  - whether L1 or the prover lane is the actual bottleneck,
  - workers required to saturate the current L1 settlement footprint,
  - and modeled hourly cost at current scale vs full-L1 saturation;
- add direct unit coverage for:
  - prover-bound vs L1-bound lanes,
  - parallel-job scaling,
  - hourly-throughput derivation,
  - and required-worker calculations;
- add functional coverage that:
  - finalizes a real three-user proof-anchored bridge-out settlement,
  - feeds the finalized footprint into `bridge_estimatecapacity`,
  - overlays modeled native / CPU / GPU / network lanes,
  - and checks whether each lane can sustain the `90 s` BTX cadence;
- register the new functional scenario in `test_runner.py` and re-run the
  normal runner path with the refreshed build-tree script links.

## Seventeenth Implementation Slice

Bind prover timing metadata to actual imported proof artifacts instead of
keeping prover-lane timings as ad hoc manual inputs:

- add canonical `BridgeProverSample` objects linked to one proof artifact and
  carrying:
  - statement hash,
  - proof artifact id,
  - proof-system id,
  - verifier-key hash,
  - artifact storage bytes,
  - native / CPU / GPU / network wall times,
  - and peak memory bytes;
- add canonical `BridgeProverProfile` objects that aggregate a set of prover
  samples for one bridge batch statement and commit to them through a stable
  sample root;
- add RPCs:
  - `bridge_buildproversample`,
  - `bridge_decodeproversample`,
  - `bridge_buildproverprofile`,
  - and `bridge_decodeproverprofile`;
- extend `bridge_estimatecapacity` so `options.prover` can accept a canonical
  prover profile and derive `millis_per_settlement` for each lane from the
  artifact-linked sample set;
- add unit coverage for:
  - prover-sample roundtrips and ids,
  - profile aggregation,
  - profile serialization,
  - and duplicate-sample rejection;
- add functional coverage that:
  - finalizes a real three-user proof-anchored bridge-out settlement,
  - builds three prover samples from the actual imported artifacts,
  - aggregates them into one canonical prover profile,
- and verifies that profile-derived prover-lane estimates exactly match the
  previous manual-timing scenario.

## Eighteenth Implementation Slice

Turn the measured state-growth problem into an explicit retention-policy model
instead of leaving "what stays on L1?" as a vague later-stage design note:

- add canonical `BridgeShieldedStateRetentionPolicy` and
  `BridgeShieldedStateRetentionEstimate` types that split aggregate-settlement
  state into:
  - retained persistent bytes,
  - externalized persistent bytes,
  - deferred wallet materialization bytes,
  - retained snapshot bytes,
  - externalized snapshot bytes,
  - and runtime hot-cache bytes;
- add stable serialization / hashing for the retention policy so bridge and
  wallet experiments can reuse the same policy object across measurements;
- extend the bridge estimator surface with
  `EstimateBridgeShieldedStateRetention(...)`;
- add wallet RPCs:
  - `bridge_buildstateretentionpolicy`,
  - `bridge_decodestateretentionpolicy`,
  - and `bridge_estimatestateretention`;
- measure at least two directly competing policies on the same DA-lane rollup
  footprint:
  - full L1 retention with full first-touch wallet materialization,
  - and proof-backed externalization of commitment history plus deferred
    wallet materialization;
- quantify snapshot-target cadence so the branch stops talking abstractly
  about storage growth and starts answering how fast a node hits a concrete
  retained-state threshold.

## Nineteenth Implementation Slice

Replace the manual hard-fork proof/DA byte assumptions with canonical
artifact-backed bundle inputs so BTX can measure aggregate settlement against
current imported proof and externalized-state payload shapes:

- add canonical `BridgeDataArtifact` objects for DA/state-diff/snapshot/query
  payload manifests tied to one bridge batch statement;
- add canonical `BridgeAggregateArtifactBundle` objects that summarize:
  - proof artifact counts and Merkle root,
  - data artifact counts and Merkle root,
  - aggregate proof payload bytes,
  - aggregate DA payload bytes,
  - and aggregate auxiliary off-chain bytes;
- add wallet RPCs:
  - `bridge_builddataartifact`,
  - `bridge_decodedataartifact`,
  - `bridge_buildaggregateartifactbundle`,
  - `bridge_decodeaggregateartifactbundle`;
- extend `bridge_buildaggregatesettlement` so it can derive
  `proof_payload_bytes`, `data_availability_payload_bytes`, and
  `auxiliary_offchain_bytes` from one canonical artifact bundle instead of
  from manual byte entries;
- feed the new bundle surface from:
  - current proof artifacts,
  - and retention-derived externalized state/snapshot payloads,
  so the branch stops comparing hard-fork aggregate settlement against purely
  hand-entered byte budgets.

## External Research Notes

### Ethereum Rollup Pattern

- Ethereum’s ZK-rollup documentation describes the standard pattern directly:
  computation and state storage move off-chain, operators submit a summary plus
  a proof, and recursive proofs can finalize several blocks with one validity
  proof.
  - Source:
    `https://ethereum.org/en/developers/docs/scaling/zk-rollups/`
- EIP-4844 shows the matching data-availability direction: rollups move large
  data into blob transactions / sidecars, while keeping succinct commitments
  and proof verification on-chain.
  - Source:
    `https://eips.ethereum.org/EIPS/eip-4844`

Implication for BTX:

- BTX should emulate the settlement pattern, not the exact Ethereum VM stack.
- The base layer should accept batch roots, net settlement, and proof /
  attestation hooks rather than one giant proof per user action.

### Zcash Direction

- ZIP 230’s Orchard Action Group uses one aggregated zk-SNARK proof for all
  actions in the action group rather than one proof per action.
  - Source:
    `https://zips.z.cash/zip-0230`
- Halo recursion is explicitly described by Zcash as a way for a single proof
  to attest to many other proofs.
  - Source:
    `https://z.cash/learn/what-is-halo-for-zcash/`
- Project Tachyon is an active Zcash-oriented proposal focused on shrinking
  transactions by two orders of magnitude and removing runaway validator state
  growth.
  - Source:
    `https://tachyon.z.cash/`

Implication for BTX:

- The industry direction for shielded systems is aggregation and state-growth
  control, not simply tolerating large monolithic proofs.

### Aztec Direction

- Aztec’s rollup circuit design compresses thousands of transactions into a
  single SNARK proof, aggregates private-kernel and public-execution proofs,
  and uses a binary tree of proofs to parallelize proving.
  - Source:
    `https://docs.aztec.network/developers/docs/foundational-topics/advanced/circuits/rollup_circuits`
- Aztec also distinguishes the actually zero-knowledge private kernel from the
  broader rollup compression machinery.
  - Source:
    `https://docs.aztec.network/developers/docs/concepts/advanced/circuits/kernels/private_kernel`

Implication for BTX:

- BTX should separate privacy-preserving user proof generation from the L1
  settlement compression layer.

### Nillion Direction

- Nillion’s Blind Computer docs frame the network as confidential storage and
  compute infrastructure rather than a base chain that directly executes every
  private action.
  - Source:
    `https://docs.nillion.com/blind-computer/learn/overview`
- Nillion Blacklight adds a verification layer with committee assignment,
  staking, and workload verification on an Ethereum L2.
  - Source:
    `https://docs.nillion.com/blacklight/learn/overview`

Implication for BTX:

- A committee-verified or externally proved bridge domain is a legitimate
  scaling model for BTX. Private activity does not need to be re-executed
  directly in BTX consensus if BTX standardizes the settlement boundary.
- The new BTX receipt-set path maps cleanly onto that model:
  - off-chain work happens elsewhere,
  - a bounded verifier committee signs a canonical statement,
  - and BTX only needs the compact settlement commitment plus the witness-set
    root.
- The new verifier-set commitment extends that model one step further:
  - the committee threshold is now part of the signed statement itself,
  - not just relayer-local policy.

### Shared Proof Aggregation And DA Layers

- ZKsync Gateway is explicitly documented as a shared proof aggregation layer
  that aggregates proofs from multiple chains into one proof submitted to
  Ethereum.
  - Source:
    `https://docs.zksync.io/zksync-protocol/gateway/features`
- ZKsync’s validium docs make the DA split concrete:
  - pubdata can be stored on an external DA layer,
  - the protocol can verify inclusion on L1 through verification bridges or ZK
    proofs,
  - and the DA validator contract only needs to decide whether a commitment /
    proof pair is valid.
  - Source:
    `https://docs.zksync.io/zk-stack/customizations/validium`
- Celestia’s current docs describe the exact modular DA role:
  - execution and settlement sit above the DA layer,
  - DAS lets light nodes verify availability without downloading full blocks,
  - NMTs let each application fetch only its own namespace.
  - Source:
    `https://docs.celestia.org/learn/celestia-101/data-availability/`

Implication for BTX:

- If BTX wants to support higher private throughput than its own base layer can
  publish, a validium-style attachment is realistic:
  - BTX can verify a compact batch commitment / proof,
  - while bulk encrypted state or replay data lives on an external DA layer.

### Blobstream / DA-Bridge Reference

- Celestia’s current Blobstream docs describe a concrete pattern that is very
  close to what BTX would need for external replay / data-availability binding:
  - a light-client contract on the settlement chain,
  - succinct validity proofs for source-chain headers,
  - and Merkle inclusion proofs against published data roots.
  - Source:
    `https://docs.celestia.org/how-to-guides/blobstream`
- Celestia also states that current Blobstream deployments use SP1 Blobstream,
  while a RISC Zero implementation remains available as an alternative.
  - Source:
    `https://docs.celestia.org/how-to-guides/blobstream`
- Celestia’s operator guide for Blobstream describes the exact signer / submitter
  split:
  - an orchestrator watches Celestia and signs attestations,
  - while a relayer submits them onward.
  - Source:
    `https://docs.celestia.org/operate/blobstream/install-binary/`
- Celestia’s current proof-query docs describe the concrete proof chaining used
  for settlement verification:
  - Merkle proofs from shares to row roots,
  - row roots to the data root,
  - and the data root into the data-root tuple root consumed by Blobstream.
  - Source:
    `https://docs.celestia.org/how-to-guides/blobstream/proof-queries`

Implication for BTX:

- A practical BTX validium path does not need BTX consensus to carry full
  shielded replay data.
- BTX can instead standardize:
  - a batch commitment in the bridge settlement,
  - a DA root / epoch reference,
  - and a proof or committee witness that the encrypted batch log is available
    somewhere else.
- The new generic external anchor in this branch is intentionally shaped around
  that model:
  - `domain_id` identifies the external domain,
  - `source_epoch` identifies the batch / blob / log interval,
  - `data_root` binds availability,
  - `verification_root` binds a proof receipt or committee transcript.
- The new receipt-backed anchor builder is intentionally aligned with that
  deployment pattern:
  - signer membership can be enforced by `required_attestors`,
  - one settlement submitter can post the result,
  - and BTX still only sees one compact anchored batch commitment.
- The new verifier-set commitment is the BTX analogue of that signer-set
  boundary:
  - one relayer can submit the batch,
  - while the signed statement already commits to which attestors and threshold
  define validity for that bridge epoch.
- The new verifier-set proof path is the natural continuation of that model:
  - BTX does not need full committee disclosure for each settlement,
  - only compact inclusion witnesses for the specific signers that actually
    appear in the receipt set.

### Prover-Network / zkVM Cost Reference

- Succinct’s current prover-network docs are explicit that competitive proving
  is a hardware-heavy activity, typically involving multi-GPU clusters such as
  L4, L40, 3090, or 4090 fleets.
  - Source:
    `https://docs.succinct.xyz/docs/provers/introduction`
- RISC Zero’s current datasheet publishes directly usable proving-envelope
  numbers. On the current `main` datasheet for Metal on Apple M2 Pro:
  - `rv32im poseidon2 1.00M cycles` is reported at `1m 17s`, `8.87 GB` RAM,
    and `274.54 KB` seal size;
  - recursive `join` and `succinct` stages keep seals around `217.45 KB` in the
    published table.
  - Source:
    `https://reports.risczero.com/main/datasheet`

Implication for BTX:

- Verifying a succinct proof on BTX may be cheap.
- Producing that proof for a high-volume private bridge domain is likely to be
  an operator / prover-network concern, not a commodity CPU task for ordinary
  users or validators.
- That pushes BTX toward a staged roadmap:
  - immediate canonical batch settlement and signed authorizations,
  - then optional committee / DA attachment,
  - then external recursive proofs once a proving market or GPU-backed service
    is justified.
- Succinct’s current SP1 V4 memory-argument paper also describes a multiset
  hash check that is explicitly order-independent.
  - Source:
    `https://docs.succinct.xyz/docs/sp1/resources/memory-argument-paper`

Implication for BTX:

- Order-independent set commitments are a useful future research direction for
  committee or witness sets.
- BTX still prefers Merkle roots today because they support direct membership
  proofs for bridge receipts, which is the immediate operational need.

### Imported Proof Receipt Envelope Reference

- Succinct’s SP1 `v4.0.0` release notes state that the onchain verifier now
  checks the public-values digest for compressed proofs.
  - Source:
    `https://github.com/succinctlabs/sp1/releases/tag/v4.0.0`
- The SP1 SDK docs on `SP1ProofWithPublicValues` expose the same broad
  envelope shape at the SDK layer:
  - one proof object,
  - one public-values object,
  - and versioned proof metadata.
  - Source:
    `https://docs.rs/sp1-sdk/latest/sp1_sdk/provers/struct.SP1ProofWithPublicValues.html`
- RISC Zero’s current `Receipt` docs describe a receipt that carries:
  - a `journal`,
  - a `seal`,
  - and metadata,
  while verification is tied to the expected claim / image identity.
  - Source:
    `https://docs.rs/risc0-zkvm/latest/risc0_zkvm/struct.Receipt.html`
- Nillion Blacklight’s overview describes a verification layer that confirms
  attestation outcomes and produces verifiable reports rather than forcing the
  settlement layer to replay all private execution.
  - Source:
    `https://docs.nillion.com/blacklight/learn/overview`

Implication for BTX:

- The common envelope across SP1, RISC Zero, Blobstream, and Blacklight is not
  “carry the whole proof on L1.”
- It is:
  - bind the batch statement or claim digest,
  - bind the verifier/program identity,
  - bind the public-output digest,
  - and bind one commitment to the proof / seal / receipt artifact.
- That is why the new `BridgeProofReceipt` does not hardcode any one zkVM or
  DA stack. Its fields map cleanly onto:
  - SP1 verifying key hash + public-values digest,
  - RISC Zero image / claim identity + journal / seal commitments,
  - Blobstream-style proof bundle commitments,
  - or Blacklight report commitments.
- This keeps BTX’s current L1 surface small while leaving room for future
  imported-proof verification policies or native verifiers.

### Statement-Bound Proof Policy Reference

- Succinct’s SP1 `v4.0.0` release notes say the onchain verifier path now
  checks the public-values digest for compressed proofs, which reinforces the
  need to bind both verifier identity and public-output identity at the
  settlement boundary.
  - Source:
    `https://github.com/succinctlabs/sp1/releases/tag/v4.0.0`
- The SP1 SDK’s `SP1ProofWithPublicValues` docs keep the same envelope shape:
  - proof bytes,
  - public values,
  - and proof metadata.
  - Source:
    `https://docs.rs/sp1-sdk/latest/sp1_sdk/provers/struct.SP1ProofWithPublicValues.html`
- RISC Zero’s `Receipt` docs similarly describe a receipt whose meaning is
  tied to a verifier/program identity plus published output.
  - Source:
    `https://docs.rs/risc0-zkvm/latest/risc0_zkvm/struct.Receipt.html`
- Celestia’s Blobstream docs remain explicit that current deployments can use
  one proving implementation or another (`SP1 Blobstream` today, RISC Zero as
  an alternative), which is exactly the kind of multi-verifier environment that
  benefits from a statement-bound descriptor allowlist instead of a local
  side-channel policy.
  - Source:
    `https://docs.celestia.org/how-to-guides/blobstream`

Implication for BTX:

- Once imported proofs are in scope, “is the batch valid?” is no longer just a
  yes/no statement about one proof artifact.
- It is also a question of:
  - which proof families are acceptable for this bridge epoch,
  - which verifier/program ids are acceptable,
  - and how many independent receipts or recursive bundles are required.
- That makes a statement-bound proof-policy commitment the right abstraction:
  - BTX signs the policy boundary once,
  - imported proof receipts prove membership against it,
  - and the ordinary settlement path does not have to trust mutable local RPC
    options to know which verifier/program identities were intended.

### Hybrid Committee + Proof Reference

- Agglayer’s current proof-generation docs describe an explicit two-stage
  validation model:
  - native validation first,
  - then zkVM execution over the same inputs,
  - then proof verification and state acceptance.
  - Source:
    `https://docs.agglayer.dev/agglayer/core-concepts/pessimistic-proof/proof-generation/`
- Agglayer’s current `AggchainProofGen` docs also describe a dual-proof
  boundary where a chain can submit state-transition evidence that includes
  both internal-operation verification and bridge-activity verification before
  Agglayer accepts the certificate.
  - Source:
    `https://docs.agglayer.dev/agglayer/core-concepts/aggkit/components/aggchain-proof-gen/`
- Celestia’s current Blobstream docs remain explicit that deployments can use
  one proving stack today (`SP1 Blobstream`) while an alternative prover stack
  (`RISC Zero`) remains available.
  - Source:
    `https://docs.celestia.org/how-to-guides/blobstream`
- The Blobstream operator guide keeps the off-chain roles split:
  - orchestrators / signers observe and attest,
  - while relayers submit onward.
  - Source:
    `https://docs.celestia.org/operate/blobstream/install-binary/`
- RISC Zero’s current prover docs state that proving defaults to a
  `CompositeReceipt` that may contain multiple receipts assembled into segments
  and assumptions, while `InnerReceipt` supports multiple receipt families such
  as `Composite`, `Succinct`, and `Groth16`.
  - Sources:
    `https://docs.rs/risc0-zkvm/latest/risc0_zkvm/trait.Prover.html`
    `https://docs.rs/risc0-zkvm/latest/risc0_zkvm/enum.InnerReceipt.html`
- SP1’s current prover docs describe a staged aggregation pipeline:
  - shard proofs,
  - compression into one shard proof,
  - wrapping into a SNARK-friendly field,
  - then final wrapping into a PLONK proof.
  - Source:
    `https://docs.rs/sp1-prover/latest/sp1_prover/`

Implication for BTX:

- Real bridge / rollup deployments increasingly separate:
  - operator attestations,
  - proof artifacts,
  - and final settlement acceptance.
- BTX should preserve that separation at the commitment layer too.
- A single mixed Merkle tree over heterogeneous witness envelopes would make
  policy downgrade and witness-class ambiguity harder to reason about.
- The new hybrid path instead commits to:
  - one signed-receipt root,
  - one proof-receipt root,
  - and one statement that already binds both the verifier-set policy and the
    imported-proof policy.
- That maps cleanly onto real systems where:
  - one committee or operator set attests that a bridge epoch exists,
  - one proof system attests that the epoch is internally valid,
  - and the settlement chain only needs one compact final anchor.

### Proof Profile And Receipt-Family Reference

- The SP1 SDK’s current `SP1ProofWithPublicValues` docs keep the proof envelope
  split into:
  - the proof object,
  - the public values,
  - and versioned metadata.
  - Source:
    `https://docs.rs/sp1-sdk/latest/sp1_sdk/provers/struct.SP1ProofWithPublicValues.html`
- SP1’s current prover docs describe distinct proof stages and output families:
  - shard proofs,
  - compressed proofs,
  - wrapping,
  - and PLONK / Groth16 wrapping.
  - Source:
    `https://docs.rs/sp1-prover/latest/sp1_prover/`
- RISC Zero’s current `InnerReceipt` docs enumerate distinct receipt families:
  - `Composite`,
  - `Succinct`,
  - `Groth16`,
  - `Fake`,
  - and `Zkr`.
  - Source:
    `https://docs.rs/risc0-zkvm/latest/risc0_zkvm/enum.InnerReceipt.html`
- RISC Zero’s current prover docs say proving returns a `CompositeReceipt` by
  default, which reinforces that “RISC Zero receipt” is not one monolithic
  artifact shape.
  - Source:
    `https://docs.rs/risc0-zkvm/latest/risc0_zkvm/trait.Prover.html`
- Celestia’s Blobstream docs remain explicit that current deployments can use
  `SP1 Blobstream`, while a RISC Zero implementation remains an alternative.
  - Source:
    `https://docs.celestia.org/how-to-guides/blobstream`
- Celestia’s Blobstream proof-query docs also describe a specific public-output
  claim family around shares, row roots, data roots, and the data-root tuple
  root.
  - Source:
    `https://docs.celestia.org/how-to-guides/blobstream/proof-queries`

Implication for BTX:

- “Proof system” is too coarse a unit for a bridge allowlist.
- SP1 Groth16 over one claim family, SP1 compressed over another claim family,
  RISC Zero succinct receipts, and Blobstream SP1 data-root proofs are all
  meaningfully different settlement artifacts even when they share some
  upstream stack.
- BTX therefore benefits from one canonical profile layer:
  - `family_id` says which ecosystem is in play,
  - `proof_type_id` says which proof / receipt family is in play,
  - `claim_system_id` says which public-output schema is in play,
  - and the resulting hashed `proof_system_id` stays compact enough for the
    existing proof-policy and proof-receipt structs.
- BTX also benefits from a second canonical layer over the public outputs
  themselves:
  - one claim family for batch settlement metadata,
  - one for batch-only tuples,
  - and one for Blobstream-style data-root tuples,
  so imported proofs can bind to explicit BTX semantics instead of opaque
  bridge-local digests.

### Proof Adapter Template Reference

- The current SP1 SDK exposes a versioned proof envelope whose proof variant is
  one of:
  - `Core`,
  - `Compressed`,
  - `Plonk`,
  - or `Groth16`.
  - Sources:
    `https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/struct.SP1ProofWithPublicValues.html`
    `https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/enum.SP1Proof.html`
- RISC Zero’s current `InnerReceipt` docs enumerate distinct receipt families
  including:
  - `Composite`,
  - `Succinct`,
  - and `Groth16`,
  while the prover docs still describe proving as starting from a
  `CompositeReceipt`.
  - Sources:
    `https://docs.rs/risc0-zkvm/latest/risc0_zkvm/enum.InnerReceipt.html`
    `https://docs.rs/risc0-zkvm/latest/risc0_zkvm/trait.Prover.html`
- Celestia’s current Blobstream docs keep proof queries centered on the
  `DataRootTuple` inclusion path and still describe `SP1 Blobstream` alongside a
  RISC Zero alternative.
  - Sources:
    `https://docs.celestia.org/how-to-guides/blobstream`
    `https://docs.celestia.org/how-to-guides/blobstream/proof-queries`
- Nillion’s current docs describe Blacklight as the verification layer of the
  Blind Computer rather than as one more monolithic L1 transaction format.
  - Source:
    `https://docs.nillion.com/blacklight/learn/overview`

Implication for BTX:

- The adapter layer should name the externally recognizable proof family
  directly.
- That means the canonical BTX selector space should look like:
  - `sp1-compressed-*`,
  - `sp1-plonk-*`,
  - `sp1-groth16-*`,
  - `risc0-zkvm-composite-*`,
  - `risc0-zkvm-succinct-*`,
  - `risc0-zkvm-groth16-*`,
  - or Blobstream-specific data-root adapters,
  not one generic “succinct proof” bucket.
- BTX still keeps the imported-proof receipt compact because the adapter only
  chooses the family and claim semantics:
  - the receipt envelope stays a compact commitment,
  - while the heavy proof bytes remain off-chain.

### Proof Artifact Storage Reference

- The current SP1 SDK keeps the proof bytes and the public values in one
  versioned envelope, but they are still separate payloads with distinct sizes
  and downstream transport costs.
  - Sources:
    `https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/struct.SP1ProofWithPublicValues.html`
    `https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/enum.SP1Proof.html`
- RISC Zero likewise documents multiple receipt families and a proving flow
  whose artifact metadata is not reducible to one opaque proof blob.
  - Sources:
    `https://docs.rs/risc0-zkvm/latest/risc0_zkvm/enum.InnerReceipt.html`
    `https://docs.rs/risc0-zkvm/latest/risc0_zkvm/trait.Prover.html`
- Ethereum’s current zk-rollup documentation and EIP-4844 continue to separate
  succinct settlement commitments from the larger data / proof availability
  surface.
  - Sources:
    `https://ethereum.org/en/developers/docs/scaling/zk-rollups/`
    `https://eips.ethereum.org/EIPS/eip-4844`
- Celestia’s Blobstream proof-query flow is similarly organized around
  committing to a typed tuple and keeping the heavier inclusion machinery
  outside the settlement-facing commitment.
  - Sources:
    `https://docs.celestia.org/how-to-guides/blobstream`
    `https://docs.celestia.org/how-to-guides/blobstream/proof-queries`
- Nillion’s current Blacklight description still frames the system as a
  verification layer rather than one more monolithic L1 payload format.
  - Source:
    `https://docs.nillion.com/blacklight/learn/overview`

Implication for BTX:

- BTX should model imported proofs as two layers:
  - one compact canonical L1-facing descriptor / receipt surface,
  - plus one explicit off-chain artifact summary carrying byte counts and a
    bundle commitment.
- That keeps settlement compact while finally giving BTX a stable place to
  measure storage growth and archival replay costs for real imported proofs.

### Agglayer / Pessimistic-Proof Reference

- Agglayer documents a two-stage proving model:
  - native execution first,
  - then the same program in a zkVM,
  - then proof verification and state acceptance.
  - Source:
    `https://docs.agglayer.dev/agglayer/core-concepts/pessimistic-proof/proof-generation/`
- Agglayer also frames pessimistic proofs as blast-radius containment:
  even if one prover is unsound, loss is limited to that chain’s deposited
  funds.
  - Source:
    `https://docs.agglayer.dev/agglayer/core-concepts/pessimistic-proof/`
- Their benchmark notes are directly relevant to BTX CPU / GPU planning:
  - 75%+ of computation is Keccak,
  - performance varies materially across zkVMs,
  - GPU acceleration matters,
  - production currently standardizes on SP1 + Succinct’s prover network.
  - Source:
    `https://docs.agglayer.dev/agglayer/core-concepts/pessimistic-proof/benchmarks/`

Implication for BTX:

- Any BTX recursive-proof or validity-rollup path needs an explicit proving
  cost model, not just a byte-size target.
- Hash-heavy trace design will strongly influence whether proving is practical
  on commodity CPUs or needs GPU-backed prover infrastructure.

### Current Prover Supply Surfaces

- The current SP1 SDK exposes distinct proving backends rather than one
  monolithic execution mode:
  - a configurable client builder,
  - a CUDA proving path,
  - and a separate network prover surface;
  proof envelopes also keep proof bytes and public values distinct.
  - Sources:
    `https://docs.rs/sp1-sdk/latest/sp1_sdk/client/struct.ProverClientBuilder.html`
    `https://docs.rs/sp1-sdk/latest/sp1_sdk/network/struct.NetworkProver.html`
    `https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/struct.SP1ProofWithPublicValues.html`
- RISC Zero’s current docs similarly distinguish local proving, proving
  acceleration choices, and receipt families instead of treating proof
  generation as one generic CPU-bound step.
  - Sources:
    `https://dev.risczero.com/api/generating-proofs/local-proving`
    `https://dev.risczero.com/api/latest/generating-proofs/proving-options`
    `https://docs.rs/risc0-zkvm/latest/risc0_zkvm/enum.InnerReceipt.html`
- Nillion’s current Blacklight overview still describes the system as a
  verification layer over external computation, not as another place to dump
  large monolithic settlement payloads.
  - Source:
    `https://docs.nillion.com/blacklight/learn/overview`

Implication for BTX:

- BTX should explicitly model proving supply as a separate resource from L1
  settlement bytes.
- The bridge layer needs a way to answer:
  - whether compact settlement can be sustained by local CPUs,
  - whether GPUs are enough,
  - and when a remote prover market or operator network is the only lane that
    actually keeps up with settlement demand.
- Any cost figures in the estimator should therefore be treated as scenario
  inputs tied to a chosen operator model, not as hard-coded facts about one
  vendor or one zkVM.

### Current Proof-Family Multiplexing

- SP1’s current proof docs expose several proof families under one SDK surface,
  including compressed, Plonk, and Groth16 outputs.
  - Source:
    `https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/enum.SP1Proof.html`
- RISC Zero’s current receipt docs likewise expose multiple receipt families
  under one verifier-facing type.
  - Source:
    `https://docs.rs/risc0-zkvm/latest/risc0_zkvm/enum.InnerReceipt.html`
- Celestia’s current Blobstream proof-query flow still centers on typed data
  tuples and external inclusion proof machinery rather than one monolithic
  on-chain payload.
  - Sources:
    `https://docs.celestia.org/how-to-guides/blobstream`
    `https://docs.celestia.org/how-to-guides/blobstream/proof-queries`

Implication for BTX:

- BTX should track imported proving costs at the artifact level, not only as
  one settlement-wide manual number.
- A canonical prover sample / profile layer is the right place to preserve
  which artifact mix produced a settlement-wide timing estimate while keeping
  the L1 settlement surface unchanged.

### Penumbra Reference

- Penumbra keeps value in one shielded pool, stores commitments in a state
  commitment tree, and proves spends / outputs against that tree.
  - Source:
    `https://protocol.penumbra.zone/main/shielded_pool.html`

Implication for BTX:

- A shielded system should try to minimize what becomes explicit L1 state and
  avoid publishing more per-user information than necessary.

## Implemented In This Pass

- `src/shielded/bridge.h`
- `src/shielded/bridge.cpp`
  - Added canonical bridge batch leaf / batch commitment types.
  - Added canonical batch leaf hashing and Merkle-root computation.
  - Added canonical batch commitment serialization / hashing helpers.
  - Extended bridge attestation format with version 2 fields for batch root,
    entry count, and total amount.
- `src/wallet/bridge_wallet.h`
- `src/wallet/bridge_wallet.cpp`
  - Added wallet plan support for optional batch commitments.
  - Added multi-payout bridge-out plan support using the existing vector output
    model already present in `BridgePlan`.
- `src/wallet/shielded_rpc.cpp`
  - Added RPC plumbing for batch commitment hex on bridge planning flows.
  - Added `bridge_planbatchout`.
  - Added `bridge_planbatchin`.
  - Added `bridge_buildverifierset`.
  - Added `bridge_buildproofprofile`.
  - Added `bridge_decodeproofprofile`.
  - Added `bridge_listproofadapters`.
  - Added `bridge_buildproofadapter`.
  - Added `bridge_decodeproofadapter`.
  - Added `bridge_buildproofartifact`.
  - Added `bridge_decodeproofartifact`.
  - Added `bridge_estimatecapacity`.
  - Added `bridge_buildproofclaim`.
  - Added `bridge_decodeproofclaim`.
  - Added `bridge_buildbatchstatement`.
  - Added `bridge_signbatchreceipt`.
  - Added `bridge_decodebatchreceipt`.
  - Added `bridge_buildproofreceipt`.
  - Added `bridge_decodeproofreceipt`.
  - Added `bridge_buildproofpolicy`.
  - Added `bridge_buildproofanchor`.
  - Added `bridge_buildhybridanchor`.
  - Added `bridge_buildexternalanchor`.
  - Added `bridge_signbatchauthorization`.
  - Added `bridge_decodebatchauthorization`.
  - Added `bridge_buildbatchcommitment`.
  - Added `bridge_decodebatchcommitment`.
- `src/wallet/rpc/wallet.cpp`
- `src/rpc/client.cpp`
  - Registered the new bridge RPCs and CLI argument conversion entries.
- `src/test/shielded_bridge_tests.cpp`
- `src/wallet/test/bridge_wallet_tests.cpp`
- `test/functional/test_framework/bridge_utils.py`
- `test/functional/wallet_bridge_batch_commitment.py`
- `test/functional/wallet_bridge_batch_in.py`
- `test/functional/wallet_bridge_batch_anchor.py`
- `test/functional/wallet_bridge_batch_receipt.py`
- `test/functional/wallet_bridge_proof_receipt.py`
- `test/functional/wallet_bridge_proof_profile.py`
- `test/functional/wallet_bridge_proof_adapter.py`
- `test/functional/wallet_bridge_proof_artifact.py`
- `test/functional/wallet_bridge_capacity_estimate.py`
- `test/functional/wallet_bridge_proof_claim.py`
- `test/functional/wallet_bridge_verifier_set.py`
- `test/functional/wallet_bridge_hybrid_anchor.py`
- `test/functional/create_cache.py`
- `test/functional/test_runner.py`
- `src/bench/CMakeLists.txt`
- `src/bench/bridge_batch_bench.cpp`
  - Added unit coverage for batch roots, batch commitments, attestation v2, and
    multi-payout bridge-out planning.
  - Added generic external anchor support on batch commitments and attestation
    v3 for DA / proof references.
  - Added canonical bridge batch statements and signed bridge batch receipts.
  - Added canonical verifier-set commitments and statement `version = 2`.
  - Added canonical verifier-set membership proofs and proof generation for
    selected signer subsets.
  - Added canonical proof-system profiles so imported-proof family ids can be
    derived deterministically from named profile labels.
  - Added canonical proof adapters so imported-proof profile families and BTX
    claim kinds can be selected from one stable object.
  - Added canonical proof artifacts so imported-proof bundles can carry
    explicit byte counts and one stable artifact commitment while still
    regenerating the existing compact descriptor / receipt surfaces.
  - Added canonical bridge capacity footprints and block-fit estimation so
    measured settlement tx sizes, bridge control-plane bytes, and off-chain
    proof storage can be compared inside one reusable model.
  - Added canonical proof claims so imported-proof public outputs can be
    derived deterministically from statement-bound BTX batch metadata.
  - Added canonical proof-policy commitments and compact descriptor membership
    proofs for imported proof receipts.
  - Added canonical verification-bundle hashing so one external anchor can
    commit to both signed receipts and imported proof receipts simultaneously.
  - Added unit coverage for signed batch authorizations and canonical
    authorization hashing.
  - Added unit coverage for:
    - statement hashing,
    - receipt hashing,
    - receipt-root order independence,
    - duplicate-attestor rejection,
    - verifier-set root order independence,
    - verifier-set duplicate rejection,
    - verifier-set proof round-trips,
    - verifier-set proof rejection for the wrong attestor,
    - statement v2 round-trips with verifier-set commitments,
    - and statement/receipt to external-anchor derivation.
  - Added functional coverage for:
    - wallet-signed authorizations,
    - commitment building from signed authorizations,
    - batch commitment decoding,
    - batch bridge-in planning from signed authorizations,
    - anchored batch commitments and anchored attestation decoding,
    - receipt-backed anchor building with required-attestor policy,
    - verifier-set commitment building,
    - statement-bound committee threshold enforcement,
    - and receipt membership checks against committed verifier sets,
    - compact proof-backed verifier-set membership,
    - proof-backed imported-receipt membership against statement-bound proof
      policy,
    - proof-profile-backed imported receipts for SP1-, RISC Zero-, and
      Blobstream-style families,
    - proof-artifact-backed descriptor and receipt regeneration,
    - proof-anchor derivation from proof-artifact-backed receipts,
    - finalized single-vs-batch-vs-proof-anchored bridge settlement capacity
      estimation,
    - hybrid committee-plus-proof external anchors with compact membership
      proofs on both sides,
    - bridge batch-out planning,
    - one-batch vs many-single size comparisons.
  - Added benchmark coverage for:
    - batch-root hashing throughput,
    - verifier-set root hashing throughput,
    - verifier-set proof verification throughput,
    - ML-DSA-44 authorization verification,
    - SLH-DSA-128s authorization verification,
    - attestation hash cost with and without anchored DA / proof fields,
    - external-anchor derivation cost from signed receipt sets,
    - external-anchor derivation cost from imported proof receipts,
    - proof-artifact hashing and artifact-id derivation,
    - proof-adapter hashing from canonical adapter templates,
    - proof-system-id hashing from canonical proof profiles,
    - and hybrid verification-bundle hashing / hybrid-anchor derivation.

## Key Design Decisions

- Canonical batch roots should not depend on randomized PQ signature bytes.
  Therefore the leaf `authorization_hash` is derived from the authorization
  message, not the full signed envelope.
- The signed envelope still matters operationally:
  - `bridge_buildbatchcommitment` verifies the signature before accepting the
    authorization and deriving the canonical leaf.
- This separation keeps:
  - the batch tree stable,
  - the user consent verifiable,
  - and the bridge free to archive or relay the larger signed objects
  off-chain.
- `bridge_planbatchin` keeps the bridge-in surface symmetric with batch-out:
  - the canonical batch commitment is built once,
  - the total amount is derived from the leaves,
  - and the resulting shielded settlement note can represent many off-chain
    credits for identities that do not yet exist as L1 note owners.
- External proof / DA metadata should be generic hashes, not protocol-specific
  typed fields:
  - BTX needs a stable settlement boundary first,
  - while bridge domains remain free to interpret the anchor as Celestia
    availability data, a Nillion verification transcript, a RISC Zero receipt,
    an SP1 proof commitment, or a committee root.
- The committee / prover layer should sign a pre-anchor statement, not the
  final external anchor:
  - otherwise `verification_root` would depend on receipts that themselves
    signed a structure containing that root.
- Receipt roots are canonicalized by sorting receipt leaf hashes before
  Merkleization:
  - relayer order does not perturb the anchor,
  - while duplicate attestors are rejected so one signer cannot inflate the
    witness set.
- Committee membership policy belongs at the anchor-construction boundary:
  - BTX core can keep `verification_root` generic,
  - while RPC and bridge software enforce minimum receipts and required
    attestors for a specific bridge domain.
- Once committee policy becomes part of the signed statement, it should be
  committed by hash rather than fully embedded:
  - statement `version = 2` carries one compact verifier-set commitment,
  - while the full attestor list stays off-chain and is only revealed when the
    anchor builder validates membership.
- This keeps BTX aligned with modular bridge designs:
  - compact on-chain or settlement-facing commitments,
  - richer off-chain verifier metadata,
  - and a clean upgrade path to zk receipts later.
- For bridge receipts, Merkle membership proofs are the right near-term choice:
  - they remove full committee disclosure from the hot path,
  - they are trivial compared with PQ verification cost,
  - and they match how modular bridge systems like Blobstream already verify
    compact commitments with proof paths.
- Hybrid statements must not be accepted by the pure committee-only or
  proof-only builders:
  - otherwise a bridge could accidentally or maliciously strip one half of the
    intended validity boundary at anchor-construction time.
- The hybrid `verification_root` should commit to two typed sub-roots rather
  than flattening all witnesses into one heterogeneous tree:
  - committee receipts and imported proof receipts have different trust and
    performance characteristics,
  - keeping them separate makes policy enforcement explicit,
  - and the extra bundle hash cost is negligible.
- Imported-proof families need a canonical naming layer before they can safely
  participate in statement-bound policy:
  - otherwise every bridge stack would invent its own local `proof_system_id`
    convention,
  - which would make proof-policy reuse brittle across SP1, RISC Zero,
    Blobstream, and future imported-proof adapters.
- The new proof-profile layer keeps that naming problem off the settlement hot
  path:
  - a compact hashed `proof_system_id` still sits in receipts and descriptors,
  - but bridges can now derive it deterministically from
  `(family, proof_type, claim_system)`.
- Imported-proof byte accounting should also be canonicalized instead of left
  in bridge-local logs:
  - the receipt remains compact,
  - but the off-chain artifact manifest needs one stable hash and stable byte
    counters so BTX can compare storage and replay costs across proof systems.
- Capacity modeling must distinguish three different cost surfaces:
  - actual L1 bytes / weight,
  - auxiliary bridge control-plane bytes,
  - and off-chain proof / artifact storage.
- Without that separation, a rollup-style design can look artificially cheap
  or artificially expensive depending on which layer of the settlement stack is
  counted.

## Experiment Log

### 2026-03-14 1

- Confirmed current bridge code exists and is functional.
- Confirmed current bridge layer does not yet standardize batch roots or
  aggregated settlement reports.
- Rebuilt `build-btx` test binary.
- Re-ran targeted unit tests:
  - `shielded_bridge_tests`
  - `bridge_wallet_tests`
  - `shielded_transaction_tests`
  - `ringct_range_proof_tests/serialized_size_is_compact`
  - `ringct_matrict_tests/proof_size_target_for_2in_2out`

### 2026-03-14 2

- Implemented canonical bridge batch commitments and versioned bridge
  attestations.
- Added wallet support for:
  - aggregated bridge-in commitments embedded as canonical note memos,
  - aggregated bridge-out commitments bound into attestation v2,
  - multiple transparent payouts in a single bridge-out plan.
- Added RPC support for building / decoding batch commitments and for creating a
  batch bridge-out plan.
- Rebuilt `test_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests`
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests`
  - `./build-btx/bin/test_btx --run_test=ringct_range_proof_tests/serialized_size_is_compact --log_level=message`
  - `./build-btx/bin/test_btx --run_test=ringct_matrict_tests/proof_size_target_for_2in_2out --log_level=message`

### 2026-03-14 3

- No DigitalOcean infrastructure was created in this pass.
- Reason:
  - local unit / serialization / proof-size work was sufficient for the first
    implementation slice,
  - bridge batch commitments are deterministic code-path changes and do not yet
    require remote cluster benchmarking.

### 2026-03-14 4

- Added canonical signed bridge batch authorizations.
- Added direct wallet RPC signing using a wallet-owned P2MR PQ key.
- Added batch commitment support for `authorization_hex` entries so bridges can
  build canonical roots directly from signed user authorizations.
- Rebuilt `bitcoind` and `test_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_batch_commitment.py --descriptors --configfile=test/config.ini`
- Measured on regtest for 3 payouts:
  - three single plans: `17316` bytes total plan serialization
  - one batch plan: `5902` bytes
  - three single attestations: `402` bytes total
  - one batch attestation: `178` bytes
  - three single bridge-unshield PSBTs: `9177` bytes total
  - one batch bridge-unshield PSBT: `3191` bytes
- Compression observed in the practical bridge-out path:
  - plan surface: about `2.93x`
  - attestation surface: about `2.26x`
  - PSBT surface: about `2.88x`
- `test_runner.py wallet_bridge_batch_commitment.py --descriptors` currently
  trips a pre-existing runner/cache mismatch in this repo because
  `create_cache.py` does not accept `--descriptors`; direct execution of the
  functional test succeeded.

### 2026-03-14 5

- Added `bridge_planbatchin` so the wallet can build one deterministic
  aggregated bridge-in settlement from many canonical leaves or signed
  authorizations.
- Reused the existing bridge-in plan builder rather than introducing a second
  settlement encoding.
- Added direct functional coverage in
  `test/functional/wallet_bridge_batch_in.py`.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_batch_commitment.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_batch_in.py --descriptors --configfile=test/config.ini`
- Measured on regtest for 3 bridge-in credits:
  - three single bridge-in plans: `20646` bytes total plan serialization
  - one batch bridge-in plan: `6992` bytes
  - three single bridge-in shield PSBTs: `8508` bytes total
  - one batch bridge-in shield PSBT: `2946` bytes
- Compression observed in the practical bridge-in path:
  - plan surface: about `2.95x`
  - PSBT surface: about `2.89x`

### 2026-03-14 6

- Added `src/bench/bridge_batch_bench.cpp` and measured the canonical batch
  settlement primitives directly.
- `./build-btx/bin/bench_btx -filter='BridgeBatch.*' -min-time=50` reported:
  - `BridgeBatchRoot32`: `252.99 ns/leaf`
  - `BridgeBatchRoot256`: `248.02 ns/leaf`
  - `BridgeBatchAuthorizationVerifyMLDSA44`: `54,300.40 ns/op`
  - `BridgeBatchAuthorizationVerifySLHDSA128S`: `208,221.68 ns/op`
- Existing bare PQ verification microbenchmarks remain:
  - `bench_mldsa_verify`: `53,375.00 ns/op`
  - `bench_slhdsa_verify`: `206,238.07 ns/op`
- Conclusion:
  - canonical leaf hashing and Merkle-root construction are cheap relative to
    proof generation and even relative to PQ verification;
  - authorization verification overhead is effectively just the underlying PQ
    signature verification cost, which is the right shape for an L1 settlement
    boundary.

### 2026-03-14 7

- Added `BridgeExternalAnchor` and propagated it through:
  - batch commitment v2,
  - bridge-in memo-bound batch commitments,
  - and bridge-out attestation v3.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_batch_commitment.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_batch_in.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_batch_anchor.py --descriptors --configfile=test/config.ini`
- Deterministic anchored serialization sizes observed:
  - anchored batch commitment: `211` bytes
  - anchored bridge-out attestation: `279` bytes
- `./build-btx/bin/bench_btx -filter='BridgeBatch.*|BridgeAttestationHashV[23]' -min-time=50`
  reported:
  - `BridgeBatchRoot32`: `258.14 ns/leaf`
  - `BridgeBatchRoot256`: `260.15 ns/leaf`
  - `BridgeBatchAuthorizationVerifyMLDSA44`: `62,378.87 ns/op`
  - `BridgeBatchAuthorizationVerifySLHDSA128S`: `215,257.59 ns/op`
  - `BridgeAttestationHashV2`: `217.07 ns/op`
  - `BridgeAttestationHashV3`: `273.22 ns/op`
- Existing bare PQ verification microbenchmarks on the same run remained:
  - `bench_mldsa_verify`: `61,000.00 ns/op`
  - `bench_slhdsa_verify`: `215,325.00 ns/op`
- Conclusion:
  - adding the external DA / proof anchor increases the attestation hash path
    by only about `1.26x`;
  - that cost is negligible beside PQ verification and utterly negligible
  beside any realistic zk proof generation path;
  - so BTX can afford to bind external replay / proof references directly into
    its bridge settlement messages.

### 2026-03-14 8

- Added canonical `BridgeBatchStatement` and signed `BridgeBatchReceipt`
  support, plus `bridge_buildexternalanchor` verifier-policy inputs.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_batch_receipt.py --descriptors --configfile=test/config.ini`
- Deterministic receipt-backed serialization sizes observed:
  - statement: `178` bytes
  - receipt: `3918` bytes
- Functional verifier-policy checks now confirm:
  - duplicate attestors are rejected,
  - and missing required attestors are rejected.
- `./build-btx/bin/bench_btx -filter='BridgeBatch.*|BridgeAttestationHashV[23]|BridgeExternalAnchorFromReceipts8MLDSA44' -min-time=50`
  reported:
  - `BridgeAttestationHashV2`: `206.43 ns/op`
  - `BridgeAttestationHashV3`: `251.11 ns/op`
  - `BridgeBatchAuthorizationVerifyMLDSA44`: `53,400.38 ns/op`
  - `BridgeBatchAuthorizationVerifySLHDSA128S`: `193,653.85 ns/op`
  - `BridgeBatchRoot256`: `256.89 ns/leaf`
  - `BridgeBatchRoot32`: `261.97 ns/leaf`
  - `BridgeExternalAnchorFromReceipts8MLDSA44`: `111,052.95 ns/receipt`
- Conclusion:
  - receipt-backed committee witnesses are still cheap relative to any serious
    zk proving workload;
  - most of the verifier-side cost is still just PQ signature verification;
  - and BTX now has a concrete path for one relayer to submit a batch
    settlement on behalf of many users while binding a bounded verifier set.

### 2026-03-14 9

- Added `BridgeVerifierSetCommitment`, statement `version = 2`, and
  `bridge_buildverifierset`.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_batch_receipt.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_verifier_set.py --descriptors --configfile=test/config.ini`
- Deterministic verifier-set statement size observed:
  - statement with committed verifier set: `219` bytes
- Functional verifier-set checks now confirm:
  - statement-bound threshold enforcement,
  - receipt attestor membership checks against the committed verifier set,
  - and backward compatibility for the older statement `version = 1` receipt
    path.
- `./build-btx/bin/bench_btx -filter='BridgeBatch.*|BridgeVerifierSetRoot32MLDSA44|BridgeAttestationHashV[23]|BridgeExternalAnchorFromReceipts8MLDSA44' -min-time=50`
  reported:
  - `BridgeAttestationHashV2`: `208.78 ns/op`
  - `BridgeAttestationHashV3`: `255.97 ns/op`
  - `BridgeBatchAuthorizationVerifyMLDSA44`: `53,138.42 ns/op`
  - `BridgeBatchAuthorizationVerifySLHDSA128S`: `208,041.65 ns/op`
  - `BridgeBatchRoot256`: `257.51 ns/leaf`
  - `BridgeBatchRoot32`: `252.92 ns/leaf`
  - `BridgeExternalAnchorFromReceipts8MLDSA44`: `110,764.38 ns/receipt`
  - `BridgeVerifierSetRoot32MLDSA44`: `988.38 ns/attestor`
- Conclusion:
  - verifier-set commitment construction is negligible beside PQ verification;
  - BTX can canonically bind committee size and threshold without materially
    changing the performance profile of the anchored settlement path;
  - the next scalability gap is no longer “how do we represent a committee,”
    but “how do we avoid revealing full verifier sets or full proof receipts
    when stronger proof systems arrive.”

### 2026-03-14 10

- Added `BridgeVerifierSetProof` and extended `bridge_buildverifierset` to emit
  proofs for selected attestors.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_verifier_set.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_batch_receipt.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_batch_anchor.py --descriptors --configfile=test/config.ini`
- Deterministic proof-backed verifier-set surfaces observed:
  - statement with committed verifier set: `219` bytes
  - verifier-set membership proof: `70` bytes
- Functional verifier-set checks now confirm:
  - one proof per receipt can replace full verifier-set disclosure,
  - proof verification fails for the wrong attestor,
  - and the older `revealed_attestors` path still works as a compatibility
    fallback.
- `./build-btx/bin/bench_btx -filter='BridgeBatch.*|BridgeVerifierSetRoot32MLDSA44|BridgeVerifierSetProofVerify32MLDSA44|BridgeAttestationHashV[23]|BridgeExternalAnchorFromReceipts8MLDSA44' -min-time=50`
  reported:
  - `BridgeAttestationHashV2`: `211.51 ns/op`
  - `BridgeAttestationHashV3`: `251.58 ns/op`
  - `BridgeBatchAuthorizationVerifyMLDSA44`: `53,364.80 ns/op`
  - `BridgeBatchAuthorizationVerifySLHDSA128S`: `209,947.00 ns/op`
  - `BridgeBatchRoot256`: `261.74 ns/leaf`
  - `BridgeBatchRoot32`: `253.15 ns/leaf`
  - `BridgeExternalAnchorFromReceipts8MLDSA44`: `111,401.49 ns/receipt`
  - `BridgeVerifierSetRoot32MLDSA44`: `995.59 ns/attestor`
  - `BridgeVerifierSetProofVerify32MLDSA44`: `1,406.63 ns/op`
- Conclusion:
  - compact verifier-set membership proofs are cheap enough to sit directly in
    the bridge settlement path;
  - the disclosure burden is now on the specific signers rather than on the
    entire committee;
  - and BTX has a cleaner bridge boundary for later zk receipt imports because
    committee verification no longer requires full-set replay.

### 2026-03-14 11

- Added canonical `BridgeProofReceipt` support plus:
  - `bridge_buildproofreceipt`,
  - `bridge_decodeproofreceipt`,
  - `bridge_buildproofanchor`.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_proof_receipt.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_batch_receipt.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_verifier_set.py --descriptors --configfile=test/config.ini`
- Deterministic imported-proof surfaces observed:
  - statement: `178` bytes
  - proof receipt: `161` bytes
- Functional proof-receipt checks now confirm:
  - one bridge batch statement can be referenced by multiple imported proof
    receipts without replaying the full statement per receipt,
  - duplicate proof receipts are rejected,
  - required proof-system ids and verifier-key hashes can be enforced locally,
  - and the resulting proof-backed external anchor feeds directly into the
    existing bridge-out commitment and attestation flow.
- `./build-btx/bin/bench_btx -filter='BridgeProofReceiptRoot8|BridgeExternalAnchorFromProofReceipts8|BridgeExternalAnchorFromReceipts8MLDSA44|BridgeVerifierSetProofVerify32MLDSA44|BridgeAttestationHashV[23]' -min-time=50`
  reported:
  - `BridgeAttestationHashV2`: `208.34 ns/op`
  - `BridgeAttestationHashV3`: `254.35 ns/op`
  - `BridgeExternalAnchorFromProofReceipts8`: `1,322.25 ns/receipt`
  - `BridgeExternalAnchorFromReceipts8MLDSA44`: `111,036.89 ns/receipt`
  - `BridgeProofReceiptRoot8`: `651.94 ns/receipt`
  - `BridgeVerifierSetProofVerify32MLDSA44`: `1,417.91 ns/op`
- Conclusion:
  - the imported proof-receipt envelope is about `24x` smaller than the
    current signed committee receipt (`161` bytes vs `3918` bytes in the
    existing functional path);
  - anchor derivation from imported proof receipts is about `84x` cheaper than
    the signed-receipt path because it avoids PQ signature verification on the
    settlement boundary;
  - and BTX now has a concrete, reusable place to hang future SP1, RISC Zero,
    Blobstream, or Blacklight receipt imports without forcing consensus to
    absorb their full artifact formats.

### 2026-03-14 12

- Added canonical imported-proof policy commitments plus:
  - `BridgeProofDescriptor`,
  - `BridgeProofPolicyCommitment`,
  - `BridgeProofPolicyProof`,
  - and `bridge_buildproofpolicy`.
- Extended `bridge_buildbatchstatement` so proof-backed statements can bind the
  descriptor policy directly:
  - `version = 3` for proof policy only,
  - `version = 4` when both verifier-set and proof-policy commitments are
    present.
- Extended `bridge_buildproofanchor` so a statement-bound proof policy can be
  enforced via:
  - `descriptor_proofs` as the compact path,
  - or `revealed_descriptors` as the fallback path.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_proof_receipt.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_batch_receipt.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_verifier_set.py --descriptors --configfile=test/config.ini`
- Deterministic proof-policy-backed surfaces observed:
  - statement with bound proof policy: `260` bytes
  - proof receipt: `161` bytes
  - descriptor proof: `38` bytes
- Functional proof-policy checks now confirm:
  - imported proof acceptance can be determined from the signed statement plus
    one compact proof per receipt,
  - missing descriptor proofs are rejected,
  - wrong descriptors fail membership checks,
  - and the older full-set disclosure path still works as a compatibility
    fallback.
- `./build-btx/bin/bench_btx -filter='BridgeProofPolicyRoot32|BridgeProofPolicyProofVerify32|BridgeProofReceiptRoot8|BridgeExternalAnchorFromProofReceipts8|BridgeVerifierSetProofVerify32MLDSA44|BridgeExternalAnchorFromReceipts8MLDSA44' -min-time=50`
  reported:
  - `BridgeExternalAnchorFromProofReceipts8`: `1,361.22 ns/receipt`
  - `BridgeExternalAnchorFromReceipts8MLDSA44`: `121,835.57 ns/receipt`
  - `BridgeProofPolicyProofVerify32`: `661.49 ns/op`
  - `BridgeProofPolicyRoot32`: `220.22 ns/descriptor`
  - `BridgeProofReceiptRoot8`: `690.84 ns/receipt`
  - `BridgeVerifierSetProofVerify32MLDSA44`: `1,408.01 ns/op`
- Conclusion:
  - binding the imported-proof allowlist into the signed statement only grows
    the statement by `82` bytes relative to the prior proof-only statement;
  - descriptor proofs are materially smaller than verifier-set proofs
    (`38` bytes vs `70` bytes in the current functional paths) because the leaf
    payload is just `(proof_system_id, verifier_key_hash)`;
  - and BTX now has the same architectural property for imported proof
    verifiers that it already has for committee signers:
    settlement policy is canonical, signed, and membership-checkable.

### 2026-03-14 13

- Added canonical `BridgeVerificationBundle` plus:
  - `BuildBridgeExternalAnchorFromHybridWitness`,
  - and `bridge_buildhybridanchor`.
- Hardened the pure anchor builders so they reject hybrid statements:
  - `bridge_buildexternalanchor` now rejects statements with a committed
    `proof_policy`,
  - `bridge_buildproofanchor` now rejects statements with a committed
    `verifier_set`.
- Added nested hybrid policy validation so the hybrid RPC can enforce:
  - attestor membership proofs or full verifier-set disclosure,
  - descriptor membership proofs or full proof-policy disclosure,
  - minimum receipt counts on both witness classes,
  - duplicate-attestor rejection,
  - and duplicate imported-proof rejection.
- Added direct functional coverage in
  `test/functional/wallet_bridge_hybrid_anchor.py`.
- Registered:
  - `wallet_bridge_proof_receipt.py --descriptors`,
  - and `wallet_bridge_hybrid_anchor.py --descriptors`
  in `test/functional/test_runner.py`.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_hybrid_anchor.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_proof_receipt.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_batch_receipt.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_verifier_set.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_batch_anchor.py --descriptors --configfile=test/config.ini`
- Deterministic hybrid surfaces observed:
  - statement with committed verifier set and proof policy: `260` bytes
  - signed receipt over that statement: `4000` bytes
  - imported proof receipt: `161` bytes
  - attestor membership proof: `70` bytes
  - descriptor membership proof: `38` bytes
- `./build-btx/bin/bench_btx -filter='BridgeVerificationBundleHash|BridgeExternalAnchorFromHybridWitness8|BridgeProofPolicyRoot32|BridgeProofPolicyProofVerify32|BridgeProofReceiptRoot8|BridgeExternalAnchorFromProofReceipts8|BridgeVerifierSetRoot32MLDSA44|BridgeVerifierSetProofVerify32MLDSA44|BridgeExternalAnchorFromReceipts8MLDSA44' -min-time=50`
  reported:
  - `BridgeExternalAnchorFromHybridWitness8`: `58,367.32 ns/witness`
  - `BridgeExternalAnchorFromProofReceipts8`: `1,430.97 ns/receipt`
  - `BridgeExternalAnchorFromReceipts8MLDSA44`: `115,401.75 ns/receipt`
  - `BridgeProofPolicyProofVerify32`: `679.84 ns/op`
  - `BridgeProofPolicyRoot32`: `224.61 ns/descriptor`
  - `BridgeProofReceiptRoot8`: `670.64 ns/receipt`
  - `BridgeVerificationBundleHash`: `340.91 ns/op`
  - `BridgeVerifierSetProofVerify32MLDSA44`: `1,409.76 ns/op`
  - `BridgeVerifierSetRoot32MLDSA44`: `1,013.82 ns/attestor`
- Conclusion:
  - the hybrid path preserves the same economic shape as the earlier slices:
    the signed committee half is still the expensive part, while the imported
    proof half and the final bundle hash are tiny by comparison;
  - hybrid acceptance therefore scales as “committee verification cost plus a
    very small extra root / bundle cost,” not as a fundamentally new verifier
    bottleneck;
  - and BTX now has a concrete settlement boundary for bridges that want both:
    an operator / committee quorum,
    and imported succinct proof receipts,
    under one final `verification_root`.

### 2026-03-14 14

- Added canonical `BridgeProofSystemProfile` plus:
  - `bridge_buildproofprofile`,
  - and `bridge_decodeproofprofile`.
- Extended `bridge_buildproofpolicy` and `bridge_buildproofreceipt` so they can
  derive `proof_system_id` from either:
  - raw `proof_system_id`,
  - `proof_profile_hex`,
  - or inline `proof_profile` objects.
- Added direct functional coverage in
  `test/functional/wallet_bridge_proof_profile.py`.
- Registered:
  - `wallet_bridge_proof_profile.py --descriptors`
  in `test/functional/test_runner.py`.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_proof_profile.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_proof_receipt.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_hybrid_anchor.py --descriptors --configfile=test/config.ini`
- Deterministic proof-profile-backed surfaces observed:
  - proof profile: `97` bytes
  - statement with bound proof policy: `260` bytes
  - proof receipt: `161` bytes
  - descriptor proof with a 3-descriptor policy: `70` bytes
- `./build-btx/bin/bench_btx -filter='BridgeProofSystemIdHash|BridgeProofPolicyRoot32|BridgeProofPolicyProofVerify32|BridgeProofReceiptRoot8|BridgeVerificationBundleHash|BridgeExternalAnchorFromProofReceipts8|BridgeExternalAnchorFromHybridWitness8|BridgeVerifierSetProofVerify32MLDSA44|BridgeExternalAnchorFromReceipts8MLDSA44' -min-time=50`
  reported:
  - `BridgeExternalAnchorFromHybridWitness8`: `56,498.05 ns/witness`
  - `BridgeExternalAnchorFromProofReceipts8`: `1,435.39 ns/receipt`
  - `BridgeExternalAnchorFromReceipts8MLDSA44`: `112,913.54 ns/receipt`
  - `BridgeProofPolicyProofVerify32`: `658.05 ns/op`
  - `BridgeProofPolicyRoot32`: `220.60 ns/descriptor`
  - `BridgeProofReceiptRoot8`: `661.91 ns/receipt`
  - `BridgeProofSystemIdHash`: `411.32 ns/op`
  - `BridgeVerificationBundleHash`: `325.74 ns/op`
  - `BridgeVerifierSetProofVerify32MLDSA44`: `1,405.73 ns/op`
- Conclusion:
  - canonical proof profiles add a negligible hashing cost relative to both the
    imported-proof and committee-verification paths;
  - they standardize imported-proof family naming without changing the compact
    receipt size (`161` bytes remains unchanged);
  - and BTX now has a cleaner adapter boundary for real proof stacks such as
    SP1 Groth16, RISC Zero Succinct, or Blobstream SP1 data-root proofs,
    before any proof bytes are brought near consensus.

### 2026-03-14 15

- Added canonical `BridgeProofClaim` plus:
  - `bridge_buildproofclaim`,
  - and `bridge_decodeproofclaim`.
- Extended `bridge_buildproofreceipt` so it can derive `public_values_hash`
  from either:
  - raw `public_values_hash`,
  - `claim_hex`,
  - or inline `claim` objects.
- Added statement-matching checks so imported proof claims cannot be replayed
  across different batch statements.
- Added direct functional coverage in
  `test/functional/wallet_bridge_proof_claim.py`.
- Registered:
  - `wallet_bridge_proof_claim.py --descriptors`
  in `test/functional/test_runner.py`.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_proof_claim.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_proof_profile.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_proof_receipt.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_hybrid_anchor.py --descriptors --configfile=test/config.ini`
- Deterministic proof-claim-backed surfaces observed:
  - proof claim:
    - `settlement_metadata_v1`: `211` bytes
    - `batch_tuple_v1`: `211` bytes
    - `data_root_tuple_v1`: `211` bytes
  - statement with bound proof policy: `260` bytes
  - proof receipt: `161` bytes
- `./build-btx/bin/bench_btx -filter='BridgeProofSystemIdHash|BridgeProofClaimHashSettlementMetadata|BridgeProofClaimHashDataRootTuple|BridgeProofPolicyRoot32|BridgeProofPolicyProofVerify32|BridgeProofReceiptRoot8|BridgeVerificationBundleHash|BridgeExternalAnchorFromProofReceipts8|BridgeExternalAnchorFromHybridWitness8' -min-time=50`
  reported:
  - `BridgeExternalAnchorFromHybridWitness8`: `56,072.35 ns/witness`
  - `BridgeExternalAnchorFromProofReceipts8`: `1,349.98 ns/receipt`
  - `BridgeProofClaimHashDataRootTuple`: `630.67 ns/op`
  - `BridgeProofClaimHashSettlementMetadata`: `628.60 ns/op`
  - `BridgeProofPolicyProofVerify32`: `689.59 ns/op`
  - `BridgeProofPolicyRoot32`: `219.64 ns/descriptor`
  - `BridgeProofReceiptRoot8`: `669.96 ns/receipt`
  - `BridgeProofSystemIdHash`: `428.02 ns/op`
  - `BridgeVerificationBundleHash`: `336.28 ns/op`
- Conclusion:
  - BTX now has canonical public-output envelopes for imported proofs, not just
    canonical proof-family identifiers;
  - `public_values_hash` can be derived from statement-bound settlement
    metadata or a Blobstream-style data-root tuple with roughly the same
    hashing cost as the earlier proof-system-id layer;
  - the compact imported-proof receipt remains `161` bytes because only the
    claim digest, not the full claim payload, reaches the receipt envelope;
  - and the next adapter work can focus on binding profile families
    (`SP1`, `RISC Zero`, `Blobstream`) to these BTX claim kinds rather than
    inventing more ad hoc hashing conventions.

### 2026-03-14 16

- Added canonical `BridgeProofAdapter` plus:
  - `bridge_listproofadapters`,
  - `bridge_buildproofadapter`,
  - and `bridge_decodeproofadapter`.
- Extended `bridge_buildproofpolicy` and `bridge_buildproofreceipt` so they can
  derive imported-proof descriptors and receipt commitments from either:
  - `proof_adapter_name`,
  - `proof_adapter_hex`,
  - or inline `proof_adapter` objects.
- Shipped built-in adapters for:
  - SP1 `compressed`, `plonk`, and `groth16`,
  - RISC Zero `composite`, `succinct`, and `groth16`,
  - and Blobstream-style `sp1` / `risc0` data-root proofs.
- Added direct functional coverage in
  `test/functional/wallet_bridge_proof_adapter.py`.
- Registered:
  - `wallet_bridge_proof_adapter.py --descriptors`
  in `test/functional/test_runner.py`.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_proof_adapter.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_proof_claim.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_proof_profile.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_proof_receipt.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_hybrid_anchor.py --descriptors --configfile=test/config.ini`
- `python3 test/functional/test_runner.py wallet_bridge_proof_adapter.py --descriptors --configfile=test/config.ini`
  still hits the pre-existing runner/cache mismatch in this repo because
  `create_cache.py` does not accept `--descriptors`; direct execution of the
  functional tests succeeded.
- Deterministic proof-adapter-backed surfaces observed:
  - proof adapter:
    - `sp1-compressed-settlement-metadata-v1`: `99` bytes
    - `risc0-zkvm-succinct-batch-tuple-v1`: `99` bytes
    - `blobstream-risc0-data-root-tuple-v1`: `99` bytes
  - proof receipt: `161` bytes
  - statement with bound proof policy: `260` bytes
- `./build-btx/bin/bench_btx -filter='BridgeProofAdapterIdHash|BridgeProofSystemIdHash|BridgeProofClaimHashSettlementMetadata|BridgeProofClaimHashDataRootTuple|BridgeProofPolicyRoot32|BridgeProofPolicyProofVerify32|BridgeProofReceiptRoot8|BridgeVerificationBundleHash|BridgeExternalAnchorFromProofReceipts8|BridgeExternalAnchorFromHybridWitness8' -min-time=50`
  reported:
  - `BridgeExternalAnchorFromHybridWitness8`: `56,419.79 ns/witness`
  - `BridgeExternalAnchorFromProofReceipts8`: `1,432.06 ns/receipt`
  - `BridgeProofAdapterIdHash`: `473.42 ns/op`
  - `BridgeProofClaimHashDataRootTuple`: `640.89 ns/op`
  - `BridgeProofClaimHashSettlementMetadata`: `643.35 ns/op`
  - `BridgeProofPolicyProofVerify32`: `696.74 ns/op`
  - `BridgeProofPolicyRoot32`: `222.44 ns/descriptor`
  - `BridgeProofReceiptRoot8`: `700.00 ns/receipt`
  - `BridgeProofSystemIdHash`: `405.48 ns/op`
  - `BridgeVerificationBundleHash`: `324.04 ns/op`
- No DigitalOcean infrastructure was created in this pass.
- Conclusion:
  - BTX now has one canonical selector layer above proof profiles and proof
    claims, which removes another source of bridge-local naming drift;
  - built-in adapters map directly onto the external proof / receipt families
    documented by SP1, RISC Zero, and Blobstream;
  - adapter hashing adds only a small constant cost on top of the already cheap
    imported-proof path;
  - and the compact proof receipt remains `161` bytes because the adapter
    chooses semantics, not proof-byte storage.

### 2026-03-14 17

- Added canonical `BridgeProofArtifact` plus:
  - `bridge_buildproofartifact`,
  - and `bridge_decodeproofartifact`.
- Extended `bridge_buildproofpolicy` and `bridge_buildproofreceipt` so they can
  accept either:
  - `proof_artifact_hex`,
  - or inline `proof_artifact`,
  and deterministically regenerate the compact descriptor / receipt from that
  manifest.
- Broadened canonical adapter parsing so decoded proof artifacts can be reused
  directly:
  - `bridge_buildproofpolicy` now accepts already-materialized canonical
    `profile` ids inside the artifact’s nested proof adapter,
  - rather than requiring a bridge-local label selector.
- Fixed the repo-local functional-runner mismatch by teaching
  `test/functional/create_cache.py` to accept `--descriptors`.
- Re-ran CMake configuration so the build-tree functional script links include:
  - `wallet_bridge_proof_artifact.py`,
  - and the updated descriptor-aware runner files.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_proof_artifact.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_proof_adapter.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/test_runner.py wallet_bridge_proof_artifact.py wallet_bridge_proof_adapter.py --descriptors --configfile=test/config.ini`
- Deterministic proof-artifact-backed surfaces observed:
  - proof artifact:
    - `sp1-compressed-settlement-metadata-v1`: `272` bytes
    - `risc0-zkvm-succinct-batch-tuple-v1`: `272` bytes
    - `blobstream-risc0-data-root-tuple-v1`: `272` bytes
  - proof receipt: `161` bytes
  - off-chain storage bytes:
    - `sp1-compressed-settlement-metadata-v1`: `395360`
    - `risc0-zkvm-succinct-batch-tuple-v1`: `266304`
    - `blobstream-risc0-data-root-tuple-v1`: `139336`
- `./build-btx/bin/bench_btx -filter='BridgeProofArtifactIdHash|BridgeProofAdapterIdHash|BridgeProofSystemIdHash|BridgeProofClaimHashSettlementMetadata|BridgeProofClaimHashDataRootTuple|BridgeProofReceiptRoot8|BridgeExternalAnchorFromProofReceipts8|BridgeVerificationBundleHash|BridgeExternalAnchorFromHybridWitness8' -min-time=50`
  reported:
  - `BridgeExternalAnchorFromHybridWitness8`: `58,058.59 ns/witness`
  - `BridgeExternalAnchorFromProofReceipts8`: `1,453.70 ns/receipt`
  - `BridgeProofAdapterIdHash`: `470.77 ns/op`
  - `BridgeProofArtifactIdHash`: `699.78 ns/op`
  - `BridgeProofClaimHashDataRootTuple`: `652.78 ns/op`
  - `BridgeProofClaimHashSettlementMetadata`: `608.49 ns/op`
  - `BridgeProofReceiptRoot8`: `665.40 ns/receipt`
  - `BridgeProofSystemIdHash`: `423.59 ns/op`
  - `BridgeVerificationBundleHash`: `350.56 ns/op`
- No DigitalOcean infrastructure was created in this pass.
- Conclusion:
  - BTX now has one stable manifest for imported proof bundles, not just the
    compact receipt committed on the settlement path;
  - the proof-artifact layer cleanly separates L1 receipt bytes from off-chain
    archival storage bytes;
  - descriptor-based functional test execution now works through the normal
    runner path in this repo;
  - and the imported-proof receipt still stays at `161` bytes while the
    artifact manifest exposes the much larger off-chain storage footprint.

### 2026-03-14 18

- Added canonical `BridgeCapacityFootprint` and `EstimateBridgeCapacity`.
- Added `bridge_estimatecapacity` so measured settlement paths can be compared
  using:
  - L1 serialized bytes,
  - L1 weight,
  - control-plane bytes,
  - off-chain storage bytes,
  - represented users per settlement,
  - and an optional native-shielded baseline.
- Added direct unit coverage for:
  - the current native shielded weight bottleneck,
  - batched-user scaling,
  - and off-chain storage accumulation.
- Added end-to-end functional coverage in
  `test/functional/wallet_bridge_capacity_estimate.py` that:
  - finalizes three single bridge-out settlements,
  - finalizes one three-user batch bridge-out settlement,
  - finalizes one proof-anchored three-user batch bridge-out settlement,
  - and feeds those real tx sizes / weights into `bridge_estimatecapacity`.
- Re-ran CMake configuration so the build-tree functional script links include:
  - `wallet_bridge_capacity_estimate.py`.
- Rebuilt `bitcoind` and `test_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_proof_artifact.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_capacity_estimate.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/test_runner.py wallet_bridge_capacity_estimate.py wallet_bridge_proof_artifact.py --descriptors --configfile=test/config.ini`
- Finalized capacity surfaces observed:
  - native shielded baseline:
    - `586196` bytes
    - `2344784` weight
    - `10` users per block
  - single bridge-out settlement:
    - `4043` bytes
    - `4325` weight
    - `2968` users per block
  - three-user batch bridge-out settlement:
    - `4173` bytes
    - `4713` weight
    - `8625` users per block
  - three-user proof-anchored batch bridge-out settlement:
    - `4276` bytes
    - `4816` weight
    - `8418` users per block
    - `801000` off-chain proof-artifact bytes per settlement
- No DigitalOcean infrastructure was created in this pass.
- Conclusion:
  - BTX now has a repeatable capacity model instead of only prose arguments
    about blockspace scarcity;
  - even a single bridge-out settlement is dramatically cheaper on L1 than one
    native shielded spend;
  - three-user batch settlement increases represented users per block to
    `862.5x` the measured native shielded baseline;
  - and proof-anchored batching preserves almost all of that L1 gain while
    making the off-chain proof-storage burden explicit.

### 2026-03-14 19

- Extended `bridge_estimatecapacity` with an optional `prover` model covering:
  - native pre-proof work,
  - CPU proving,
  - GPU proving,
  - and remote prover / prover-network lanes.
- Added canonical bridge-layer throughput types:
  - `BridgeProverLane`,
  - `BridgeProverFootprint`,
  - `BridgeProverLaneEstimate`,
  - and `EstimateBridgeProverCapacity`.
- Added direct unit coverage for:
  - prover-bound vs L1-bound throughput,
  - parallel remote-lane scaling,
  - hourly throughput,
  - required workers,
  - and modeled hourly-cost derivation.
- Added end-to-end functional coverage in
  `test/functional/wallet_bridge_prover_capacity.py` that:
  - finalizes one real three-user proof-anchored bridge-out settlement,
  - feeds its measured bytes / weight / off-chain storage into
    `bridge_estimatecapacity`,
  - overlays modeled native / CPU / GPU / network lanes,
  - and checks which lanes actually sustain the `90 s` BTX cadence.
- Re-ran CMake configuration so the build-tree functional script links include:
  - `wallet_bridge_prover_capacity.py`.
- Rebuilt `bitcoind` and `test_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_capacity_estimate.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_prover_capacity.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/test_runner.py wallet_bridge_proof_artifact.py wallet_bridge_capacity_estimate.py wallet_bridge_prover_capacity.py --descriptors --configfile=test/config.ini`
- Modeled prover-lane results over the finalized three-user proof-anchored
  batch settlement (`4276` bytes, `4816` weight, `801000` off-chain bytes):
  - L1 settlement limit:
    - `2806` settlements per block
    - `8418` users per block
    - `112240` settlements per hour
    - `336720` users per hour
  - native lane (`650 ms`, `32` workers):
    - sustains full L1 throughput
    - required workers to saturate L1: `21`
    - modeled required cost: `$7.35 / hour`
  - CPU lane (`180000 ms`, `32` workers):
    - sustains `16` settlements / block interval
    - `48` users per block
    - required workers to saturate L1: `5612`
    - modeled required cost: `$14030.00 / hour`
  - GPU lane (`12000 ms`, `8` workers):
    - sustains `60` settlements / block interval
    - `180` users per block
    - required workers to saturate L1: `375`
    - modeled required cost: `$6750.00 / hour`
  - remote proving lane (`4000 ms`, `16` workers, `8` parallel jobs each):
    - sustains full L1 throughput
    - required workers to saturate L1: `16`
    - modeled required cost: `$256.00 / hour`
- No DigitalOcean infrastructure was created in this pass.
- Conclusion:
  - the L1 settlement bytes are no longer the hard part once bridge batching is
    in place;
  - proving supply becomes the dominant constraint for proof-anchored flow;
  - local CPU and even small local GPU footprints do not come close to
    saturating BTX’s current compact settlement path under these modeled
    scenarios;
  - and a proving network / remote prover market is the first lane in this
    model that keeps up with the measured L1 settlement capacity.

### 2026-03-14 20

- Added canonical bridge prover samples and prover profiles so imported proof
  artifacts can carry reusable timing metadata instead of forcing manual lane
  timing entry in every `bridge_estimatecapacity` call.
- Added RPCs:
  - `bridge_buildproversample`,
  - `bridge_decodeproversample`,
  - `bridge_buildproverprofile`,
  - `bridge_decodeproverprofile`.
- Extended `bridge_estimatecapacity` so `options.prover` can accept:
  - `prover_profile_hex`,
  - or inline `prover_profile`,
  - and then derive lane `millis_per_settlement` from that canonical profile
    while the lane objects only supply workers / parallelism / hourly cost.
- Added direct unit coverage for:
  - prover-sample roundtrip and hashing,
  - prover-profile aggregation,
  - serialization roundtrip,
  - and duplicate-sample rejection.
- Added end-to-end functional coverage in
  `test/functional/wallet_bridge_prover_profile.py` that:
  - finalizes one real three-user proof-anchored bridge-out settlement,
  - builds three artifact-linked prover samples from the actual imported
    artifacts,
  - aggregates them into one prover profile,
  - and checks that profile-derived lane outputs match the earlier manual
    native / CPU / GPU / network scenario exactly.
- Re-ran CMake configuration so the build-tree functional script links include:
  - `wallet_bridge_prover_profile.py`.
- Rebuilt `bitcoind` and `test_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_proof_artifact.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_prover_capacity.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_prover_profile.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/test_runner.py wallet_bridge_proof_artifact.py wallet_bridge_capacity_estimate.py wallet_bridge_prover_capacity.py wallet_bridge_prover_profile.py --descriptors --configfile=test/config.ini`
- Measured on the new artifact-linked profile path:
  - canonical prover sample size: `177` bytes
  - canonical prover profile size: `125` bytes
  - artifact-backed profile storage: `801000` bytes
  - derived native / CPU / GPU / network totals: `650 / 180000 / 12000 / 4000 ms`
  - artifact-storage delta versus the measured settlement footprint: `0`
- No DigitalOcean infrastructure was created in this pass.
- Conclusion:
  - BTX now has a deterministic bridge between imported proof artifacts and the
    prover-throughput estimator;
  - the same artifact set can drive:
    - proof receipt construction,
    - off-chain storage accounting,
    - and lane throughput modeling;
- and the canonical profile reproduces the earlier manual prover scenario
  exactly while keeping the reusable metadata layer compact (`177`-byte
  samples, `125`-byte profile).

### 2026-03-14 21

- Added a built-in wallet-layer prover-template catalog so BTX can reuse named
  modeled reference inputs across imported proof artifacts instead of forcing
  each experiment to restate lane timings by hand.
- Added RPC:
  - `bridge_listprovertemplates`.
- Extended:
  - `bridge_buildproversample`,
  - and the inline sample-builder path inside `bridge_buildproverprofile`,
  - so callers can pass `prover_template_name` plus one imported proof artifact
    and get a canonical `BridgeProverSample` populated from the template.
- Kept the template layer explicitly non-consensus:
  - templates live only in the wallet RPC catalog,
  - canonical serialized sample/profile bytes are unchanged,
  - and explicit timing fields still override template defaults when an
    experiment needs to perturb one lane.
- Added end-to-end functional coverage in
  `test/functional/wallet_bridge_prover_template.py` that:
  - lists the built-in templates,
  - builds template-backed samples for SP1 Groth16 settlement metadata,
    RISC Zero succinct batch tuples, and Blobstream-style SP1 data-root tuples,
  - rejects an adapter/template mismatch,
  - aggregates the template-backed samples into one canonical prover profile,
  - and checks that the profile-derived capacity output reproduces the current
    `650 / 180000 / 12000 / 4000 ms` native / CPU / GPU / remote scenario.
- Re-ran CMake configuration so the build-tree functional script links include:
  - `wallet_bridge_prover_template.py`.
- Rebuilt `bitcoind` and `test_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_prover_profile.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/wallet_bridge_prover_template.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/test_runner.py wallet_bridge_prover_profile.py wallet_bridge_prover_template.py --descriptors --configfile=test/config.ini`
- Measured on the new template-backed path:
  - built-in prover templates exposed by RPC: `8`
  - prover sample size: `177` bytes
  - prover profile size: `125` bytes
  - derived lane totals from the three-template profile:
    - native: `650 ms`
    - CPU: `180000 ms`
    - GPU: `12000 ms`
    - remote prover / network: `4000 ms`
  - sustained users per block from that profile:
    - native: `8418`
    - CPU: `48`
    - GPU: `180`
    - remote prover / network: `8418`
- Re-checked the external proving / DA references on March 14, 2026:
  - [SP1 proof families](https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/enum.SP1Proof.html)
    still distinguish compressed, Plonk, and Groth16 envelopes.
  - [SP1 ProverClientBuilder](https://docs.rs/sp1-sdk/latest/sp1_sdk/client/struct.ProverClientBuilder.html)
    still exposes local CPU / CUDA / network prover selection in the SDK
    surface.
  - [RISC Zero local proving](https://dev.risczero.com/api/generating-proofs/local-proving)
    still documents local proving as a separate operational concern from the
    receipt family itself.
  - [Celestia Blobstream proof queries](https://docs.celestia.org/how-to-guides/blobstream/proof-queries)
    still center the operator flow on data-root / tuple proof queries rather
    than L1-sized per-user payloads.
  - [Nillion Blacklight overview](https://docs.nillion.com/blacklight/learn/overview)
    still reinforces the broader architectural split BTX is targeting:
    compact settlement commitments on-chain, richer privacy / verification work
    off-chain.
- No DigitalOcean infrastructure was created in this pass.
- Conclusion:
  - BTX now has deterministic, reusable modeled prover inputs tied directly to
    named imported-proof families;
  - those inputs can drive large experiment matrices without changing any
    canonical bridge serialization;
  - and the next meaningful step is no longer “invent more timing knobs,” but
    “replace the modeled template defaults with captured timings from real SP1,
    RISC Zero, and Blobstream proving runs.”

### 2026-03-14 22

- Added a canonical benchmark layer over repeated prover profiles so BTX can
  stop treating one run as representative and instead compare repeated
  settlement proving results through deterministic `min / p50 / p90 / max`
  summaries.
- Added core bridge types:
  - `BridgeProverMetricSummary`,
  - `BridgeProverBenchmark`,
  - and `BridgeProverBenchmarkStatistic`.
- Added core bridge functions:
  - `BuildBridgeProverBenchmark`,
  - `SerializeBridgeProverBenchmark`,
  - `DeserializeBridgeProverBenchmark`,
  - `ComputeBridgeProverBenchmarkId`,
  - and `SelectBridgeProverMetric`.
- Added RPCs:
  - `bridge_buildproverbenchmark`,
  - `bridge_decodeproverbenchmark`.
- Extended `bridge_estimatecapacity` so `options.prover` can now accept:
  - `prover_benchmark_hex`,
  - or inline `prover_benchmark`,
  - plus `benchmark_statistic = min | p50 | p90 | max`,
  - and then derive lane `millis_per_settlement` from repeated profiles
    instead of from one profile or one ad hoc scenario.
- Added direct unit coverage for:
  - prover-benchmark aggregation,
  - deterministic percentile selection,
  - serialization roundtrip,
  - and duplicate-profile rejection.
- Added a new microbench:
  - `BridgeProverBenchmarkBuild5Profiles`.
- Added end-to-end functional coverage in
  `test/functional/wallet_bridge_prover_benchmark.py` that:
  - finalizes one real three-user proof-anchored bridge-out settlement,
  - builds five repeated prover profiles over the same imported artifact set,
  - aggregates them into one canonical benchmark,
  - and feeds both `p50` and `p90` benchmark statistics back into
    `bridge_estimatecapacity`.
- Fixed a build-tree test-registration gap by changing
  `test/CMakeLists.txt` to use `GLOB_RECURSE ... CONFIGURE_DEPENDS` for
  functional test symlink generation, so new experiment scripts land in
  `build-btx/test/functional` reliably.
- Re-ran CMake configuration so the build-tree functional script links include:
  - `wallet_bridge_prover_benchmark.py`.
- Rebuilt `bitcoind`, `test_btx`, and `bench_btx` successfully.
- Re-ran targeted tests successfully:
  - `./build-btx/bin/test_btx --run_test=shielded_bridge_tests,bridge_wallet_tests --catch_system_errors=no`
  - `python3 test/functional/wallet_bridge_prover_benchmark.py --descriptors --configfile=test/config.ini`
  - `python3 test/functional/test_runner.py wallet_bridge_prover_profile.py wallet_bridge_prover_template.py wallet_bridge_prover_benchmark.py --descriptors --configfile=test/config.ini`
  - `./build-btx/bin/bench_btx -filter='BridgeProverBenchmarkBuild5Profiles' -min-time=50`
- Measured on the new repeated-profile benchmark path:
  - prover benchmark size: `273` bytes
  - repeated prover profile size: `125` bytes
  - `p50` lane totals:
    - native: `650 ms`
    - CPU: `180000 ms`
    - GPU: `12000 ms`
    - remote prover / network: `4000 ms`
  - `p90` lane totals:
    - native: `700 ms`
    - CPU: `190000 ms`
    - GPU: `13000 ms`
    - remote prover / network: `4500 ms`
  - benchmark-derived sustainable users per block:
    - `p50`: `8418 / 48 / 180 / 8418`
    - `p90`: `8418 / 45 / 165 / 7680`
    - for native / CPU / GPU / remote prover respectively
  - `BridgeProverBenchmarkBuild5Profiles`: `816.73 ns/profile`
- Re-checked the external proving / DA references on March 14, 2026:
  - [Agglayer benchmarks](https://docs.agglayer.dev/agglayer/core-concepts/pessimistic-proof/benchmarks/)
    still frame proving performance in repeated benchmark terms rather than as
    a single run.
  - [SP1 ProverClientBuilder](https://docs.rs/sp1-sdk/latest/sp1_sdk/client/struct.ProverClientBuilder.html)
    still exposes local CPU / CUDA / network prover choices at the SDK layer.
  - [RISC Zero Prover trait](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/trait.Prover.html)
    still keeps proving backends behind an operational prover abstraction.
  - [Ethereum Dencun](https://ethereum.org/en/roadmap/danksharding/)
    and [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)
    still reinforce the same architectural lesson:
    cheap data / proof carriage and scalable settlement come from changing the
    base-layer data model when necessary, not from pretending old envelopes are
    sacred.
  - [Nillion Blacklight overview](https://docs.nillion.com/blacklight/learn/overview)
    still fits the same separation between compact on-chain commitments and
    richer off-chain privacy / verification work.
- No DigitalOcean infrastructure was created in this pass.
- Conclusion:
  - BTX now has a deterministic benchmark surface for repeated proving runs,
    not just single-run modeled profiles;
  - that surface is directly usable for `p50` versus `p90` capacity planning;
  - and it is explicitly in service of larger decisions, including consensus-
    breaking settlement redesigns if those win on throughput.

### 2026-03-14 23: Hard-Fork Aggregate Settlement Prototype

Objective:

- Solve the consensus-level comparison directly instead of leaving it as an
  open blocker.
- Build one canonical BTX object that can model a hard-fork aggregate
  settlement with explicit placement of:
  - aggregate proof bytes,
  - public batch / DA bytes,
  - and off-chain retained artifact bytes.

Why this slice was chosen:

- The largest unresolved question on this branch was no longer "can bridges
  batch users?" That had already been demonstrated.
- The harder question was whether BTX should stop at a bridge-validium surface
  or push into a consensus-breaking aggregate-settlement format.
- That question could not be answered honestly with the old two-limit capacity
  model because rollup-style designs often move public batch data into a
  separate L1 data-availability lane.

What landed:

- Extended the core capacity model in `src/shielded/bridge.*` with:
  - `BridgeAggregatePayloadLocation`,
  - `BridgeAggregateSettlement`,
  - a third `BridgeCapacityBinding::DATA_AVAILABILITY`,
  - `BridgeCapacityFootprint.l1_data_availability_bytes`,
  - `BridgeCapacityEstimate.block_data_availability_limit`,
  - `BridgeCapacityEstimate.fit_by_data_availability`,
  - and `BridgeCapacityEstimate.total_l1_data_availability_bytes`.
- Added core bridge functions:
  - `SerializeBridgeAggregateSettlement`,
  - `DeserializeBridgeAggregateSettlement`,
  - `ComputeBridgeAggregateSettlementId`,
  - and `BuildBridgeAggregateSettlementFootprint`.
- Extended `EstimateBridgeCapacity(...)` so a settlement can now be limited by:
  - serialized block bytes,
  - block weight,
  - or a separate L1 data-availability lane.
- Added wallet RPCs:
  - `bridge_buildaggregatesettlement`,
  - `bridge_decodeaggregatesettlement`.
- The builder supports:
  - manual proof byte modeling,
  - artifact-backed proof byte derivation from `BridgeProofArtifact`,
  - explicit `proof_payload_location = non_witness | witness | data_availability | offchain`,
  - explicit `data_availability_location = non_witness | witness | data_availability | offchain`.
- Added direct unit coverage for:
  - aggregate settlement serialization / hashing,
  - footprint derivation,
  - and DA-lane capacity binding.
- Added new functional coverage in
  `test/functional/wallet_bridge_aggregate_settlement.py` that models:
  - witness-validium,
  - non-witness-validium,
  - and artifact-backed witness-plus-DA-lane rollup settlement.
- Added new microbenches:
  - `BridgeAggregateSettlementIdHash`,
  - `BridgeAggregateSettlementFootprint`.

Measured results from the new hard-fork prototype:

- Canonical aggregate settlement footprint:
  - serialized bytes: `20,076`
  - weight: `23,352`
  - DA-lane bytes: `4,096`
- Witness-validium hard-fork path:
  - `597` settlements per block
  - `38,208` users per block
- Non-witness-validium hard-fork path:
  - `331` settlements per block
  - `21,184` users per block
- Witness-plus-DA-lane rollup path with `786,432` DA bytes per block:
  - `192` settlements per block
  - `12,288` users per block
- Current measured proof-anchored bridge baseline for comparison:
  - `8,418` users per block
- Current native shielded baseline for comparison:
  - `10` users per block
- New microbench results:
  - `BridgeAggregateSettlementFootprint`: `5.98 ns/op`
  - `BridgeAggregateSettlementIdHash`: `527.45 ns/op`

Interpretation:

- The consensus-level answer is now concrete:
  - a hard-fork aggregate settlement with witness-discounted proof bytes
    materially outperforms the current bridge-validium settlement boundary,
    even before changing prover throughput.
- The proof-placement result is also concrete:
  - forcing aggregate proof bytes into non-witness accounting cuts modeled
    throughput from `38,208` to `21,184` users per block.
- The DA result is the key trade-off:
  - if BTX wants rollup-style public data availability instead of pure
    validium, then a separate DA lane becomes the binding limit quickly;
  - even so, the modeled rollup path still lands at `12,288` users per block,
    which is above the current bridge proof-anchored path and vastly above the
    native shielded baseline.
- That means the branch no longer has to speculate about whether a consensus
  redesign is worth serious attention:
  - it is.
  - The main remaining work is turning the modeled proof / DA byte inputs into
    real measured pipelines and then deciding how invasive BTX should be.

Primary-source re-checks used for this slice on March 14, 2026:

- [Ethereum zk-rollups](https://ethereum.org/en/developers/docs/scaling/zk-rollups/)
  still describe the core split BTX is now modeling:
  off-chain execution, on-chain proof verification, and root updates.
- [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)
  still formalizes the extra DA lane concept that motivated the new
  `l1_data_availability_bytes` capacity dimension.
- [Aztec rollup circuits](https://docs.aztec.network/developers/docs/foundational-topics/advanced/circuits/rollup_circuits)
  still show recursive circuit layering as the natural shape for private
  batch aggregation rather than one proof per user.
- [Penumbra shielded pool](https://protocol.penumbra.zone/main/shielded_pool.html)
  still reinforces that privacy systems scale around a state commitment tree
  and nullifier set, not around unbounded direct-on-L1 note-to-note flow.
- [Celestia Blobstream proof queries](https://docs.celestia.org/how-to-guides/blobstream/proof-queries)
  still demonstrate compact data-root proof tuples as the external DA anchor.
- [SP1 proof families](https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/enum.SP1Proof.html)
  and [NetworkProver](https://docs.rs/sp1-sdk/latest/sp1_sdk/network/struct.NetworkProver.html)
  still separate proof envelope choice from operational proving backend.
- [RISC Zero InnerReceipt](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/enum.InnerReceipt.html)
  still separates composite / succinct / Groth16 receipt families in the same
  way.
- [Nillion Blacklight overview](https://docs.nillion.com/blacklight/learn/overview)
  still fits the same architecture:
  compact commitments on-chain, richer privacy / verification work off-chain.

### 2026-03-14 24: Aggregate Settlement State Growth

Objective:

- Attack the next hardest blocker immediately after block-fit modeling:
  long-lived shielded state growth under a hard-fork aggregate-settlement path.
- Quantify the actual BTX storage surfaces that would scale with aggregate
  settlement instead of stopping at users-per-block.

Why this slice was chosen:

- The branch already proved that hard-fork aggregate settlement can solve the
  immediate block-scarcity problem.
- That made the next difficult question unavoidable:
  if BTX accepts consensus-breaking aggregate settlement for maximum
  throughput, how fast do nullifiers, commitment indexes, snapshot payloads,
  and first-touch account state grow?
- This is exactly the sort of high-impact blocker the branch rules require
  solving directly rather than postponing.

Code-derived state model used:

- Commitment-index persistence is modeled from `src/shielded/merkle_tree.cpp`:
  - key bytes: `1 + 8 = 9`,
  - value bytes: `32`,
  - total per commitment: `41`.
- Nullifier-index persistence is modeled from `src/shielded/nullifier.cpp`:
  - key bytes: `1 + 32 = 33`,
  - value bytes: `1`,
  - total per nullifier: `34`.
- Snapshot appendix bytes are modeled from `src/node/utxo_snapshot.h` and
  `doc/assumeutxo.md`:
  - `32` bytes per commitment,
  - `32` bytes per nullifier,
  - plus bounded recent anchor/output history.
- Hot-cache pressure is modeled from
  `src/shielded/nullifier.cpp::DynamicMemoryUsage()`:
  - `sizeof(Nullifier) + 64 = 96` bytes per cached nullifier entry.

What landed:

- Added core bridge types in `src/shielded/bridge.*`:
  - `BridgeShieldedStateProfile`,
  - `BridgeShieldedStateEstimate`,
  - `SerializeBridgeShieldedStateProfile`,
  - `DeserializeBridgeShieldedStateProfile`,
  - `ComputeBridgeShieldedStateProfileId`,
  - `EstimateBridgeShieldedStateGrowth`.
- Added wallet RPCs:
  - `bridge_buildshieldedstateprofile`,
  - `bridge_decodeshieldedstateprofile`,
  - `bridge_estimatestategrowth`.
- Added direct unit coverage for:
  - shielded-state profile serialization / hashing,
  - and default vs first-touch-materialized state-growth estimation.
- Added functional coverage in
  `test/functional/wallet_bridge_state_growth.py`.
- Added new microbenches:
  - `BridgeShieldedStateProfileIdHash`,
  - `BridgeShieldedStateGrowthEstimate`.

Measured results:

- Default shielded-state profile coefficients:
  - commitment index bytes per output: `41`,
  - nullifier index bytes per input: `34`,
  - snapshot bytes per commitment/nullifier: `32 / 32`,
  - nullifier hot-cache bytes: `96`,
  - bounded anchor history bytes: `800`.
- For the witness-plus-DA-lane rollup path
  (`192` settlements per block, `12,288` users per block):
  - per settlement:
    - persistent state bytes: `4,800`,
    - snapshot appendix bytes: `4,096`,
    - hot-cache bytes: `6,144`;
  - per block:
    - persistent state bytes: `921,600`,
    - snapshot appendix bytes: `786,432`,
    - hot-cache bytes: `1,179,648`;
  - per day at `90` second blocks:
    - persistent state bytes: `884,736,000`,
    - snapshot appendix bytes: `754,974,720`,
    - hot-cache bytes: `1,132,462,080`.
- With a modeled first-touch wallet/account materialization cost of `96`
  bytes for `24` new wallets per settlement:
  - persistent state bytes per settlement rise to `7,104`,
  - persistent state bytes per block rise to `1,363,968`,
  - persistent state bytes per day rise to `1,309,409,280`.
- For the higher-throughput witness-validium path
  (`597` settlements per block, `38,208` users per block):
  - persistent state bytes per block: `2,865,600`,
  - persistent state bytes per hour: `114,624,000`,
  - persistent state bytes per day: `2,750,976,000`.
- New microbench results:
  - `BridgeShieldedStateGrowthEstimate`: `23.61 ns/estimate`
  - `BridgeShieldedStateProfileIdHash`: `499.96 ns/op`

Interpretation:

- The block-space answer is no longer the whole answer.
- Hard-fork aggregate settlement can solve the scarcity of native shielded
  blockspace, but it converts the next bottleneck into long-lived state:
  - commitment index growth,
  - nullifier index growth,
  - snapshot appendix size,
  - and first-touch wallet/account materialization.
- The trade-off is now quantified:
  - witness-validium improves users-per-block from `12,288` to `38,208`
    compared with the DA-lane rollup path,
  - but it also lifts persistent state growth from `921,600` to `2,865,600`
    bytes per block, about `3.11x`.
- That means any maximum-throughput BTX hard fork needs a companion state
  policy, not just a better settlement envelope:
  - what is persisted forever,
  - what is only reconstructible from proof / DA artifacts,
  - when first-touch wallets become real L1 objects,
  - and how snapshot appendices stay tractable for assumeutxo / pruned nodes.

Primary-source re-checks used for this slice on March 14, 2026:

- [Aztec rollup circuits](https://docs.aztec.network/developers/docs/foundational-topics/advanced/circuits/rollup_circuits)
  still frame private rollups around dedicated state trees rather than around
  ephemeral one-shot proofs, which matches BTX needing explicit note/nullifier
  growth accounting.
- [Penumbra shielded pool](https://protocol.penumbra.zone/main/shielded_pool.html)
  still centers the privacy system on a note commitment tree and nullifier set,
  reinforcing that persistent state growth is a first-class scaling problem.
- [Ethereum zk-rollups](https://ethereum.org/en/developers/docs/scaling/zk-rollups/)
  still describe off-chain execution with on-chain proofs and state-root
  updates, which is consistent with BTX separating settlement compression from
  long-lived state retention.
- [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)
  still supports the lesson that better DA carriage can ease block-fit limits
  without making local state growth disappear.
- [Nillion Blacklight overview](https://docs.nillion.com/blacklight/learn/overview)
  still fits the same design split:
  compact commitments on-chain do not remove the need for careful accounting of
  what the chain itself must retain.
- No DigitalOcean infrastructure was created in this pass.

### 2026-03-14 25: Shielded State Retention Policy

Objective:

- Attack the next large blocker directly after state-growth modeling:
  convert "storage growth is high" into a canonical BTX policy surface for
  deciding what aggregate-settlement state actually remains on L1.
- Keep the branch doctrine explicit:
  this is not a placeholder for future design work, and hard-fork consensus
  changes remain acceptable if they materially improve BTX throughput and
  long-run storage scalability.

Why this slice was chosen:

- The previous slice quantified the storage-growth problem but still left one
  unresolved question in the critical path:
  should BTX actually retain all commitment / wallet materialization data
  locally once aggregate settlement becomes the primary scaling path?
- That is a harder and more consequential question than adding another helper
  envelope or measurement surface.
- The branch rules therefore required solving it immediately in code rather
  than writing "future retention policy" into backlog notes.

What landed:

- Added canonical bridge types in `src/shielded/bridge.*`:
  - `BridgeShieldedStateRetentionPolicy`,
  - `BridgeShieldedStateRetentionEstimate`,
  - `SerializeBridgeShieldedStateRetentionPolicy`,
  - `DeserializeBridgeShieldedStateRetentionPolicy`,
  - `ComputeBridgeShieldedStateRetentionPolicyId`,
  - `EstimateBridgeShieldedStateRetention`.
- Added wallet RPCs:
  - `bridge_buildstateretentionpolicy`,
  - `bridge_decodestateretentionpolicy`,
  - `bridge_estimatestateretention`.
- Added direct unit coverage for:
  - retention-policy serialization / hashing,
  - and full-retention vs externalized-retention estimation.
- Added functional coverage in
  `test/functional/wallet_bridge_state_retention.py`.
- Added new microbenches:
  - `BridgeShieldedStateRetentionPolicyIdHash`,
  - `BridgeShieldedStateRetentionEstimate`.
- Re-ran the normal descriptor harness path with:
  - `wallet_bridge_state_growth.py --descriptors`,
  - `wallet_bridge_state_retention.py --descriptors`.

Measured results on the DA-lane aggregate-settlement path
(`192` settlements/block, `12,288` users/block, `4 GiB` target snapshot
budget):

- Full-retention policy:
  - commitment index retained on L1,
  - nullifier index retained on L1,
  - commitments and nullifiers included in snapshots,
  - `100%` first-touch wallet materialization on L1.
- Full-retention output:
  - per settlement:
    - retained persistent state: `7,104` bytes,
    - snapshot export: `4,096` bytes,
    - runtime hot cache: `6,144` bytes;
  - per block:
    - retained persistent state: `1,363,968` bytes,
    - snapshot export: `786,432` bytes,
    - runtime hot cache: `1,179,648` bytes;
  - per day:
    - retained persistent state: `1,309,409,280` bytes,
    - snapshot export: `754,974,720` bytes;
  - time to a `4 GiB` snapshot target:
    - `5,461` blocks,
    - `136` hours,
    - `5` days,
    - `67,104,768` represented users.
- Proof-backed externalized policy:
  - commitment history not retained on L1,
  - nullifier index retained on L1,
  - snapshots include nullifiers only,
  - `25%` first-touch wallet materialization on L1.
- Externalized output:
  - per settlement:
    - retained persistent state: `2,752` bytes,
    - externalized persistent state: `4,352` bytes,
    - deferred wallet materialization: `1,728` bytes,
    - retained snapshot export: `2,048` bytes,
    - externalized snapshot bytes: `2,048` bytes;
  - per block:
    - retained persistent state: `528,384` bytes,
    - externalized persistent state: `835,584` bytes,
    - deferred wallet materialization: `331,776` bytes,
    - retained snapshot export: `393,216` bytes,
    - externalized snapshot bytes: `393,216` bytes;
  - per day:
    - retained persistent state: `507,248,640` bytes,
    - externalized persistent state: `802,160,640` bytes,
    - retained snapshot export: `377,487,360` bytes,
    - externalized snapshot bytes: `377,487,360` bytes;
  - time to the same `4 GiB` snapshot target:
    - `10,922` blocks,
    - `273` hours,
    - `11` days,
    - `134,209,536` represented users.
- New microbench results:
  - `BridgeShieldedStateRetentionEstimate`: `52.81 ns/estimate`
  - `BridgeShieldedStateRetentionPolicyIdHash`: `447.77 ns/op`
  - `BridgeShieldedStateGrowthEstimate`: `24.31 ns/estimate`
  - `BridgeShieldedStateProfileIdHash`: `520.00 ns/op`

Interpretation:

- BTX now has a direct, quantified answer to the next storage question after
  state-growth modeling:
  a hard-fork aggregate-settlement design can choose materially different
  long-run L1 storage burdens on the same throughput path.
- On the measured DA-lane rollup footprint, moving from full retention to the
  externalized policy reduces retained persistent L1 growth from
  `1,309,409,280` to `507,248,640` bytes per day, about a `61.3%` reduction.
- The same policy roughly doubles the `4 GiB` snapshot horizon from `5,461`
  to `10,922` blocks by externalizing commitment history and most wallet
  materialization.
- That means the hard blocker is now narrower and more concrete:
  BTX must decide which of these retention surfaces becomes actual protocol /
  node behavior, rather than merely acknowledging that state growth exists.

Primary-source re-checks used for this slice on March 14, 2026:

- [Ethereum state expiry and statelessness](https://ethereum.org/en/roadmap/scourge/#state-expiry)
  still frames long-lived state as a separate scaling problem from raw
  execution throughput, matching BTX needing an explicit retention decision
  after aggregate settlement changes block fit.
- [EIP-4444](https://eips.ethereum.org/EIPS/eip-4444)
  still demonstrates that history retention is a policy surface rather than an
  untouchable invariant, which is relevant because this branch treats
  consensus-breaking changes as acceptable when they materially improve scale.
- [Aztec rollup circuits](https://docs.aztec.network/developers/docs/foundational-topics/advanced/circuits/rollup_circuits)
  still center private scaling around explicit state trees rather than around
  proofs alone, which supports BTX modeling retention separately from proof
  compression.
- [Penumbra shielded pool](https://protocol.penumbra.zone/main/shielded_pool.html)
  still reinforces the same note-commitment-tree / nullifier-set state model.
- [Nillion Blacklight overview](https://docs.nillion.com/blacklight/learn/overview)
  still fits the same architecture:
  compact commitments on-chain do not eliminate a real decision about where
  private-state retention lives.
- No DigitalOcean infrastructure was created in this pass.

### 2026-03-14 26: Artifact-Backed Aggregate Settlement Bundles

Objective:

- Attack the current top uncertainty in the hard-fork path directly:
  replace hand-entered proof and DA byte inputs with canonical artifact-backed
  bundle measurements.
- Keep the branch doctrine explicit:
  the goal is not another helper surface, but a sharper answer to whether the
  optimistic hard-fork throughput numbers survive once current proof artifacts
  are actually accounted for.

Why this slice was chosen:

- The branch already had a manual hard-fork aggregate-settlement upper bound
  (`16,384` proof bytes, `4,096` DA bytes), but that left the hardest open
  question unsolved:
  what happens when the settlement footprint is driven by artifact manifests
  instead of spreadsheet numbers?
- That is a much higher-impact blocker than adding more isolated bridge
  objects because it directly tests whether the earlier throughput conclusion
  was materially overstated.
- The new retention-policy surface also made it possible to derive externalized
  state and snapshot payloads from BTX’s own models instead of guessing them.

What landed:

- Added canonical bridge types in `src/shielded/bridge.*`:
  - `BridgeDataArtifact`,
  - `BridgeAggregateArtifactBundle`,
  - `BuildBridgeDataArtifact`,
  - `BuildBridgeAggregateArtifactBundle`,
  - `ComputeBridgeDataArtifactId`,
  - `ComputeBridgeAggregateArtifactBundleId`.
- Added wallet RPCs:
  - `bridge_builddataartifact`,
  - `bridge_decodedataartifact`,
  - `bridge_buildaggregateartifactbundle`,
  - `bridge_decodeaggregateartifactbundle`.
- Extended `bridge_buildaggregatesettlement` so it can take
  `artifact_bundle_hex` / `artifact_bundle` and derive:
  - `proof_payload_bytes`,
  - `data_availability_payload_bytes`,
  - and `auxiliary_offchain_bytes`
  from the canonical bundle instead of manual byte inputs.
- Added direct unit coverage for:
  - data-artifact serialization / hashing,
  - aggregate-artifact-bundle aggregation and ids.
- Added functional coverage in
  `test/functional/wallet_bridge_aggregate_artifact_bundle.py`.
- Re-ran regression coverage for:
  - `wallet_bridge_aggregate_settlement.py --descriptors`,
  - `wallet_bridge_state_retention.py --descriptors`,
  - and the combined `test_runner.py` path over all three scenarios.
- Added new microbenches:
  - `BridgeDataArtifactIdHash`,
  - `BridgeAggregateArtifactBundleBuild`.

Measured results:

- One-proof artifact-backed DA-lane bundle:
  - one SP1 Groth16-style proof artifact:
    - `393,216` proof bytes,
    - `96` public-values bytes,
    - `2,048` auxiliary bytes;
  - one retention-derived state-diff artifact:
    - `6,080` payload bytes,
    - `512` auxiliary bytes;
  - one retention-derived snapshot artifact:
    - `2,048` payload bytes,
    - `256` auxiliary bytes.
- One-proof bundle totals:
  - proof payload bytes: `393,312`,
  - data payload bytes: `8,128`,
  - auxiliary off-chain bytes: `2,816`,
  - total artifact storage bytes: `404,256`.
- One-proof aggregate settlement footprint:
  - `397,004` serialized bytes,
  - `400,280` weight,
  - `8,128` DA-lane bytes.
- One-proof block fit:
  - `30` settlements per block,
  - `1,920` users per block.
- Two-proof artifact-backed bundle:
  - adds one Blobstream-style proof artifact:
    - `131,072` proof bytes,
    - `72` public-values bytes,
    - `8,192` auxiliary bytes.
- Two-proof bundle totals:
  - proof payload bytes: `524,456`,
  - data payload bytes: `8,128`,
  - auxiliary off-chain bytes: `11,008`,
  - total artifact storage bytes: `543,592`.
- Two-proof aggregate settlement footprint:
  - `528,148` serialized bytes,
  - `531,424` weight,
  - `8,128` DA-lane bytes.
- Two-proof block fit:
  - `22` settlements per block,
  - `1,408` users per block.
- New microbench results:
  - `BridgeAggregateArtifactBundleBuild`: `7,817.58 ns/bundle`
  - `BridgeDataArtifactIdHash`: `553.68 ns/op`

Interpretation:

- The earlier hard-fork DA-lane figure of `12,288` users per block is now
  clearly an upper-bound model rather than the current artifact-backed
  expectation.
- On the same `64`-user aggregate settlement shape:
  - one large proof artifact reduces the DA-lane path to `1,920` users per
    block,
  - and two proof artifacts reduce it further to `1,408`.
- That is still a strong improvement over the native shielded baseline of
  `10` users per block, but it is materially lower than the manual upper
  bound:
  - about `6.4x` lower for the one-proof path,
  - about `8.7x` lower for the two-proof path.
- The hard blocker is therefore sharper now:
  BTX needs materially smaller final proof envelopes, stronger recursion, or a
  different consensus/storage boundary if it wants to recover the earlier
  `8k+` to `12k+` users-per-block expectations.

Primary-source re-checks used for this slice on March 14, 2026:

- [SP1 proof variants](https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/enum.SP1Proof.html)
  still separate compressed, Plonk, and Groth16 proof families, supporting the
  conclusion that the final proof envelope choice is a first-class throughput
  variable.
- [RISC Zero InnerReceipt](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/enum.InnerReceipt.html)
  still separates composite, succinct, and Groth16 receipt families in the
  same way.
- [Celestia Blobstream proof queries](https://docs.celestia.org/how-to-guides/blobstream/proof-queries)
  still frame DA verification as an additional proof/query surface rather than
  as free control metadata.
- [Ethereum zk-rollups](https://ethereum.org/en/developers/docs/scaling/zk-rollups/)
  and [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)
  still reinforce the same architectural split:
  proof carriage and DA carriage are separate bottlenecks and both must be
  measured explicitly.
- No DigitalOcean infrastructure was created in this pass.

### 2026-03-14 27: Proof Compression Targets For Aggregate Settlement

Objective:

- Attack the next hard blocker directly instead of leaving "recursion" as a
  vague future optimization:
  quantify the exact final proof envelope BTX needs to recover higher-throughput
  aggregate settlement from the current artifact-backed path.
- Keep the branch doctrine explicit:
  solve the hardest scaling blocker available now, and accept hard-fork
  consensus changes when they materially improve throughput.

Why this slice was chosen:

- After the artifact-backed aggregate-bundle pass, the branch finally had a
  trustworthy measured starting point:
  `1,920` users/block for the one-proof DA-lane path and `1,408` for the
  two-proof path.
- That made the next high-value question unavoidable:
  which targets are impossible because fixed bytes already bind, and what exact
  proof size ceiling is required where compression can still help?
- That question is more important than another helper object because it decides
  whether BTX should keep investing in DA-lane rollup settlement, pivot toward
  witness-validium, or redesign the settlement boundary again.

What landed:

- Added canonical bridge types in `src/shielded/bridge.*`:
  - `BridgeProofCompressionTarget`,
  - `BridgeProofCompressionEstimate`,
  - `BuildBridgeProofCompressionTarget(...)`,
  - `SerializeBridgeProofCompressionTarget(...)`,
  - `DeserializeBridgeProofCompressionTarget(...)`,
  - `ComputeBridgeProofCompressionTargetId(...)`,
  - `EstimateBridgeProofCompression(...)`.
- Added wallet RPCs:
  - `bridge_buildproofcompressiontarget`,
  - `bridge_decodeproofcompressiontarget`.
- Added direct unit coverage for:
  - target serialization / hashing,
  - DA-lane zero-proof ceiling detection,
  - validium proof-envelope target quantification.
- Added end-to-end functional coverage in
  `test/functional/wallet_bridge_proof_compression_target.py`.
- Added new microbenches:
  - `BridgeProofCompressionTargetIdHash`,
  - `BridgeProofCompressionEstimate12288`.

Measured results:

- Current one-proof artifact-backed DA-lane settlement remains:
  - `393,312` proof-payload bytes,
  - `8,128` DA bytes,
  - `1,920` users/block.
- Asking that same DA-lane path to represent at least `8,418` users/block
  requires `132` settlements/block (`8,448` represented users at `64` users per
  settlement).
- BTX now proves that target is impossible even with a zero-byte final proof:
  - zero-proof ceiling: `96` settlements/block,
  - `6,144` users/block,
  - binding limit: `data_availability`.
- On the same artifact-backed batch shape with the DA payload moved off-chain
  (witness-validium-style settlement):
  - current capacity remains `1,920` users/block,
  - zero-proof ceiling rises to `208,000` users/block,
  - so proof compression becomes the real limiter again.
- For the validium-style path:
  - to reach `12,288` users/block:
    - max final proof payload: `58,808` bytes,
    - reduction from current proof payload: `334,504` bytes,
    - remaining ratio vs current proof payload: `14.95%`,
    - remaining ratio vs current proof artifact total (`395,360` bytes):
      `14.88%`;
  - to reach `38,208` users/block:
    - max final proof payload: `16,408` bytes,
    - reduction from current proof payload: `376,904` bytes,
    - remaining ratio vs current proof payload: `4.17%`,
    - remaining ratio vs current proof artifact total: `4.15%`.
- New microbench results:
  - `BridgeProofCompressionTargetIdHash`: `571.09 ns/op`
  - `BridgeProofCompressionEstimate12288`: `135.72 ns/estimate`
  - re-run artifact reference points:
    - `BridgeAggregateArtifactBundleBuild`: `7,201.12 ns/bundle`
    - `BridgeDataArtifactIdHash`: `504.80 ns/op`

Interpretation:

- Proof compression alone cannot rescue the current artifact-backed DA-lane
  hard-fork path because the fixed `8,128` DA bytes already cap it at
  `6,144` users/block with a zero-byte final proof.
- The same batch shape on a validium-style path can recover high throughput,
  but only if the final settlement proof is dramatically smaller than the
  current imported artifact:
  about `58.8 KiB` for `12,288` users/block and about `16.4 KiB` for
  `38,208`.
- That `16,408` byte ceiling is effectively the earlier manual
  `16,384`-byte upper bound again, but now it is justified by BTX's own
  artifact-backed measurements instead of by a spreadsheet assumption.
- The branch therefore has a sharper protocol direction now:
  - DA-lane rollup settlement needs DA compression or a larger DA lane before
    proof compression matters;
  - witness-validium remains the highest-upside hard-fork path;
  - and actual recursive proof systems only matter to BTX insofar as they can
    land near the measured `~59 KiB` or `~16 KiB` final envelope thresholds.

Primary-source re-checks used for this slice on March 14, 2026:

- [SP1 proof variants](https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/enum.SP1Proof.html)
  still distinguish compressed, Plonk, and Groth16 outputs, which is exactly
  the envelope choice BTX is now quantifying.
- [RISC Zero InnerReceipt](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/enum.InnerReceipt.html)
  still distinguishes composite, succinct, and Groth16 receipts at the same
  boundary.
- [Ethereum zk-rollups](https://ethereum.org/en/developers/docs/scaling/zk-rollups/)
  and [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)
  still support BTX's split between proof-envelope pressure and DA-lane
  pressure.
- [Celestia Blobstream proof queries](https://docs.celestia.org/how-to-guides/blobstream/proof-queries)
  still reinforce that external DA verification adds a separate proof/query
  surface instead of disappearing into control metadata.
- [Nillion Blacklight overview](https://docs.nillion.com/blacklight/learn/overview)
  still fits the same conclusion:
  off-chain private computation does not remove the need for a compact final
  settlement envelope.
- No DigitalOcean infrastructure was created in this pass.

### 2026-03-14 28: Live Relay-Fee Sufficiency Verification For Bridge Settlement PSBTs

Problem found during post-merge operational verification on local regtest:

- `bridge_buildshieldtx` could return a structurally valid PSBT whose funding
  margin was still below the live mempool policy floor.
- The concrete failure mode was a bridge-in settlement funded with
  `0.00010000` BTX fee margin:
  the builder returned the PSBT, but live broadcast failed with
  `min shielded relay premium not met`.
- Root cause:
  the builder surfaced selected P2MR metadata, but it did not estimate the
  final bridge witness size or check the shielded relay premium before the
  caller attempted broadcast.

Implementation landed in the follow-up branch:

- `bridge_buildshieldtx`, `bridge_buildunshieldtx`, and `bridge_buildrefund`
  now return:
  - `relay_fee_sufficient`
  - `relay_fee_analysis_available`
  - `relay_fee_analysis`
- The fee analysis derives the bridge witness template from the selected P2MR
  leaf itself instead of relying on generic dummy PSBT finalization.
  That matters because bridge P2MR inputs do not behave like ordinary
  descriptor inputs under the standard dummy-signing analysis path.
- The estimator now binds together:
  - transparent input value,
  - transparent output value,
  - shielded `value_balance`,
  - selected bridge witness size,
  - current relay floor,
  - current mempool floor,
  - and `MIN_SHIELDED_RELAY_FEE_PREMIUM` when the settlement enters the
    shielded pool.

Measured verification results:

- Rebuilt `bitcoind` and `test_btx`; targeted unit tests still passed.
- Re-ran the full bridge functional suite:
  - `29/29` bridge tests passed in `75 s` wall clock.
- Manual one-daemon regtest RPC verification outside the harness also passed:
  - low-margin bridge-in settlement:
    - funding margin: `0.00010000`
    - `relay_fee_sufficient = false`
    - `estimated_vsize = 7321`
    - `required_total_fee = 0.00012321`
    - broadcast rejected with `-26`:
      `min shielded relay premium not met, 10000 < 12321`
  - high-margin bridge-in settlement:
    - funding margin: `0.00020000`
    - `relay_fee_sufficient = true`
    - `estimated_vsize = 7322`
    - `required_total_fee = 0.00012322`
    - settlement txid:
      `40e9e7c7475fd97715b9cecb5a228e3a7c6bd1b011b4276145e9fd1131cda364`
    - recipient shielded balance after confirmation:
      `3.50000000`

Implication:

- BTX bridge settlement tooling now reports live policy sufficiency before the
  caller tries to broadcast.
- That closes a real operational correctness gap in the merged bridge surface.
- It also makes later batch / bridge benchmarking more trustworthy because
  underfunded settlement attempts are visible at build time instead of only
  after node rejection.

## Active Hard Blockers

These are current in-branch work items, not deferred backlog.

1. Connect the new artifact-bundle settlement path to live prover / DA outputs
   instead of reference-size manifests:
   - ingest real SP1 compressed / Plonk / Groth16 outputs,
   - ingest real RISC Zero composite / succinct / Groth16 receipts,
   - ingest real Blobstream-style proof-query artifacts,
   - and record the exact auxiliary bytes needed for replay and audit.
2. Replace the new modeled proof-envelope targets with real recursive proof
   outputs:
   - the branch now knows the actual thresholds:
     - the current artifact-backed DA-lane path cannot exceed `6,144`
       users/block even with a zero-byte final proof,
     - witness-validium needs about `58.8 KiB` to reach `12,288`
       users/block,
     - and about `16.4 KiB` to reach `38,208`;
   - now ingest real SP1 compressed / Plonk / Groth16 results and real RISC
     Zero composite / succinct / Groth16 results,
   - and determine which stacks can actually meet those BTX-specific envelope
     targets on current hardware.
3. Convert the modeled retention-policy surface into actual BTX protocol /
   node behavior instead of keeping it as a measurement-only tool:
   - choose the default hard-fork retention mode for aggregate settlement,
   - define which retained vs externalized state splits are consensus-critical
     vs node-policy / archival-policy choices,
   - define first-touch wallet/account materialization behavior for wallets
     that have never appeared on L1,
   - and tie assumeutxo / pruned-node snapshot cadence to the measured
     `~1.31 GB/day` full-retention path vs `~0.51 GB/day` externalized path.
4. Stand up a disposable remote proving / bridge sandbox as soon as one
   artifact-backed importer is connected to real prover outputs:
   - benchmark CPU-only vs GPU-backed proving,
   - record network / storage costs,
   - and terminate the infrastructure immediately after measurements.
5. Extend the standardized BTX claim schema when aggregate shielded settlement
   gains more public metadata worth binding:
   - e.g. bridge state roots,
   - nullifier bundles,
   - or net output summaries beyond the current batch and data-root tuples.
