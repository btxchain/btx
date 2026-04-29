# BTX Shielded Block Capacity Analysis

Status: historical analysis superseded by the March 20, 2026 runtime audit.

Use
[doc/btx-shielded-production-status-2026-03-20.md](btx-shielded-production-status-2026-03-20.md)
for the current architecture and measured numbers.

The key differences versus the historical analysis below are:

- the current baseline serialized block limit is `24 MB`, not `12 MB`,
- the reset-chain default direct-spend path is `DIRECT_SMILE` on the audited
  single-round launch surface (`anon_set <= 32`, `rec_levels == 1`),
- the current measured direct-SMILE footprints on that shipped surface are:
  - `1x2`: `60,218` bytes, `398 tx/block` at `24 MB`
  - `2x2`: `70,272` bytes, `341 tx/block`
  - `2x4`: `101,918` bytes, `235 tx/block`
- bridge ingress / egress remain the higher-action settlement paths:
  - Smile ingress `63 leaves / 8 spends / 8 proof shards / 1 reserve`:
    `312,364` bytes, `76 tx/block`, `4,788` represented ingress leaves / block
  - `32-output v2_egress`: `470,168` bytes, `51 tx/block`,
    `1,632` represented outputs / block
- `main` now also includes future-proofed settlement slack on the existing
  bridge/proof envelope, so later settlement-side soft forks can tighten
  `action_root`, DA, recovery/exit, and proof-policy semantics without adding
  a new outer settlement object first
- the refreshed chain-growth projection derived from current footprints keeps
  the `1b`, `5b`, and `10b` annual `1%` boundary workloads feasible at the
  current `24 MB` cadence; `32 MB` does not improve that mixed-workload model
  because it becomes weight-bound.

Date: 2026-03-14

## Question

How much block space do shielded transactions consume in BTX given:

- a 12,000,000 byte serialized block cap,
- a 24,000,000 weight-unit block cap,
- much larger post-quantum transparent signatures than legacy ECDSA,
- and an intended architecture where most transactional volume is expected to move through L2 / bridge paths while L1 remains a settlement layer?

The core question is not just "are shielded transactions large?" but "how many actually fit in a block, and does that make the base chain impractical?"

## Design Stance

- This analysis is not preserving backward compatibility as a first principle.
  If maximum BTX throughput and scalability require a hard-fork consensus
  change, that option is explicitly acceptable.
- Bridge-layer measurements are therefore being used for two purposes:
  - to show what the current non-consensus settlement path can achieve today,
  - and to build evidence for or against a larger consensus-level redesign.
- Difficult capacity blockers should be attacked directly rather than deferred
  into an indefinite backlog.

## Executive Summary

- Transparent post-quantum settlement transactions are not the dominant capacity problem. A measured 1-input / 2-output P2MR transaction is about 3.9 KB serialized and 4.3 kWU, so roughly 3,064 fit in a max block before the 12 MB serialized cap binds.
- Transparent-to-shielded funding is also not the main bottleneck. A measured `z_shieldfunds` transaction with 1 transparent input and 1 shielded output is about 5.1 KB serialized and 9.2 kWU, so about 2,339 fit in a max block.
- Actual shielded spending is the bottleneck. A measured 1-shielded-input / 1-shielded-output transaction is about 586 KB serialized and 2.344 MWU.
- Because the current implementation charges shielded bundle bytes as non-witness bytes, a block can carry only about 10 of those fully shielded spend transactions before hitting the 24 MWU weight limit.
- By contrast, measured finalized bridge-out settlement transactions are tiny on L1:
  - a single-user bridge-out settlement is about `4,043` bytes / `4,325` weight,
  - a three-user batch bridge-out settlement is about `4,173` bytes / `4,713` weight,
  - and a three-user proof-anchored batch settlement is about `4,276` bytes / `4,816` weight.
- That translates to roughly:
  - `2,968` represented users per block for single bridge-out settlement,
  - `8,625` represented users per block for three-user batch settlement,
  - and `8,418` represented users per block for three-user proof-anchored batch settlement,
  while keeping `801,000` proof-artifact bytes per settlement off-chain in the proof-backed path.
- BTX now also has a hard-fork aggregate-settlement prototype with an explicit
  proof/data placement model:
  - witness-validium: `38,208` users per block,
  - non-witness-validium: `21,184` users per block,
  - witness plus separate DA lane (`786,432` DA bytes/block): `12,288` users
    per block.
- The next hard limit after block fit is now quantified state growth:
  - the DA-lane rollup path adds about `921,600` persistent state bytes per
    block before first-touch wallet materialization,
  - while the higher-throughput witness-validium path raises that to
    `2,865,600` persistent bytes per block.
- BTX now also has a retention-policy model for that aggregate-settlement
  state:
  - a full-retention DA-lane policy with first-touch wallet materialization
    keeps about `1,309,409,280` persistent bytes per day on L1 and reaches a
    `4 GiB` snapshot target in about `5` days,
  - while a proof-backed externalized policy cuts retained persistent state to
    about `507,248,640` bytes per day and stretches the same snapshot target
    to about `11` days by externalizing commitment history and most wallet
    materialization.
- BTX now also has an artifact-bundle model for hard-fork aggregate
  settlement:
  - one current SP1 Groth16-style proof artifact plus retention-derived DA
    artifacts yields about `1,920` represented users per block,
  - adding a second Blobstream-style proof artifact drops that to about
    `1,408` users per block,
  - which is about `6.4x` to `8.7x` lower than the earlier manual
    `12,288 users/block` rollup upper-bound model.
- So the honest answer is: BTX L1 is viable as a settlement layer, but not as a high-volume retail layer if ordinary shielded note-to-note activity is expected to happen directly on L1 at scale.
- That does not make the system impractical if the intended model is "L2 for frequent activity, L1 for occasional high-value settlement, shield pool ingress/egress, and checkpointing." It does mean L1 shielded spends are scarce blockspace and should be treated accordingly.

## Consensus Limits That Matter

From the current implementation:

- `src/consensus/consensus.h`
  - `MAX_BLOCK_SERIALIZED_SIZE = 12,000,000`
  - `MAX_BLOCK_WEIGHT = 24,000,000`
  - `WITNESS_SCALE_FACTOR = 4`
- `src/consensus/validation.h`
  - `GetTransactionWeight(tx) = GetSerializeSize(TX_NO_WITNESS_WITH_SHIELDED(tx)) * 3 + GetSerializeSize(TX_WITH_WITNESS(tx))`

That formula matters a lot. Transparent witness data receives the usual witness treatment, but shielded data is explicitly included in the non-witness accounting path.

This behavior is reinforced by the tests:

- `src/test/shielded_transaction_tests.cpp`
  - `shielded_bundle_is_nonwitness_weight`

That test asserts that a transaction containing only a shielded bundle is charged at full non-witness weight, effectively `4 * serialized_size`.

## Why Post-Quantum Signatures Matter Less Than Expected Here

BTX transparent transactions are larger than ECDSA/Schnorr-era Bitcoin transactions because the transparent scheme uses large post-quantum keys and signatures. Current tests show:

- `pq_algorithm = "ml-dsa-44"`
- `pq_backup_algorithm = "slh-dsa-shake-128s"`
- `pq_pubkey_size = 1312`
- `pq_signature_size = 2420`

These sizes do materially inflate transparent transaction bytes. But transparent PQ signatures live in the witness path, so their blockspace effect is moderated by the witness discount logic.

By contrast, shielded bundles are not witness-discounted in the current implementation. So although PQ inflates transparent transactions, shielded spending still dominates the capacity picture.

## Shielded Limits in Code

From `src/shielded/bundle.h`:

- `MAX_SHIELDED_SPENDS_PER_TX = 16`
- `MAX_SHIELDED_OUTPUTS_PER_TX = 16`
- `MAX_VIEW_GRANTS_PER_TX = 8`
- `MAX_SHIELDED_PROOF_BYTES = 1536 * 1024` (1.5 MiB)

From the March 14 historical parameter snapshot in `src/shielded/lattice/params.h`:

- `RING_SIZE = 16`

From `src/validation.cpp`, `PrecheckShieldedProofPlausibility`:

- base lower bound: `2048` bytes
- per-input lower bound: `51200` bytes
- per-output lower bound: `15360` bytes

So even before measuring live transactions, the implementation already suggests that shielded proofs are heavy objects compared with transparent witness payloads.

## Measured Transactions

All measurements below were taken against a local regtest node built from this repository. These are runtime measurements of the actual serialized transaction form produced by the wallet and validated by the node, not just theoretical lower bounds.

### 1. Transparent P2MR Self-Send

Measured transaction:

- type: 1 transparent PQ input, 2 P2MR outputs
- txid: `30ff2066396386d63207e5b8ff8d52cc8a6abae635af2e79f4048573035612fd`
- serialized size: `3916` bytes
- vsize: `1082`
- weight: `4327`

Block fit estimate:

- serialized cap: `12,000,000 / 3916 ~= 3064`
- weight cap: `24,000,000 / 4327 ~= 5547`

Binding constraint:

- serialized size cap

Conclusion:

- Even with PQ transparent signatures, a BTX block can still carry on the order of three thousand simple transparent settlement transactions.

### 2. Transparent to Shielded Funding (`z_shieldfunds`)

Measured transaction:

- type: 1 transparent PQ input, 1 shielded output
- txid: `62ac95a95bb7aec6a8cd40e9b72de29f93958e6f4aa796b589d08054e55b9e72`
- serialized size: `5130` bytes
- vsize: `2298`
- weight: `9189`

Block fit estimate:

- serialized cap: `12,000,000 / 5130 ~= 2339`
- weight cap: `24,000,000 / 9189 ~= 2611`

Binding constraint:

- serialized size cap, slightly

Conclusion:

- Entering the shielded pool is not cheap, but it is still in the "thousands of transactions per block" regime rather than the "dozens" regime.

### 3. Fully Shielded Spend (1 Shielded Input, 1 Shielded Output)

Measured transaction:

- type: 1 shielded input, 1 shielded output, no transparent inputs, no transparent outputs
- txid: `3959007d70bf79cbdeebfacf4db049199a3d18abc79117a0e642c684964540f2`
- serialized size: `586196` bytes
- vsize: `586196`
- weight: `2344784`

Block fit estimate:

- serialized cap: `12,000,000 / 586196 ~= 20`
- weight cap: `24,000,000 / 2344784 ~= 10`

Binding constraint:

- weight cap

Conclusion:

- The current implementation permits only about 10 transactions of this class in a maximum block.

This is the pivotal result.

### 4. Shielded Spend to Transparent with Shielded Change

Measured transaction:

- type: 1 shielded input, 1 transparent output, residual shielded change
- txid: `14a999674593770e5e87e187509826bf65ed518ed6e93cb77a4977be733c1e9b`
- serialized size: `586239` bytes
- vsize: `586239`
- weight: `2344956`

This landed in essentially the same size class as the fully shielded spend. The extra transparent output barely changes the picture relative to the total proof payload.

Conclusion:

- Exiting the shielded pool through a shielded spend is capacity-constrained almost exactly the same way as note-to-note shielded transfer.

## Capacity Table

| Transaction class | Example shape | Serialized bytes | Weight | Fit by 12 MB cap | Fit by 24 MWU cap | Real block limit |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Transparent P2MR | 1 in / 2 out | 3,916 | 4,327 | 3,064 | 5,547 | 3,064 |
| Shielding | 1 transparent in / 1 shielded out | 5,130 | 9,189 | 2,339 | 2,611 | 2,339 |
| Shielded spend | 1 shielded in / 1 shielded out | 586,196 | 2,344,784 | 20 | 10 | 10 |
| Unshield with change | 1 shielded in / 1 transparent out (+ shielded change) | 586,239 | 2,344,956 | 20 | 10 | 10 |

## What Bridge Aggregation Already Buys

The new `bridge_estimatecapacity` RPC makes the bridge-side comparison
repeatable from measured transaction footprints instead of leaving it in ad hoc
notes. Using finalized regtest bridge settlements from this repository:

| Settlement class | Users represented by one L1 settlement | Serialized bytes | Weight | Real block limit | Represented users per block | Off-chain bytes per settlement |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Single bridge-out settlement | 1 | 4,043 | 4,325 | 2,968 | 2,968 | 0 |
| Three-user batch bridge-out settlement | 3 | 4,173 | 4,713 | 2,875 | 8,625 | 0 |
| Three-user proof-anchored batch settlement | 3 | 4,276 | 4,816 | 2,806 | 8,418 | 801,000 |

Interpretation:

- Even the single bridge-out settlement path is already about `296.8x` the
  represented users-per-block of the current native shielded baseline.
- Moving from one-user to three-user batched bridge-out settlement raises the
  represented users-per-block figure from `2,968` to `8,625` while barely
  changing the actual L1 transaction footprint.
- Adding proof anchoring only trims that figure from `8,625` to `8,418`, a
  drop of about `2.4%`, while making the much larger off-chain proof-storage
  burden explicit instead of hiding it.
- That is the modular rollup-style shape BTX wants:
  - compact L1 settlement bytes,
  - explicit off-chain proof / DA burden,
  - and many user actions represented by one accepted L1 settlement.

## Proving Supply Is Now The Bottleneck

The new prover-lane extension on `bridge_estimatecapacity` makes the next
constraint explicit: once BTX compresses many users into one small settlement,
the main question is no longer "can L1 fit it?" but "can the proving side
produce receipts fast enough to keep up with that compact settlement path?"

Using the same finalized three-user proof-anchored batch settlement above
(`4,276` bytes, `4,816` weight, `801,000` off-chain bytes), BTX can fit:

- `2,806` such settlements per block,
- `8,418` represented users per block,
- `112,240` such settlements per hour at the current `90 s` cadence,
- and `336,720` represented users per hour.

The prover model was then exercised with scenario inputs, not claimed vendor
benchmarks, chosen to reflect the current public split between:

- native pre-proof work,
- local CPU proving,
- local GPU proving,
- and remote prover-network supply.

| Lane | Scenario input | Sustainable users per block | Sustainable users per hour | Binding limit | Workers required to saturate current L1 path | Modeled hourly cost at saturation |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| Native pre-proof lane | `650 ms`, `32` workers | 8,418 | 336,720 | L1 | 21 | `$7.35` |
| CPU proving lane | `180,000 ms`, `32` workers | 48 | 1,920 | Prover | 5,612 | `$14,030.00` |
| GPU proving lane | `12,000 ms`, `8` workers | 180 | 7,200 | Prover | 375 | `$6,750.00` |
| Remote proving lane | `4,000 ms`, `16` workers, `8` parallel jobs each | 8,418 | 336,720 | L1 | 16 | `$256.00` |

Interpretation:

- The native pre-proof stage is not the hard limit in this modeled setup; it
  can already keep pace with the compact L1 settlement boundary.
- Local CPU-only proving is nowhere close. Even with `32` workers it sustains
  only `48` represented users per block, far below the `8,418` users per block
  the measured L1 settlement path could accept.
- Small local GPU footprints improve the picture materially, but they still
  leave proving as the binding limit rather than L1.
- The first modeled lane that actually keeps up with the measured compact L1
  path is a remote prover / prover-network style supply surface.
- That is the key architectural point for BTX:
  - bridge batching and proof anchoring solve the block-space side,
  - but production-scale private settlement still depends on how proof supply
    is provisioned and paid for.

## Artifact-Linked Prover Profiles Remove The Manual Timing Gap

The prover-capacity model now has a canonical bridge from imported proof
artifacts to settlement-wide timing assumptions:

- one `BridgeProverSample` per imported proof artifact,
- one `BridgeProverProfile` aggregating those samples for a single committed
  bridge batch statement,
- and `bridge_estimatecapacity` able to derive lane
  `millis_per_settlement` from that profile instead of requiring the caller to
  re-enter every timing number manually.

Measured on the same finalized three-user proof-anchored bridge settlement:

- prover sample size: `177` bytes
- prover profile size: `125` bytes
- artifact-backed storage represented by the profile: `801,000` bytes
- derived lane totals: `650 / 180,000 / 12,000 / 4,000 ms`
  for native / CPU / GPU / remote proving respectively
- artifact-storage delta between the profile and the measured settlement
  footprint: `0`

Interpretation:

- The reusable metadata needed to bind throughput assumptions to a real proof
  artifact set is tiny compared with the actual off-chain proof payloads.
- BTX no longer has to choose between:
  - storage accounting from real artifacts,
  - and throughput accounting from manual spreadsheet inputs.
- The same imported artifact set now drives:
  - compact proof receipts,
  - explicit off-chain storage accounting,
  - and reproducible prover-throughput estimates.

## Built-In Prover Templates Make Modeled Inputs Reusable

BTX now exposes a wallet-layer catalog of named prover templates tied to the
same proof-adapter families already used for imported receipts:

- SP1 compressed / Plonk / Groth16,
- RISC Zero composite / succinct / Groth16,
- and Blobstream-style SP1 / RISC Zero data-root tuple flows.

Measured on the same finalized three-user proof-anchored bridge settlement:

- built-in prover templates exposed by RPC: `8`
- template-backed prover sample size: `177` bytes
- template-backed prover profile size: `125` bytes
- template-derived lane totals:
  - native: `650 ms`
  - CPU: `180,000 ms`
  - GPU: `12,000 ms`
  - remote prover / network: `4,000 ms`
- template-derived sustainable users per block:
  - native: `8,418`
  - CPU: `48`
  - GPU: `180`
  - remote prover / network: `8,418`

Interpretation:

- The new template catalog does not change any canonical bridge serialization;
  it only replaces repeated ad hoc scenario entry with named reference inputs.
- The canonical sample/profile envelope stays compact while the modeled input
  layer becomes easier to reuse across SP1, RISC Zero, and Blobstream-style
  experiments.
- Because the templates are wallet-local, BTX can revise them as real prover
  measurements arrive without touching consensus or settlement commitments.
- That does not mean consensus is off limits. It means the benchmark and
  template layers are instrumentation surfaces that can inform a future
  consensus-breaking redesign if that redesign wins decisively on throughput.
- That is the correct boundary for the current external systems as re-checked
  on March 14, 2026:
  - [SP1 proof families](https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/enum.SP1Proof.html)
    still separate compressed, Plonk, and Groth16 envelopes.
  - [SP1 ProverClientBuilder](https://docs.rs/sp1-sdk/latest/sp1_sdk/client/struct.ProverClientBuilder.html)
    still presents local CPU / CUDA / network prover selection as an SDK-side
    operational choice.
  - [RISC Zero local proving](https://dev.risczero.com/api/generating-proofs/local-proving)
    still documents proving mode as an operational layer distinct from the
    receipt family itself.
  - [Celestia Blobstream proof queries](https://docs.celestia.org/how-to-guides/blobstream/proof-queries)
    still center the DA side on compact data-root proof tuples.
  - [Nillion Blacklight overview](https://docs.nillion.com/blacklight/learn/overview)
    still fits the same architectural split:
    compact commitments on L1, richer privacy / verification work off-chain.

## Repeated Prover Benchmarks Make Capacity Planning Honest

BTX now has a canonical repeated-run benchmark layer over prover profiles:

- one `BridgeProverBenchmark` per repeated experiment set,
- deterministic `min / p50 / p90 / max` summaries for native / CPU / GPU /
  remote-prover lanes,
- and direct `bridge_estimatecapacity` support for benchmarking against `p50`
  or `p90` instead of pretending a single run is representative.

Measured on the same finalized three-user proof-anchored bridge settlement:

- prover benchmark size: `273` bytes
- repeated prover profile size: `125` bytes
- `p50` lane totals:
  - native: `650 ms`
  - CPU: `180,000 ms`
  - GPU: `12,000 ms`
  - remote prover / network: `4,000 ms`
- `p90` lane totals:
  - native: `700 ms`
  - CPU: `190,000 ms`
  - GPU: `13,000 ms`
  - remote prover / network: `4,500 ms`
- sustainable users per block from the benchmark:
  - `p50`: `8,418 / 48 / 180 / 8,418`
  - `p90`: `8,418 / 45 / 165 / 7,680`
  - for native / CPU / GPU / remote prover respectively
- `BridgeProverBenchmarkBuild5Profiles`: `816.73 ns/profile`

Interpretation:

- The repeated-run benchmark makes the proving bottleneck harder to hand-wave:
  the `p90` case visibly degrades GPU and remote-prover throughput even though
  the L1 settlement boundary is unchanged.
- That is exactly the kind of data BTX needs before deciding whether the right
  answer is:
  - a richer proving market over the current bridge-validium path,
  - or a more ambitious hard-fork settlement format that compresses more of
    the private state transition into one consensus-recognized envelope.
- The external systems checked on March 14, 2026 still point in that direction:
  - [Agglayer benchmarks](https://docs.agglayer.dev/agglayer/core-concepts/pessimistic-proof/benchmarks/)
    still frame proof generation as a repeated benchmark problem.
  - [SP1 ProverClientBuilder](https://docs.rs/sp1-sdk/latest/sp1_sdk/client/struct.ProverClientBuilder.html)
    still exposes multiple proving backends rather than one universal latency
    number.
  - [RISC Zero Prover trait](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/trait.Prover.html)
    still abstracts over proving backends in the same way.
  - [Ethereum Dencun](https://ethereum.org/en/roadmap/danksharding/)
    and [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)
    still reinforce the broader lesson:
    base layers improve scale by changing the data / settlement model when
    needed, not by treating legacy envelopes as immutable.

## Hard-Fork Aggregate Settlement Prototype

BTX now has a canonical hard-fork aggregate-settlement model in
`src/shielded/bridge.*` rather than only prose about a possible future
consensus redesign.

The model adds:

- `BridgeAggregateSettlement`, a canonical settlement prototype tied to a batch
  statement hash,
- explicit payload placement for aggregate proof bytes and DA bytes:
  - `non_witness`,
  - `witness`,
  - `data_availability`,
  - or `offchain`,
- and a third capacity limit:
  - `block_data_availability_limit`.

That matters because the old capacity model could compare only:

- serialized block bytes,
- and block weight.

That was enough for bridge-validium, but not for blob-style or rollup-style
consensus paths where public batch data lives in a separate L1 lane.

### Measured Prototype Inputs

Modeled from the new aggregate-settlement functional test:

- one aggregate settlement represents `64` users,
- `24` of those users are modeled as first-touch wallets not previously
  materialized on L1,
- transaction shell:
  - `900` non-witness bytes,
  - `2,600` witness bytes,
  - `192` state-commitment bytes,
- aggregate proof payload:
  - `16,384` bytes,
- public DA payload:
  - `4,096` bytes.

That yields one canonical aggregate footprint of:

- `20,076` serialized bytes,
- `23,352` weight,
- `4,096` separate DA-lane bytes.

### Capacity Results

1. Witness-validium hard-fork path:
   - proof bytes in witness,
   - DA bytes off-chain,
   - `597` settlements per block,
   - `38,208` users per block.
2. Non-witness-validium hard-fork path:
   - proof bytes in non-witness,
   - DA bytes off-chain,
   - `331` settlements per block,
   - `21,184` users per block.
3. Witness-plus-DA-lane rollup path:
   - proof bytes in witness,
   - DA bytes in a `786,432` bytes/block DA lane,
   - `192` settlements per block,
   - `12,288` users per block.

For comparison:

- current measured proof-anchored bridge settlement: `8,418` users per block,
- current native shielded baseline: `10` users per block.

### Interpretation

- The consensus-redesign question is no longer hypothetical:
  - a hard-fork aggregate settlement materially outperforms the current
    bridge-validium path in the modeled witness-validium and witness-plus-DA
    modes.
- Witness discount for proof bytes is not cosmetic:
  - moving the same aggregate proof from witness to non-witness reduces
    modeled throughput from `38,208` to `21,184` users per block.
- A separate DA lane is the honest safety/performance trade-off:
  - if BTX wants rollup-style public data availability instead of pure
    validium, DA bytes become the binding limit quickly;
  - even then, the modeled rollup path still outperforms the current bridge
    proof-anchored baseline.
- That means the next hard problem is not "should BTX analyze a hard fork?"
  anymore.
  It is:
  - how to feed the new artifact-backed bundle path from live prover / DA
    outputs,
  - and how to compress the final proof envelope enough that the measured
    artifact-backed path can recover the earlier upper-bound throughput.

Primary-source context re-checked on March 14, 2026:

- [Ethereum zk-rollups](https://ethereum.org/en/developers/docs/scaling/zk-rollups/)
  still describe the exact split BTX is now modeling:
  off-chain execution, on-chain proof verification, and state-root updates.
- [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)
  still motivates the new third limit directly by formalizing a separate DA
  carriage path for rollups.
- [Aztec rollup circuits](https://docs.aztec.network/developers/docs/foundational-topics/advanced/circuits/rollup_circuits)
  still show recursive circuit layering as the natural structure for private
  batch aggregation.
- [Penumbra shielded pool](https://protocol.penumbra.zone/main/shielded_pool.html)
  still reinforces the state-tree / nullifier-set model for private ledger
  scale.
- [Celestia Blobstream proof queries](https://docs.celestia.org/how-to-guides/blobstream/proof-queries)
  still show compact data-root proof tuples as the right boundary between BTX
  settlement and external DA.

## Artifact-Backed Aggregate Settlement Replaces The Manual Upper Bound

The hard-fork section above established an optimistic upper bound by assuming:

- one `16,384` byte aggregate proof payload,
- one `4,096` byte DA payload,
- and no explicit artifact bundle tying those bytes to current imported proof
  families or state-externalization surfaces.

BTX now has a canonical artifact-backed alternative in `src/shielded/bridge.*`:

- `BridgeDataArtifact`
- `BridgeAggregateArtifactBundle`
- `BuildBridgeAggregateArtifactBundle(...)`

with wallet RPCs that expose the same boundary directly:

- `bridge_builddataartifact`
- `bridge_decodedataartifact`
- `bridge_buildaggregateartifactbundle`
- `bridge_decodeaggregateartifactbundle`

and `bridge_buildaggregatesettlement` now accepts `artifact_bundle_hex` /
`artifact_bundle` so the aggregate settlement footprint can be derived from
canonical proof/data manifests instead of manual proof and DA byte entries.

### Measured Artifact-Backed Results

The new functional path builds:

- one SP1 Groth16-style settlement proof artifact:
  - `393,216` proof bytes,
  - `96` public-values bytes,
  - `2,048` auxiliary bytes;
- one externalized state-diff artifact derived from the retention model:
  - `6,080` payload bytes,
  - `512` auxiliary bytes;
- one externalized snapshot artifact derived from the retention model:
  - `2,048` payload bytes,
  - `256` auxiliary bytes.

That one-proof artifact bundle yields:

- bundle totals:
  - proof payload: `393,312` bytes,
  - DA payload: `8,128` bytes,
  - auxiliary off-chain bytes: `2,816`,
  - total artifact storage: `404,256` bytes;
- aggregate settlement footprint:
  - `397,004` serialized bytes,
  - `400,280` weight,
  - `8,128` DA-lane bytes;
- block fit at
  - `12,000,000` serialized bytes,
  - `24,000,000` weight,
  - `786,432` DA bytes/block:
  - `30` settlements per block,
  - `1,920` users per block.

The same path with a second Blobstream-style proof artifact added
(`131,072` proof bytes, `72` public-values bytes, `8,192` auxiliary bytes)
yields:

- bundle totals:
  - proof payload: `524,456` bytes,
  - DA payload: `8,128` bytes,
  - auxiliary off-chain bytes: `11,008`,
  - total artifact storage: `543,592` bytes;
- aggregate settlement footprint:
  - `528,148` serialized bytes,
  - `531,424` weight,
  - `8,128` DA-lane bytes;
- block fit:
  - `22` settlements per block,
  - `1,408` users per block.

### Why This Matters

- The earlier `12,288 users/block` DA-lane rollup figure is now clearly an
  upper-bound model, not a current artifact-backed expectation.
- Switching from manual byte assumptions to canonical artifact bundles cuts
  the measured DA-lane hard-fork path to:
  - `1,920` users per block with one large settlement proof artifact,
  - `1,408` users per block when a second proof artifact is required.
- That is still far better than the current native shielded baseline of `10`
  users per block.
- But it is about:
  - `6.4x` lower than the earlier manual rollup model for the one-proof path,
  - `8.7x` lower for the two-proof path.
- So the hard blocker is now more precise:
  BTX does not merely need "some rollup proof."
  It needs either:
  - materially smaller final proof envelopes,
  - stronger recursive compression,
  - or a different consensus/storage design that avoids carrying current proof
    artifact sizes at the settlement boundary.

### Research Context

- [SP1 proof variants](https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/enum.SP1Proof.html)
  still separate compressed, Plonk, and Groth16 proof families, which matches
  BTX needing to treat the proof envelope itself as a throughput variable.
- [RISC Zero InnerReceipt](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/enum.InnerReceipt.html)
  still separates composite, succinct, and Groth16 receipt families in the
  same way.
- [Celestia Blobstream proof queries](https://docs.celestia.org/how-to-guides/blobstream/proof-queries)
  still frame DA verification as an additional proof/query surface rather than
  as free metadata.
- [Ethereum zk-rollups](https://ethereum.org/en/developers/docs/scaling/zk-rollups/)
  and [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)
  still reinforce the same lesson:
  proof and DA carriage are separate bottlenecks, and the final settlement
  envelope must be measured rather than assumed.

## Proof Compression Targets Replace Hand-Wavy Recursion Goals

The next hard blocker after the artifact-backed bundle pass was not another
helper type. It was the unresolved recursion question:

- which throughput targets are impossible even with a zero-byte final proof,
- and where proof compression can still recover the earlier hard-fork
  expectations.

BTX now has a canonical proof-compression target model in `src/shielded/bridge.*`:

- `BridgeProofCompressionTarget`
- `BridgeProofCompressionEstimate`
- `BuildBridgeProofCompressionTarget(...)`
- `EstimateBridgeProofCompression(...)`

with wallet RPCs that expose it directly:

- `bridge_buildproofcompressiontarget`
- `bridge_decodeproofcompressiontarget`

### Measured Compression Targets

Using the same one-proof artifact-backed batch from the previous section:

- `393,312` proof-payload bytes,
- `8,128` DA-lane bytes,
- `64` represented users per aggregate settlement,
- and current DA-lane capacity of `1,920` users/block.

BTX now shows that the artifact-backed DA-lane path cannot recover an `8k+`
throughput target through proof compression alone.

To represent at least `8,418` users/block on a `64`-user settlement shape,
BTX needs `132` settlements/block (`8,448` represented users at that
granularity). But with the current fixed `8,128` DA bytes per settlement:

- the zero-proof ceiling is only `96` settlements/block,
- which is `6,144` users/block,
- and the binding limit is still the DA lane.

That means the current artifact-backed DA-lane path cannot hit `8k+`
users/block even if the final proof shrinks to zero bytes.

The same artifact-backed batch on a witness-validium-style path is different:

- the current measured capacity is still `1,920` users/block,
- but the zero-proof ceiling rises to `208,000` users/block,
- so proof compression becomes the real binding variable again.

For that validium-style path, BTX now has exact proof-envelope targets:

- to reach `12,288` users/block:
  - final proof payload must be at most `58,808` bytes,
  - which is a reduction of `334,504` bytes from the current
    `393,312`-byte proof payload,
  - leaving `14.95%` of the current proof payload,
  - or `14.88%` of the current `395,360` total proof-artifact bytes
    including auxiliary data;
- to reach `38,208` users/block:
  - final proof payload must be at most `16,408` bytes,
  - which is a reduction of `376,904` bytes,
  - leaving `4.17%` of the current proof payload,
  - or `4.15%` of the current total proof-artifact bytes.

### Why This Matters

- The current artifact-backed DA-lane hard-fork path cannot be rescued by
  proof compression alone.
  BTX must either:
  - shrink the fixed published DA bytes,
  - raise the DA lane materially,
  - or stop treating that path as the way to recover `8k+` users/block.
- The validium-style hard-fork path remains viable, but only if the final
  recursive proof envelope is dramatically smaller than the current imported
  artifact:
  about `58.8 KiB` for `12,288` users/block and about `16.4 KiB` for
  `38,208`.
- That `16,408` byte ceiling is effectively the earlier manual
  `16,384`-byte upper bound again, but now it is derived from BTX's measured
  artifact-backed footprint rather than from an optimistic assumption.

### Research Context

- [SP1 proof variants](https://docs.rs/sp1-sdk/latest/sp1_sdk/proof/enum.SP1Proof.html)
  still distinguish compressed, Plonk, and Groth16 outputs, matching BTX's
  need to treat the final proof envelope as a first-class parameter.
- [RISC Zero InnerReceipt](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/enum.InnerReceipt.html)
  still distinguish composite, succinct, and Groth16 receipts at the same
  boundary.
- [Ethereum zk-rollups](https://ethereum.org/en/developers/docs/scaling/zk-rollups/)
  and [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)
  still reinforce the same protocol split:
  proof-envelope pressure and DA-lane pressure are separate constraints.
- [Celestia Blobstream proof queries](https://docs.celestia.org/how-to-guides/blobstream/proof-queries)
  still show that DA verification adds another proof/query artifact surface
  rather than disappearing into free metadata.
- [Nillion Blacklight overview](https://docs.nillion.com/blacklight/learn/overview)
  still fits the same architecture:
  private off-chain computation does not remove the need for a compact final
  settlement envelope.

## State Growth Becomes The Next Hard Limit

BTX now also has a canonical shielded-state growth model in `src/shielded/bridge.*`:

- `BridgeShieldedStateProfile`
- `BridgeShieldedStateEstimate`
- `EstimateBridgeShieldedStateGrowth(...)`

and wallet RPCs that expose the model directly:

- `bridge_buildshieldedstateprofile`
- `bridge_decodeshieldedstateprofile`
- `bridge_estimatestategrowth`

The important point is that a hard-fork aggregate settlement does not only
change block fit. It also changes how fast BTX accumulates:

- persistent commitment-index state,
- persistent nullifier-index state,
- snapshot appendix payloads for assumeutxo / pruned-node recovery,
- and hot-cache pressure from active nullifier tracking.

### Code-Derived Default State Profile

The current default coefficients are taken from the existing BTX codebase:

- commitment-index bytes per output:
  - `9` key bytes from `src/shielded/merkle_tree.cpp`,
  - `32` value bytes,
  - `41` total.
- nullifier-index bytes per input:
  - `33` key bytes from `src/shielded/nullifier.cpp`,
  - `1` value byte,
  - `34` total.
- snapshot appendix bytes:
  - `32` per commitment,
  - `32` per nullifier,
  - plus bounded recent anchor/output history from
    `src/node/utxo_snapshot.h` and `doc/assumeutxo.md`.
- nullifier hot-cache bytes:
  - `96` per nullifier entry from
    `src/shielded/nullifier.cpp::DynamicMemoryUsage()`.

### Measured State-Growth Results

For the witness-plus-DA-lane rollup path from the new functional test:

- `192` aggregate settlements per block,
- `12,288` represented users per block,
- `64` commitments and `64` nullifiers per settlement.

That produces:

- per settlement:
  - `4,800` persistent state bytes,
  - `4,096` snapshot appendix bytes,
  - `6,144` hot-cache bytes.
- per block:
  - `921,600` persistent state bytes,
  - `786,432` snapshot appendix bytes,
  - `1,179,648` hot-cache bytes.
- per day at `90` second blocks:
  - `884,736,000` persistent state bytes,
  - `754,974,720` snapshot appendix bytes,
  - `1,132,462,080` hot-cache bytes.

If BTX also charges `96` bytes for each first-touch wallet/account
materialization and keeps the same modeled `24` new wallets per settlement:

- persistent state rises to `7,104` bytes per settlement,
- `1,363,968` bytes per block,
- and `1,309,409,280` bytes per day.

For the higher-throughput witness-validium mode:

- `597` settlements per block,
- `38,208` represented users per block,
- `2,865,600` persistent state bytes per block,
- `114,624,000` persistent state bytes per hour,
- `2,750,976,000` persistent state bytes per day.

So the faster hard-fork path increases persistent state growth by about `3.11x`
relative to the DA-lane rollup path.

### Why This Matters

- The hard-fork throughput result is still strong:
  witness-validium is the highest-capacity modeled path so far.
- But higher L1 aggregate throughput does not come for free.
  It accelerates the exact shielded-state surfaces that pruned-node recovery,
  snapshots, and long-term archival burden depend on.
- That means a serious BTX consensus redesign must decide more than proof and
  DA placement. It must also decide:
  - what stays on-chain permanently,
  - what remains reconstructible from proof / DA artifacts,
  - when a never-before-seen wallet becomes real L1 state,
  - and how snapshot cadence should respond to multi-hundred-megabyte-per-day
    growth.

### Research Context

- [Aztec rollup circuits](https://docs.aztec.network/developers/docs/foundational-topics/advanced/circuits/rollup_circuits)
  continue to frame private rollups around dedicated state trees, not just
  proof aggregation.
- [Penumbra shielded pool](https://protocol.penumbra.zone/main/shielded_pool.html)
  continues to center privacy state around a commitment tree and nullifier set.
- [Ethereum zk-rollups](https://ethereum.org/en/developers/docs/scaling/zk-rollups/)
  and [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)
  continue to reinforce the same lesson:
  better proof / DA carriage can solve block-fit limits, but it does not make
  long-lived state disappear.
- [Nillion Blacklight overview](https://docs.nillion.com/blacklight/learn/overview)
  fits the same separation between compact on-chain commitments and richer
  off-chain privacy work.

## Retention Policy Becomes A Consensus Lever

BTX now also has a canonical retention-policy model in `src/shielded/bridge.*`:

- `BridgeShieldedStateRetentionPolicy`
- `BridgeShieldedStateRetentionEstimate`
- `EstimateBridgeShieldedStateRetention(...)`

and wallet RPCs that expose the same policy boundary directly:

- `bridge_buildstateretentionpolicy`
- `bridge_decodestateretentionpolicy`
- `bridge_estimatestateretention`

This moves the next hard problem out of vague design notes and into measured
trade-offs. Once aggregate settlement exists, BTX must decide not only how
many users one settlement can represent, but also which parts of the
resulting shielded state are:

- retained on L1 permanently,
- reconstructible from proof / DA artifacts,
- materialized immediately for first-touch wallets,
- or deferred into later recovery / replay work.

### Measured Retention Results On The DA-Lane Rollup Path

The new functional and unit coverage apply retention policies to the same
measured DA-lane aggregate settlement used in the state-growth section above:

- `192` aggregate settlements per block,
- `12,288` represented users per block,
- `24` newly materialized wallets per settlement in the full-retention case,
- `64` commitments and `64` nullifiers per settlement,
- `4 GiB` target snapshot budget.

#### Full-Retention Baseline

With the default policy:

- retain commitment index state,
- retain nullifier index state,
- include both commitments and nullifiers in snapshot exports,
- materialize `100%` of first-touch wallets on L1.

Measured result:

- per settlement:
  - retained persistent state: `7,104` bytes,
  - snapshot export: `4,096` bytes,
  - hot cache: `6,144` bytes;
- per block:
  - retained persistent state: `1,363,968` bytes,
  - snapshot export: `786,432` bytes,
  - hot cache: `1,179,648` bytes;
- per day:
  - retained persistent state: `1,309,409,280` bytes,
  - snapshot export: `754,974,720` bytes;
- time to a `4 GiB` snapshot target:
  - `5,461` blocks,
  - about `136` hours,
  - about `5` days,
  - about `67,104,768` represented users.

#### Proof-Backed Externalized Retention Policy

With a more aggressive policy:

- do not retain commitment-index history on L1,
- retain nullifier-index state,
- include only nullifiers in snapshot exports,
- materialize only `25%` of first-touch wallets on L1 and defer the rest to
  proof / DA-backed replay.

Measured result:

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
  - about `273` hours,
  - about `11` days,
  - about `134,209,536` represented users.

### Why This Matters

- The difference between aggregate-settlement designs is no longer only
  users-per-block.
- On the same DA-lane settlement path, BTX can choose between:
  - a full-retention model that keeps about `1.31 GB/day` of new persistent
    state on L1,
  - or an externalized model that cuts retained L1 growth to about
    `0.51 GB/day` while explicitly pushing about `0.80 GB/day` of persistent
    state and `0.38 GB/day` of snapshot bytes into the proof / DA side.
- That makes retention policy a consensus-scale performance knob, not just an
  implementation detail.
- If BTX accepts hard-fork redesigns for maximum throughput, it should also
  accept that state-retention rules may need to change just as aggressively as
  settlement rules.

### Research Context

- [Ethereum state expiry and statelessness](https://ethereum.org/en/roadmap/scourge/#state-expiry)
  continues to frame long-lived state as a separate scaling problem from pure
  execution throughput.
- [EIP-4444](https://eips.ethereum.org/EIPS/eip-4444)
  reinforces the same split by expiring old history from ordinary nodes
  instead of assuming every node keeps every byte forever.
- [Aztec rollup circuits](https://docs.aztec.network/developers/docs/foundational-topics/advanced/circuits/rollup_circuits)
  continue to organize private rollups around explicit state trees, which fits
  BTX needing to choose what aggregate-settlement state remains locally
  indexed.
- [Penumbra shielded pool](https://protocol.penumbra.zone/main/shielded_pool.html)
  continues to center privacy scale on a commitment tree and nullifier set,
  which is consistent with BTX treating retention policy as a first-class
  design surface.
- [Nillion Blacklight overview](https://docs.nillion.com/blacklight/learn/overview)
  still fits the same architectural split:
  compact on-chain commitments do not eliminate the need to choose where the
  richer private-state burden lives.

## Interpretation

### Transparent PQ Overhead Is Real but Not the Main Limiter

Compared with a classical Bitcoin-style signature system, BTX transparent transactions are much fatter because of the PQ stack. But they are still small enough that the chain can carry thousands of them per block.

That means PQ by itself does not collapse L1 into uselessness.

### Shielded Spending Is the Main Scarce Resource

The real constraint is the shielded spend proof and associated shielded bundle data. In the current implementation:

- shielded transaction bytes are charged as non-witness bytes,
- shielded spend proofs are very large,
- and each fully shielded spend consumes roughly one tenth of a block's weight budget.

So if many users tried to use L1 for ordinary private payment flow, the chain would saturate very quickly.

### What This Means for a Settlement-Layer Architecture

If BTX is intended to function as:

- L2 / bridge network for high-frequency transaction flow,
- L1 for infrequent settlement,
- L1 for shield-pool entry and exit,
- L1 for larger-value privacy-preserving settlements,

then the current capacity profile is harsh but not automatically fatal.

That architecture can still work, because settlement layers do not need retail transaction density.

But if the design intent is:

- broad consumer payment usage directly on L1,
- many concurrent shielded note-to-note transfers,
- routine use of the shielded pool for everyday traffic,

then the current economics and block occupancy strongly suggest impracticality.

## Is the Chain "Only Usable by a Small Number of People"?

The precise answer depends on how "people" are using it.

### If most activity is off-chain or bridged

Then no, not necessarily.

If a block only needs to absorb:

- occasional rollup commitments,
- bridge checkpoints,
- shielded ingress/egress,
- treasury movements,
- exchange settlements,
- and a relatively small number of high-value private settlements,

then the chain can remain perfectly usable as a settlement system even if only about 10 fully shielded spends fit per block.

That is a low throughput number, but settlement systems routinely operate with low transaction counts and high economic density per transaction.

### If users expect direct L1 private payment usage

Then yes, this becomes restrictive very quickly.

At about 10 simple fully shielded spends per block, the base layer has very little room for large populations to transact privately on-chain in a routine way.

In that model, blockspace becomes scarce enough that:

- fees will rise quickly under demand,
- confirmation latency pressure grows,
- and the system becomes unsuitable for broad daily-use transactional traffic.

## Fee and Policy Pressure

There is also policy-level pressure beyond bare block limits.

From `src/policy/policy.h`, shielded transactions receive extra relay/mining "verify weight":

- `SHIELDED_VERIFY_WEIGHT_PER_SPEND = 100000`
- `SHIELDED_VERIFY_WEIGHT_PER_OUTPUT = 20000`
- `SHIELDED_VERIFY_WEIGHT_PER_PROOF_KB = 1000`

That extra weight affects mempool admission and fee economics even though it does not redefine the consensus block cap itself.

In practical testing, a 1-input / 1-output shielded spend also required a materially higher fee than simple transparent transactions. That reinforces the same conclusion: shielded L1 usage is not only byte-heavy, it is operationally expensive to relay and mine.

## Most Important Design Takeaways

1. BTX L1 can still handle a meaningful number of transparent PQ settlement transactions per block.
2. Entering the shielded pool is much cheaper than spending within it.
3. The present implementation makes fully shielded spend transactions extremely scarce in blockspace terms.
4. The current design is defensible if BTX is intentionally a settlement chain for L2 / bridge activity.
5. The current design is not well suited to mass-market direct-on-L1 private payments without either:
   - substantially larger blocks,
   - materially smaller shielded proofs,
   - different weight accounting,
   - or a much stronger assumption that nearly all user activity stays off-chain.

## Bottom Line

The post-quantum transparent signature overhead is noticeable, but it is not the main threat to BTX block capacity.

The main constraint is that a basic fully shielded spend currently weighs about 2.344 MWU and occupies about 586 KB serialized, because shielded bundle bytes are charged as non-witness data. In practice that means only about 10 such transactions fit in a max block.

So the chain is not "impractical for almost anything" if it is honestly treated as a low-frequency settlement layer with L2 / bridging handling transaction flow. But it is impractical as a high-throughput direct-on-L1 shielded payments network for a large user base under the current transaction format and block limits.

## Practical Usage Model

The platform should be used as a layered system:

- **L1 transparent / P2MR** for settlement, bridge control, commitments, treasury moves, operator checkpoints, and general coordination.
- **L1 shielded** for ingress to privacy, egress from privacy, occasional high-value private settlement, and shielded rebalancing.
- **L2 / bridge domains** for frequent transactional activity.

That means the system should **not** be positioned as "everyone does ordinary shielded retail payments directly on L1."

Instead, the economically coherent model is:

1. Users move value into an L2 or operator-managed environment.
2. Most activity happens off-chain or inside a separate execution environment.
3. L1 is used for aggregate deposits, withdrawals, dispute / refund paths, periodic checkpoints, and selective shielded settlement.

Under this model, a scarce L1 shielded spend is acceptable because one L1 event can represent many off-chain user actions.

## What Is Actually Cheap vs Expensive

The cheap part of an L2 system is **activity after the user is already inside the L2**. Those updates can be off-chain messages, signed state transitions, operator ledger entries, or other non-blockchain events depending on the exact L2 design.

The expensive part is **crossing the L1/L2 boundary**:

- entering from L1 into an L2,
- exiting from an L2 back to L1,
- or converting a shielded L1 balance into a form usable by the L2.

Those boundary crossings require L1 settlement transactions.

So no, bridge-in / bridge-out is not automatically cheap merely because some L2 activity is off-chain.

In the current BTX transaction profile:

- **Transparent to shielded** is relatively cheap on L1: measured at ~5.1 KB / 9.2 kWU.
- **Shielded spend / unshield** is expensive on L1: measured at ~586 KB / 2.344 MWU.

Therefore:

- If an L2 accepts **transparent P2MR deposits**, L1 entry can be reasonably efficient.
- If using the L2 requires first **spending shielded notes on L1**, then the user pays the expensive shielded-spend class cost at the boundary.

This strongly suggests that a scalable deployment should minimize per-user shielded L1 exits and instead prefer:

- batched bridge operations,
- transparent settlement commitments where acceptable,
- and shielded L1 usage only where privacy is actually worth the scarce blockspace.

## Does the Fee Schedule Reflect the True Cost?

Broadly, yes: the current fee model does a better-than-naive job of pricing shielded spends.

There are two separate cost layers:

1. **Consensus block cost**
   - Shielded bundle bytes are counted as non-witness bytes, so they consume real scarce blockspace.
2. **Policy / relay cost**
   - The node adds extra relay/mining weight for shielded verification work.

Current policy surcharges are:

- `SHIELDED_VERIFY_WEIGHT_PER_SPEND = 100000`
- `SHIELDED_VERIFY_WEIGHT_PER_OUTPUT = 20000`
- `SHIELDED_VERIFY_WEIGHT_PER_PROOF_KB = 1000`
- fixed premium: `MIN_SHIELDED_RELAY_FEE_PREMIUM = 5000 sat`

For the measured 1-input / 1-output shielded spend:

- raw consensus vsize is about `586,196 vB`,
- policy extra weight adds about `692,000 WU`,
- effective relay vsize becomes about `759,196 vB`,
- and at a 1 sat/vB floor the relay fee floor is roughly `0.00759196 BTX`,
- plus the fixed premium gives roughly `0.00764196 BTX`.

That matches observed behavior much better than a simple "pay by raw bytes only" model would.

So the fee schedule is directionally aligned with real cost. It is not merely cosmetic. It explicitly makes shielded spends more expensive to relay and mine than equally-sized ordinary transactions.

What it does **not** do is magically eliminate the architectural scarcity. Correct pricing helps reveal the scarcity; it does not remove it.

## Bridge / L2 Implementation Status

This section separates what exists in the current repository from what is still architecture or specification.

Implementation update in the current tree: the BTX-side bridge contract layer
described in this handoff is now implemented in `src/shielded/bridge.*`,
`src/wallet/bridge_wallet.*`, `src/wallet/shielded_rpc.cpp`,
`src/test/shielded_bridge_tests.cpp`, `src/wallet/test/bridge_wallet_tests.cpp`,
and the `test/functional/wallet_bridge_*.py` lifecycle suite. The remaining
subsections are preserved as the original handoff snapshot and completion plan
that the implementation executed. Where the archived text below describes
missing work, read it as the March 14 handoff baseline rather than the current
repository state.

Post-implementation validation now also includes clean macOS and Linux/GCC
builds for the bridge stack. During this pass the root CMake warning wiring was
refined so C++-only warnings no longer leak into C compilation units in mixed
targets such as `bitcoin_crypto`, which keeps the repository's bridge/L2 build
surface warning-clean across both environments.

### Implemented Today

#### 1. Covenant substrate for bridge-style scripts

The codebase already implements the major P2MR covenant building blocks needed for bridge constructions:

- `OP_CHECKTEMPLATEVERIFY`
- `OP_CHECKSIGFROMSTACK`
- CLTV-based refund leaves
- HTLC-style leaves
- CTV+checksig leaves
- delegation / oracle-attested leaves

Relevant code:

- `src/script/interpreter.cpp`
- `src/script/pqm.cpp`
- `src/script/pqm.h`
- `src/script/descriptor.cpp`

There is test coverage for these pieces:

- `src/test/script_htlc_templates_tests.cpp`
- `src/test/pq_phase4_tests.cpp`
- `src/test/pq_descriptor_tests.cpp`
- `src/test/pq_policy_tests.cpp`
- `src/test/pq_consensus_tests.cpp`

So the covenant substrate is real, not hypothetical.

#### 2. Shielded pool core

The shielded transaction system itself is implemented:

- shielded bundle serialization and limits,
- note encryption,
- proof carriage,
- wallet creation of shielded transactions,
- RPC surface via `z_sendmany` and `z_shieldfunds`.

Relevant code:

- `src/shielded/bundle.h`
- `src/shielded/bundle.cpp`
- `src/wallet/shielded_wallet.cpp`
- `src/wallet/shielded_rpc.cpp`

#### 3. View-grant cryptographic primitive

The selective disclosure primitive exists as `CViewGrant`, with create/decrypt logic and tests.

Relevant code:

- `src/shielded/bundle.h`
- `src/shielded/bundle.cpp`
- `src/test/shielded_transaction_tests.cpp`

#### 4. Turnstile pool accounting

ZIP-209-style shielded pool accounting is implemented and wired into validation, rollback, rebuild, and rollforward paths.

Relevant code:

- `src/shielded/turnstile.h`
- `src/shielded/turnstile.cpp`
- `src/validation.cpp`
- `src/test/shielded_turnstile_tests.cpp`

#### 5. CTV now commits to shielded bundle contents

This is important because earlier documents treated it as an open blocker.

Current code in `src/script/interpreter.cpp` computes a shielded-bundle hash containing:

- `value_balance`
- `shielded_inputs`
- `shielded_outputs`
- `view_grants`
- `proof`

and folds that into the precomputed CTV commitment state when a shielded bundle is present.

So the earlier "CTV does not bind shielded outputs" concern appears to be resolved in the current tree.

### Pre-Implementation Gap Snapshot (Historical)

Despite the above pieces, the **actual end-to-end bridge product is not present** in the repository in a complete operational form.

#### 1. No concrete bridge module

The design/spec repeatedly references:

- `src/shielded/bridge.h`
- `src/shielded/bridge.cpp`

but those files are not present in `src/`.

So the bridge orchestration layer described in the spec is not implemented as a dedicated module.

#### 2. Historical gap: no bridge RPC / wallet workflow at handoff time

There is no dedicated user-facing RPC or wallet API for:

- bridge-in,
- bridge-out,
- operator attestation handling,
- bridge deposit monitoring,
- or refund-path orchestration.

The exposed shielded RPCs are generic:

- `z_sendmany`
- `z_shieldfunds`

They do not expose bridge-specific parameters such as operator KEM keys, view-grant recipients, bridge templates, attestation payloads, or refund path construction.

#### 3. Historical gap: no automatic use of view grants in wallet bridge flows

`CViewGrant` exists as a primitive, but I did not find wallet/RPC code that automatically inserts operator-facing view grants during shielding or unshielding.

At handoff time, that meant the compliance-oriented bridge disclosure model described in the spec was not yet surfaced as a real user workflow.

#### 4. No reference L2 engine in this tree

I did not find an implemented:

- rollup engine,
- state-channel system,
- bridge operator ledger,
- sequencer,
- withdrawal queue,
- challenge system,
- or batched settlement coordinator.

That is not automatically a defect in BTX core.

Different operators can build different L2 engines on top of BTX. BTX core does
**not** need to ship one canonical off-chain execution environment.

What it **does** need to ship is the standardized on-chain bridge / settlement
surface those operators can rely on.

So at handoff time the repo contained **L1 primitives and shielded mechanics**,
but not yet the complete standardized bridge product that would let many
external L2 implementations interoperate cleanly with BTX.

#### 5. Historical gap: no end-to-end bridge integration tests at handoff time

There are tests for the covenant pieces and tests for shielded components, but I did not find a concrete `shielded_bridge_tests.cpp` implementation in `src/test/` matching the spec's proposed bridge module.

So there is no clear evidence here of a working end-to-end:

- deposit,
- operator attestation,
- shielded bridge settlement,
- refund timeout,
- and withdrawal cycle.

## Original Remaining Work (Now Completed in Current Tree)

The original handoff identified the following work items. All of them are now
implemented in the current tree:

1. **A concrete bridge module**
   - Implement the missing `bridge.*` logic, or equivalent, as real production code rather than only spec text.

2. **Bridge wallet/RPC flows**
   - User-facing creation and monitoring of bridge-in / bridge-out transactions.
   - Operator attestation submission and verification flow.
   - Refund / timeout UX.

3. **View-grant integration**
   - Wallet support to generate bridge operator view grants automatically when the bridge design requires selective disclosure.

4. **Batching strategy**
   - If scale is the goal, bridge deposits and withdrawals need aggregation logic so one L1 event can represent many user actions.

5. **A standardized BTX-side bridge contract layer**
   - Core does not need to implement one universal L2 engine.
   - Core does need to implement the reusable on-chain bridge layer that
     different operators can target consistently.

6. **End-to-end integration tests**
   - Deposit -> attestation -> settlement -> withdrawal -> refund failure-path tests.

7. **Operational fee / UX policy**
   - The wallet should make clear when a requested bridge action will consume expensive shielded-spend blockspace versus cheaper transparent settlement blockspace.

## Original Operational Conclusion

The original handoff conclusion was:

- **bridge-capable at the primitive level**,
- **shielded-capable at the transaction level**,
- but **not yet a finished bridge/L2 system**.

The corresponding usage guidance at that time was:

- Do **not** assume there is already a complete cheap shielded bridge product in this tree.
- Do assume the underlying P2MR covenant tools and shielded components are strong enough to serve as the foundation for one.
- If the intended final architecture is large-scale L2 usage, the missing bridge orchestration and batching layers are not optional polish; they are the main remaining product work.

## Core vs Operator Boundary

This distinction should be frozen before more implementation work begins.

### What BTX Core Must Provide

These pieces belong in the BTX repository because different operators need a
common, auditable, interoperable settlement surface:

- canonical bridge script-tree builders,
- canonical bridge attestation message format and hashing helpers,
- wallet / PSBT helpers for bridge deposits, withdrawals, and refunds,
- standardized bridge RPCs for building and inspecting bridge plans,
- optional operator view-grant insertion for shielded bridge settlement,
- integration tests proving the chain-side bridge lifecycle works,
- documentation and user/operator guidance.

### What BTX Core Does Not Need To Provide

These pieces can legitimately vary by operator and do **not** need to live in
BTX core:

- rollup VM or application logic,
- state-channel protocol logic,
- sequencer / orderer,
- operator ledger or account model,
- withdrawal queue business rules,
- compliance platform or operator dashboard,
- indexing / analytics services,
- liquidity management and batching policy,
- fee-spread or commercial policy.

So the correct target is **not** "put the whole L2 into BTX core." The correct
target is "finish the common on-chain bridge layer so multiple L2
implementations can settle to BTX consistently."

## Continuous-Flow TDD Handoff (Historical Reference)

This archived section is the original implementation handoff for the follow-on
coding agent that completed the bridge contract layer now present in this tree.

### Goal

Deliver the **BTX-side bridge contract layer** required for multiple external L2
operators to interoperate with BTX without requiring BTX core to embed a single
canonical L2 engine. Status: completed in the current repository.

### Non-Goals

Do **not** implement any of the following inside BTX core as part of this work:

- a rollup sequencer,
- an operator ledger,
- an exchange or payment engine,
- an L2 VM,
- liquidity routing,
- or operator-specific business policy.

### Design Freeze

The follow-on implementation should adopt these constraints:

1. Reuse existing types where possible.
   - Do **not** create parallel bridge-local copies of `CShieldedBundle`,
     `CShieldedInput`, `CShieldedOutput`, or `CViewGrant`.
   - Reuse the existing implementations in `src/shielded/bundle.h`.
2. Reuse existing P2MR/PSBT machinery where possible.
   - P2MR selected-leaf support already exists.
   - P2MR CSFS message/signature PSBT fields already exist.
   - Bridge flows should populate those existing surfaces rather than inventing
     parallel metadata channels.
3. Keep the bridge module focused on BTX-side settlement primitives.
   - The bridge module should help build/verify plans and transactions.
   - It should not attempt to own operator off-chain state.
4. Keep bridge RPCs in a dedicated namespace.
   - Do not overload generic `z_*` RPCs with bridge-specific parameters.
5. Preserve the current CTV shielded-bundle commitment behavior.
   - The current tree already commits shielded bundle contents into the CTV
     precompute path; new bridge code must rely on that behavior, not bypass it.

### Recommended Branch

The implementation was developed on the dedicated branch:

- `codex/bridge-l2-core-handoff`

### Execution Order

The work below records the phases the implementation followed.

## Phase 1: Bridge Primitive Module

### Objective

Add the missing dedicated bridge module that wraps the already-implemented
P2MR covenant primitives into a standard bridge surface.

### Files To Add

- `src/shielded/bridge.h`
- `src/shielded/bridge.cpp`
- `src/test/shielded_bridge_tests.cpp`

### Files To Update

- `src/CMakeLists.txt`
- `src/test/CMakeLists.txt`

### Required Public API

The new module should at minimum expose:

- `BuildShieldBridgeScriptTree(...)`
- `BuildUnshieldBridgeScriptTree(...)`

Recommended supporting types:

- `BridgeDirection`
- `BridgeTemplateKind`
- `BridgeAttestationMessage`
- `BridgeOperatorConfig`
- `BridgePlanIds`

### Tests To Write First

Add unit tests in `src/test/shielded_bridge_tests.cpp` before implementing the
module:

1. `shield_bridge_script_tree_structure`
   - `BuildShieldBridgeScriptTree()` returns exactly two leaves.
   - Merkle root is non-null.
   - Leaf hashes differ.
2. `unshield_bridge_script_tree_structure`
   - `BuildUnshieldBridgeScriptTree()` returns exactly two leaves.
   - Merkle root is non-null.
   - Leaf hashes differ.
3. `different_ctv_hash_produces_different_bridge_root`
   - Mutating the CTV hash changes the resulting root.
4. `bridge_script_tree_is_deterministic`
   - Same inputs produce the same root and leaf hashes.
5. `bridge_control_block_verifies_leaf_commitment`
   - A control block for each leaf reconstructs the same root via
     `VerifyP2MRCommitment(...)`.
6. `bridge_script_tree_rejects_invalid_pubkey_or_timeout_inputs`
   - Invalid key material or invalid timeout parameters fail cleanly.

### Implementation Notes

- Use the existing low-level helpers from `src/script/pqm.cpp`:
  - `BuildP2MRCTVChecksigScript(...)`
  - `BuildP2MRRefundLeaf(...)`
  - `BuildP2MRCSFSScript(...)`
  - `ComputeP2MRLeafHash(...)`
  - `ComputeP2MRMerkleRoot(...)`
- Do not duplicate view-grant logic in `bridge.cpp`; `CViewGrant` already
  exists in `bundle.cpp`.
- The bridge module should be a thin standardization layer over the existing
  covenant substrate, not a second script framework.

### Acceptance Criteria

- Bridge script-tree builders compile and are test-covered.
- No duplicate bundle/view-grant types are introduced.
- The unit tests prove deterministic and verifiable bridge script trees.

## Phase 2: Canonical Bridge Attestation Format

### Objective

Standardize the message format operators sign for CSFS-based bridge actions so
independent operators produce interoperable attestation payloads.

### Files To Update

- `src/shielded/bridge.h`
- `src/shielded/bridge.cpp`
- `src/test/shielded_bridge_tests.cpp`

### Required Public API

Add helpers for canonical attestation bytes and hash calculation.

Recommended minimum API:

```cpp
enum class BridgeDirection : uint8_t {
    BRIDGE_IN = 1,
    BRIDGE_OUT = 2,
};

struct BridgeAttestationMessage {
    uint8_t version;
    uint256 genesis_hash;
    BridgeDirection direction;
    uint256 bridge_id;
    uint256 operation_id;
    uint256 ctv_hash;
    uint32_t refund_lock_height;
};

std::vector<uint8_t> SerializeBridgeAttestationMessage(const BridgeAttestationMessage&);
uint256 ComputeBridgeAttestationHash(const BridgeAttestationMessage&);
bool IsWellFormedBridgeAttestation(const BridgeAttestationMessage&);
```

### Why These Fields

- `version`: upgrade path
- `genesis_hash`: cross-chain replay protection
- `direction`: distinguish bridge-in vs bridge-out attestations
- `bridge_id`: operator / bridge instance domain separation
- `operation_id`: replay protection within the same bridge
- `ctv_hash`: binds the attestation to the exact on-chain settlement template
- `refund_lock_height`: binds the attestation to the refund window

### Tests To Write First

1. `bridge_attestation_serialization_is_deterministic`
2. `bridge_attestation_hash_changes_when_any_field_changes`
3. `bridge_attestation_rejects_zero_or_invalid_direction`
4. `bridge_attestation_rejects_missing_ctv_hash`
5. `bridge_attestation_rejects_wrong_network_domain`
   - Simulate mismatched `genesis_hash`.
6. `bridge_attestation_hash_roundtrips_with_csfs_domain`
   - Verify the bytes/hashes produced are usable with the existing
     `HASHER_CSFS` flow.

### Implementation Notes

- The operator still signs via the existing CSFS stack path.
- This phase defines the **message bytes** and **hash helper** only; it does
  not add a second signature scheme.
- The serialization must be fixed-width and deterministic.

### Acceptance Criteria

- There is one canonical attestation serialization path in core.
- Cross-chain and cross-bridge replay protection is explicit.
- CSFS consumers can rely on a stable message contract.

## Phase 3: Wallet-Level Bridge Plan Builders

### Objective

Provide reusable BTX-side plan builders so operators and wallets can construct
bridge deposits, bridge settlements, and refund transactions without manually
assembling leaf scripts and P2MR metadata.

### Files To Add

- `src/wallet/bridge_wallet.h`
- `src/wallet/bridge_wallet.cpp`
- `src/wallet/test/bridge_wallet_tests.cpp`

### Files To Update

- `src/wallet/CMakeLists.txt`
- `src/wallet/test/CMakeLists.txt`
- `src/wallet/shielded_wallet.h`
- `src/wallet/shielded_wallet.cpp`

### Required Public API

Recommended plan types:

```cpp
struct BridgeInPlan {
    uint256 ctv_hash;
    uint256 merkle_root;
    std::vector<unsigned char> normal_leaf_script;
    std::vector<unsigned char> normal_control_block;
    std::vector<unsigned char> refund_leaf_script;
    std::vector<unsigned char> refund_control_block;
    std::vector<CViewGrant> operator_view_grants;
};

struct BridgeOutPlan {
    BridgeAttestationMessage attestation;
    uint256 ctv_hash;
    uint256 merkle_root;
    std::vector<unsigned char> normal_leaf_script;
    std::vector<unsigned char> normal_control_block;
    std::vector<unsigned char> refund_leaf_script;
    std::vector<unsigned char> refund_control_block;
};
```

Recommended builders:

- `BuildBridgeInPlan(...)`
- `BuildBridgeOutPlan(...)`
- `CreateBridgeRefundTransaction(...)`
- `CreateBridgeShieldSettlementTransaction(...)`
- `CreateBridgeUnshieldSettlementTransaction(...)`

### Tests To Write First

1. `bridge_in_plan_contains_two_valid_control_paths`
2. `bridge_out_plan_contains_csfs_attestation_payload`
3. `bridge_in_plan_inserts_operator_view_grants_when_operator_kem_keys_present`
4. `bridge_in_plan_omits_view_grants_when_not_requested`
5. `bridge_refund_transaction_selects_refund_leaf`
6. `bridge_unshield_settlement_populates_selected_p2mr_leaf_and_csfs_message`
7. `bridge_plan_generation_reuses_existing_psbt_csfs_fields`
8. `bridge_plan_rejects_mismatched_operator_and_refund_keys`

### Implementation Notes

- Use existing selected-leaf and CSFS PSBT surfaces:
  - `PSBT_IN_P2MR_LEAF_SCRIPT`
  - `PSBT_IN_CSFS_MESSAGE`
  - `PSBT_IN_CSFS_SIGNATURE`
- Do **not** invent bridge-specific duplicate PSBT fields.
- Prefer a dedicated `bridge_wallet.*` layer instead of bloating
  `shielded_wallet.cpp` further.
- Reuse `CViewGrant::Create(...)` to attach operator viewing access where
  required by the bridge plan.

### Acceptance Criteria

- A caller can ask core to build a bridge plan without hand-assembling P2MR
  trees or CSFS messages.
- Refund path construction is standardized and test-covered.
- View-grant insertion is an explicit, auditable part of bridge planning.

## Phase 4: Bridge RPC Surface

### Objective

Expose the standardized bridge-planning and refund-building surface through a
dedicated RPC namespace suitable for wallets, operator daemons, and test
harnesses.

### Files To Update

- `src/wallet/shielded_rpc.cpp`
- `src/wallet/rpc/wallet.cpp`
- `src/rpc/client.cpp`
- `test/functional/`

### Minimum RPC Set

Recommended command set:

- `bridge_planin`
- `bridge_planout`
- `bridge_buildrefund`
- `bridge_decodeattestation`

If transaction creation is included in this phase, also add:

- `bridge_buildshieldtx`
- `bridge_buildunshieldtx`

### Tests To Write First

Add functional tests before wiring the RPCs:

1. `wallet_bridge_planin.py`
   - returns a deterministic plan structure and bridge root
2. `wallet_bridge_planout.py`
   - returns canonical attestation bytes/hash and refund metadata
3. `wallet_bridge_refund.py`
   - builds a refund transaction only after timeout eligibility
4. `wallet_bridge_viewgrant.py`
   - verifies operator view-grant payloads appear when requested
5. `wallet_bridge_psbt.py`
   - verifies PSBT output includes selected P2MR leaf and CSFS message fields

### Implementation Notes

- Keep bridge RPCs separate from generic shielded RPCs.
- RPC responses should return both human-readable fields and raw bytes/hashes
  needed by operator software.
- Error messages must clearly indicate whether failure is due to:
  - bad operator material,
  - bad timeout/refund parameters,
  - missing shielded notes,
  - or invalid plan construction.

### Acceptance Criteria

- A bridge operator daemon can call BTX RPCs to build/inspect the chain-side
  bridge artifacts it needs.
- RPCs do not assume any particular off-chain L2 engine.

## Phase 5: End-to-End Bridge Lifecycle Tests

### Objective

Prove that the BTX-side lifecycle works under regtest:

- setup,
- normal bridge settlement,
- attested withdrawal,
- and refund fallback.

### Files To Add

- `test/functional/wallet_bridge_happy_path.py`
- `test/functional/wallet_bridge_attested_unshield.py`
- `test/functional/wallet_bridge_refund_timeout.py`

### Required Scenarios

1. **Bridge-In Happy Path**
   - User funds a bridge P2MR output.
   - Operator completes the shield settlement path.
   - The resulting shielded transaction contains the expected bundle and optional
     view grants.
2. **Bridge-In Refund Path**
   - User funds a bridge P2MR output.
   - Operator does not complete the bridge.
   - After timeout, user spends through the refund leaf.
3. **Bridge-Out Happy Path**
   - Operator prepares unshield path.
   - Canonical attestation bytes are signed.
   - On-chain spend succeeds through the CSFS normal path.
4. **Bridge-Out Refund Path**
   - Operator becomes unresponsive.
   - After timeout, refund path is spendable.
5. **PSBT / External Signer Interop**
   - Selected P2MR leaf and CSFS message/signature metadata round-trip through
     PSBT for a bridge plan.

### Acceptance Criteria

- At least one regtest functional test covers each of the four lifecycle paths.
- Refund logic is proven, not merely documented.
- CSFS attestation data survives PSBT round-trips.

## Phase 6: Documentation Completion

### Objective

Document the bridge/L2 surface in all user-facing docs once the code lands.

### Files To Update

- `README.md`
- `doc/README.md`
- `doc/btx-shielded-pool-guide.md`
- `doc/JSON-RPC-interface.md`
- this file

### Required Documentation Outcomes

1. README clearly distinguishes:
   - bridge-capable primitives already implemented,
   - standardized bridge product still pending / newly implemented,
   - external L2 engines remain operator-specific.
2. Shielded pool guide explains:
   - when bridge-in/out is cheap vs expensive,
   - why shielded L1 spending is scarce,
   - and how bridge flows should be used operationally.
3. RPC docs cover bridge planning and refund commands.
4. This document remains the implementation-status and design-handoff source of truth.

## Definition of Done

The BTX-side bridge work should only be called complete when all of the
following are true:

1. `src/shielded/bridge.h/cpp` exists and is covered by unit tests.
2. Canonical bridge attestation bytes/hashes are defined and test-covered.
3. Wallet/PSBT bridge planning helpers exist and reuse current P2MR/CSFS
   metadata surfaces.
4. Operator view-grant insertion for shielded bridge flows is supported.
5. Bridge RPCs exist in a dedicated namespace.
6. Regtest functional tests cover happy-path and refund-path bridge flows.
7. README and docs are updated to reflect the final operator/core boundary.

## Implementation Risks To Watch

These are the highest-signal risks a follow-on agent should keep in view:

1. **Type duplication risk**
   - The old spec text sketches bridge-local `ViewGrant` / `ShieldedBundle`
     types, but current core already has real `CViewGrant` / `CShieldedBundle`
     implementations. Do not fork these types.
2. **RPC creep**
   - Bridge RPCs should expose BTX-side settlement artifacts only, not operator
     business workflows.
3. **Per-user L1 cost explosion**
   - The implementation should bias toward batching and planning, not encourage
     one shielded L1 spend per user action.
4. **Replay-domain ambiguity**
   - Attestation messages must bind chain identity and operation identity.
5. **Documentation drift**
   - The bridge guide, README, and RPC docs must be updated as the code lands
     so the operator/core boundary remains explicit.

## Reproduction Notes

Relevant code paths:

- `src/consensus/consensus.h`
- `src/consensus/validation.h`
- `src/test/shielded_transaction_tests.cpp`
- `src/shielded/bundle.h`
- `src/shielded/lattice/params.h`
- `src/validation.cpp`
- `src/policy/policy.h`
- `src/policy/policy.cpp`
- `src/wallet/test/pq_wallet_tests.cpp`
- `test/functional/rpc_pq_wallet.py`

Measured on local regtest with the built binaries from this repository.
