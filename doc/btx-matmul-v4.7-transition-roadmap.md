# MatMul v4.7 consensus transition roadmap

Status: **canonical documentation for the MatMul v4.7 transition. Epoch A is
ACTIVATED on mainnet at block height 181'894** (`nMatMulV4Height =
nMatMulBMX4CHeight = nMatMulRCHeight = 181'894` in
`src/kernel/chainparams.cpp`, both ratification constants true in
`src/consensus/params.h`, RC ASERT rescale `4294967295/1` installed).
Testnet and signet heights remain disabled, as do Epochs B–D everywhere.
This document records the transition contract, the evidence that closed the
Epoch-A gates, and the gates that were explicitly accepted as residual risk
(§4). The activation itself lives in the consensus source, not here.

## 1. Naming and scope

**MatMul v4.7** is the name of the complete transition architecture in this
branch. It is not the value of one existing profile selector:

- `nMatMulRCProfile=1` selects the four-round Resident Curriculum workload
  used by the interim ExactReplay launch candidate.
- `nMatMulRCProfile=2` selects the approximately 16-times-heavier datacenter
  workload reserved for proof-authoritative operation.
- Existing `V2`, `V3`, `V7`, and similar proof/coupled-profile labels identify
  internal historical constructions. They must not be read as the
  v4.7 network transition epoch.

The v4.7 design preserves the 182-byte digest-only block header and the
header-derived work statement. Verification authority and proof carriage can
change at later heights without redefining the work already committed by the
header. Epoch A adds no proof or witness bytes to blocks. Epoch B may add a
separately specified durable proof object to consensus data, so its exact byte
budget, commitment, relay, pruning, and IBD rules must be reviewed before that
epoch can activate.

### 1.1 Atomic Epoch-A contract — now installed on mainnet

Historical contract: through every implementation-only release, all public
v4, BMX4C, and RC heights stayed `INT32_MAX`; DRLT, coupled RC, HeaderPoW,
unfinished Stage-3 authority, and toy dimensions stayed disabled; Profile 1
was the inert pre-activation selector; and
`BTX_MATMUL_NO_INVERSION_GATE_RATIFIED` stayed false.

The activation commit set the tuple atomically on mainnet at
`H_A = 181'894`, satisfying the contract as follows:

| Component | Contract at Epoch A | Installed mainnet value |
|---|---|---|
| Heights | `nMatMulV4Height = nMatMulBMX4CHeight = nMatMulRCHeight = H_A` | all three `181'894` |
| Withdrawn/intermediate paths | `nMatMulDRLTHeight = nMatMulRCCoupledHeight = INT32_MAX` | both `INT32_MAX` (disabled) |
| Workload | `nMatMulRCProfile = 1`, production dimensions, four-round replay | Profile 1, `matmul_dim = 4096` |
| Authority | ExactReplay; Stage-3 proof authority remains disabled | ExactReplay only |
| Header admission | HeaderPoW disabled; the fixed header remains 182 bytes | disabled; 182 bytes |
| ASERT | v4 and BMX4C ratios remain `1/1`; RC owns the reviewed final-binary calibration | v4/BMX4C `1/1`; RC `4294967295/1` — the saturated uint32 ceiling of the measured two-rig calibration (the larger measured CUDA-rig value is not expressible in the uint32 field; see `kRCEpochAAsertRescaleNum` in `src/kernel/chainparams.cpp`) |
| Ratification | explicit L0 ratification is a separate reviewed decision | `BTX_MATMUL_NO_INVERSION_GATE_RATIFIED` and `BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED` flipped true, with the recorded basis and the accepted residual risk documented at the flags (`src/consensus/params.h`) |

The equality of the three heights prevents any digest-only v4/BMX4C interval
before ExactReplay authority. The ASERT assignment is deliberately
single-owner: because RC is the live dispatch branch at the unified height,
placing the same calibration on v4 or BMX4C would be ambiguous or risk double
application. HeaderPoW cannot be part of this tuple because its local grind
nonce is not serialized in the fixed header; Poseidon2 `rcadmit`, quotas, and
zero unauthenticated chainwork provide admission policy instead.

## 2. Four consensus epochs

Each epoch requires a separately reviewed activation height. No implementation
may infer or collapse one height into the next.

| Epoch | Workload | Consensus authority | Succinct proof | ExactReplay |
|---|---|---|---|---|
| A — P1 ExactReplay / optional proof | Profile 1 | ExactReplay | Optional, shadow-only | Required for every claimed block |
| B — P1 dual validation | Profile 1 | Proof **and** ExactReplay | Mandatory, durable, consensus-checked | Still required |
| C — P1 proof authority | Profile 1 | Succinct proof | Mandatory and authoritative | Optional non-consensus audit |
| D — P2 proof authority | Profile 2 | Succinct proof | Mandatory and authoritative | Optional non-consensus audit |

### Epoch A — Profile 1 ExactReplay, proof optional

Profile 1 is four sequential rounds, 16 FFN layers, `b_seq=16,384`, and
`T_leaf=1,024`. ExactReplay is epsilon-zero consensus authority. An optional
proof may be produced, relayed, and shadow-verified, but it cannot:

- accept or reject a block;
- contribute chainwork or fork-choice weight;
- punish a peer;
- replace replay; or
- create a dependency on process-local proof availability.

This is the only epoch proposed for the first activation-height PR.

### Epoch B — Profile 1 mandatory proof plus ExactReplay

The proof format, transcript, algorithm hash, serialization, and availability
rules must be frozen before this height. Every block must pass both the
succinct verifier and ExactReplay. ExactReplay retains unconditional soundness
while the mandatory proving and distribution system completes a bounded
consensus burn-in.

A mandatory proof is durable consensus data. It may be a canonical block
attachment or an equivalently committed and retrievable object, but it may not
exist only in the ephemeral `rcadmit` or optional relay sidecar stores.

### Epoch C — Profile 1 succinct-proof authority

The proof becomes the sole deterministic consensus authority while the
workload remains Profile 1. ExactReplay may continue as background auditing,
telemetry, dispute evidence, or operator policy, but a local replay result may
not independently change consensus validity after this height.

Keeping Profile 1 for this epoch isolates the proof-authority transition from
the workload-size transition.

### Epoch D — Profile 2 succinct-proof authority

Only after Profile 1 proof authority has operated successfully does a separate
height select Profile 2: eight rounds, 24 FFN layers, `b_seq=87,552`, and
`T_leaf=4,096`. The corresponding difficulty/work calibration must activate
atomically with Profile 2. Profile 2 ExactReplay remains a diagnostic oracle,
not the routine validator requirement.

Epochs B, C, and D require new, explicit height-versioned selectors before
they can be implemented: at minimum a proof-required height, a proof-authority
height, and a Profile-2 workload height. Dispatch must evaluate those selectors
against the block being validated. A later release must not flip the current
global Stage-3 readiness value or change the global Profile-1 selector in a way
that causes historical Epoch-A blocks to be replayed or judged under Epoch B,
C, or D rules.

## 3. Measured Epoch-A evidence

The corrected Apple M4 Max Metal campaign used 100 distinct
`matmul_dim=4096` headers:

- loaded nearest-rank p99: **28.210448250 seconds**;
- maximum replay: **28.362590458 seconds**;
- worst adjacent pair: **56.495303916 seconds**;
- actual two-winner zero-gap worker drain: **56.407940500 seconds**;
- ticketed-invalid preemption: **1.528641959 seconds**, with the honest verdict
  **30.207028375 seconds** after the flood began and zero invalid completions;
- three-branch canonical verdict after reorg: **29.708123583 seconds**;
- deterministic injected-device mismatch under the pre-activation
  `auto-fallback` policy: two identical portable recoveries of an honest claim
  plus fail-closed confirmation of a false claim; the production
  `strict-device` policy instead classifies the mismatch as local and leaves
  the block retryable, without quarantining the provider (a sole device
  disagreement is `UnconfirmedDigestMismatch`, which is deliberately not
  quarantinable);
- full Metal pipeline with zero CPU contraction calls or fallbacks.

The sanitized Blackwell-class CUDA campaign is additional cross-backend
evidence. The tip-correlated 2026-08-01 artifact
(`doc/evidence/cuda-blackwell-16gib-profile1-loaded-2026-08-01/`) records 100
distinct production headers with nearest-rank p99 32.705 seconds, maximum
32.709 seconds, zero CPU GEMM fallbacks, and CUDA TU md5
`ed1e9477432b1766f549c039b6779632` matching the campaign tip. The earlier
2026-07-30 report remains historical (stale fingerprint vs current tip). The
committed reports record only a broad hardware class and contain no hostname,
username, personal path, or device serial. This 2026-08-01 campaign did not
by itself constitute activation evidence; see §4 for which gates the later
sealed cohort, soak, and calibration artifacts closed, and which were never
met. L0 ratification has since been recorded (both flags true,
`src/consensus/params.h`).

## 4. Epoch-A activation gates — status at the 181'894 activation

The activation shipped. This section records what closed and what did not.

**Closed by committed evidence** (all under `doc/evidence/`):

- **Sealed CUDA+Metal golden cohort at one code freeze**
  (`multi-gpu-profile1-goldens-cuda-metal-2026-08-03-sealed`): both providers
  reproduced from the same `source_revision` and build-relevant
  `source_tree_fingerprint`, all eight digests and frozen header byte strings
  byte-identical, zero CPU GEMM calls/MACs/fallbacks; passed the hardened
  provenance comparator and is committed as the production golden manifest
  (`CommittedRCProductionGoldenManifest()` in
  `src/matmul/matmul_v4_rc_production_canary.cpp`). This closes gate 1 below.
- **Zero-fallback lifecycle/soak campaign across the RC boundary**
  (`cuda-profile1-soak-2026-08-02`): 45 minutes, 38 scenarios (relay,
  competing branches, restart, cache persistence, IBD boundary) on two local
  regtest peers, zero failures. This covers the restart/cache/IBD mechanics
  of gate 7 but explicitly does not claim gate 7 itself
  (`gate7_multi_day_multi_peer_claim = false` in its summary).
- **Two-rig, two-vendor ASERT calibration**
  (`asert-two-rig-calibration-2026-08-03`): both halves of the v3-vs-RC ratio
  measured on the same silicon on two vendors; the installed
  `4294967295/1` rescale is the saturated uint32 ceiling of that
  measurement. This closes the calibration half of gate 9; the activation
  commit itself closed the atomic-tuple and ratification half.

**Explicitly NOT met, accepted as residual risk by the operator in flipping
the ratification flags** (recorded at
`BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED`, `src/consensus/params.h`):

- multi-day wall-clock soak;
- multi-peer public testnet topology (gate 7 as written below);
- upgrade behavior across released binaries.

Other items below (HIP reproduction — optional per the golden policy and
still fail-closed with no committed corpus; a final-binary re-run of the
dated 100-run loaded campaigns; frozen checkpoint/IBD disclosures) were not
recorded as closed in the activation evidence and should be read
accordingly. Do not cite this section as claiming more than the three
closed artifacts above.

The pre-activation contract required:

1. Reproduce the CUDA+Metal ExactReplay corpus byte-identically on the same
   frozen production canary headers
   (`contrib/matmul-v4/multi-gpu-golden-corpus.sh`) from the exact code freeze.
   Portable CPU is the diagnostic oracle, not an independently viable launch
   provider; optional HIP evidence must match the cohort.
2. Every required accelerator campaign must contain at least 100 continuous
   dimension-bound runs with exact device-coverage telemetry.
3. Actual-consensus back-to-back and three-branch reorg tests must remain
   bounded with one device submitter.
4. Invalid ticketed candidates must not starve the authenticated-tip lane.
   The M4 Max production-shape test now passes; the final CUDA build and
   multi-peer testnet soak must reproduce it.
5. A first device/header digest disagreement in `strict-device` mode must be
   classified as `LocalAcceleratorFailure`, leave the block retryable, and
   avoid peer punishment, a negative-verdict cache, or provider quarantine.
   Quarantine is reserved for a confirmed execution/coverage failure or for a
   provider proven faulty by independent adjudication. The explicit
   pre-activation `auto-fallback` test may retain portable recovery, but that
   path is not production validation. Final accelerator builds must reproduce
   mismatch retry, execution-failure quarantine, restart/alternate-provider
   recovery, and retry.
6. Header/body serialization and the no-chainwork-before-ExactReplay
   invariants must pass in the final candidate binary.
7. A multi-day testnet soak must cover block relay, competing branches,
   restarts, cache persistence, IBD boundaries, and upgrade behavior.
8. Checkpoint and historical-sync trust assumptions must be disclosed.
9. The atomic tuple, measured RC ASERT ratio, and explicit L0 ratification must
   be a separate, narrow review with an operator upgrade window and a
   pre-activation stop procedure. A partial tuple must fail construction.

## 5. Near-tip and admission invariants

- Header-first replay may overlap body transfer and transaction validation.
- A candidate has no authenticated chainwork, fork-choice influence, or mining
  eligibility until ExactReplay succeeds in Epochs A and B.
- The shared production unauthenticated-work allowance is zero: even one
  unverified MatMul header cannot displace an authenticated tip on claimed
  work. Headers may still be retained and used to schedule body download.
- The verifier uses one submitter per saturated accelerator, duplicate-hash
  collapse, authenticated-tip priority, bounded competing branches, stale-job
  cancellation, and persistent successful verdicts.
- `rcadmit` remains P2P admission policy, never consensus authority.
- Requested historical bodies during IBD may bypass the ephemeral `rcadmit`
  ticket only; they still consume verifier budgets, run ExactReplay, and gain
  no authenticated chainwork before success. Unsolicited IBD bodies do not
  receive this exception.
- Poseidon2 admission work, per-peer/netgroup budgets, and global caps must be
  enforced together.
- In production `strict-device` mode, device mismatch is a local failure that
  leaves the block retryable; it never triggers inline portable replay,
  permanent rejection, peer punishment, or provider quarantine. Quarantine is
  reserved for `ExecutionFailure`.

## 6. Proof-security gates

Epochs B–D remain disabled until:

- the complete statement, round-seed chain, transcript, ExtractMX behavior,
  Merkle binding, target binding, and block-header projection are proven or
  independently audited;
- the proof verifier has adversarial vectors and independent implementation
  coverage;
- proof bytes and verification time fit their frozen budgets;
- proof generation succeeds under sustained production workload;
- mandatory proof data remains available through relay, reorgs, restart, and
  IBD; and
- historical proof backfill is complete before checkpoints cease to be
  load-bearing.

No sampled/Freivalds precheck, carrier, shadow verifier, environment variable,
or process-local cache may silently become proof authority.

## 7. Current branch state

The branch contains the Profile 1 ExactReplay implementation, end-to-end Metal
acceleration, near-tip scheduler, admission policy, and local evidence. It
also retains Profile 2 and unfinished Stage-3 proof machinery for continued
development.

The branch selects Profile 1 and installs the complete mainnet Epoch-A tuple:
`nMatMulV4Height = nMatMulBMX4CHeight = nMatMulRCHeight = 181'894`, the RC
ASERT rescale `4294967295/1`, both ratification flags true, and the populated
CUDA+Metal production golden manifest. Epochs B–D remain unreachable (no
height-versioned proof selectors exist), and testnet/signet remain on v3
with all transition heights disabled. Mainnet leaves v3 at height 181'894.

## 8. Documentation precedence

For this branch:

1. this roadmap defines transition intent and epoch terminology;
2. `matmul-v4-exact-replay-launch-candidate.md` defines the measured Epoch-A
   launch gates;
3. the current normative workload/proof specifications define byte-level
   algorithms within their stated epoch; and
4. dated audits, measurement reports, scratchpads, and superseded version
   proposals are historical evidence only.

Historical documents must retain their original findings but carry an explicit
status notice pointing to this roadmap when their recommendations or defaults
conflict with v4.7.
