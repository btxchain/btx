# MatMul v4.7 consensus transition roadmap

Status: **canonical documentation for the proposed PR; all activation heights
remain disabled.** This document describes the intended transition and does
not itself activate consensus.

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

### 1.1 Disabled merge state and atomic Epoch-A contract

Merging the implementation PR activates no consensus change. On every public
network, the v4, BMX4C, and RC heights remain `INT32_MAX`; DRLT, coupled RC,
HeaderPoW, unfinished Stage-3 authority, and toy dimensions remain disabled;
Profile 1 is merely the inert pre-activation selector; and
`BTX_MATMUL_NO_INVERSION_GATE_RATIFIED` remains false.

After all gates in §4 close, a separate activation PR may choose `H_A`. That PR
must set the following tuple atomically:

| Component | Required value at Epoch A |
|---|---|
| Heights | `nMatMulV4Height = nMatMulBMX4CHeight = nMatMulRCHeight = H_A` |
| Withdrawn/intermediate paths | `nMatMulDRLTHeight = nMatMulRCCoupledHeight = INT32_MAX` |
| Workload | `nMatMulRCProfile = 1`, production dimensions, four-round replay |
| Authority | ExactReplay; Stage-3 proof authority remains disabled |
| Header admission | HeaderPoW disabled; the fixed header remains 182 bytes |
| ASERT | v4 and BMX4C ratios remain `1/1`; only the live RC branch receives the measured one-time calibration |
| Ratification | explicit L0 ratification remains a separate reviewed decision |

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
- actual two-winner zero-gap worker drain: **56.439502250 seconds**;
- three-branch canonical verdict after reorg: **28.101862542 seconds**;
- full Metal pipeline with zero CPU contraction calls or fallbacks.

The reported RTX 5060 Ti CUDA campaign is additional cross-backend evidence:
its 12 loaded samples observed approximately 21.36 seconds at the tail and its
four-block mine/verify cycle observed approximately 42.37 seconds. Because 12
samples cannot substantiate a stable p99 estimate, the CUDA host must repeat
the corrected 100-sample, dimension-bound campaign before activation review.

## 4. Epoch-A activation gates

Merging the implementation PR and activating Epoch A are separate decisions.
The implementation PR keeps production activation heights disabled.

Before an activation-height PR:

1. Metal, CUDA, and portable execution must produce byte-identical corrected
   golden digests for the same frozen headers.
2. Every required accelerator campaign must contain at least 100 continuous
   dimension-bound runs with exact device-coverage telemetry.
3. Actual-consensus back-to-back and three-branch reorg tests must remain
   bounded with one device submitter.
4. Invalid ticketed candidates must not starve the authenticated-tip lane.
5. A deliberately faulted device result must exercise deterministic portable
   retry without peer punishment or divergent validity.
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
- Device mismatch invokes the portable oracle before permanent rejection or
  peer punishment.

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

The branch now selects Profile 1 as the disabled pre-activation default and
keeps the complete public Epoch-A tuple disabled. The proposed integration PR
must retain and explicitly test the disabled tuple while keeping Epochs B–D
unreachable. An activation height, calibrated RC ratio, and L0 ratification are
intentionally not part of this branch; merging it leaves mainnet on v3.

## 8. Documentation precedence

For the proposed PR:

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
