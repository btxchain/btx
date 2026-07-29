> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX v4.5 episode AIR compact verifier measurement — 2026-07-22

Branch: `wip/air-episode-compact`

Remote WIP base tested: `9fc907f3a6` (`Stage-C Piece 1 — Poseidon2-Goldilocks algebraic permutation`)

Local scope: additive verifier-only patch and measurement report. No activation
flags were flipped: `kRCGkrFormalSoundnessReady=false`,
`nMatMulRCHeight=INT32_MAX`, arbiter off.

## Test results

- Build target: `test_btx` succeeded.
- `matmul_v4_rc_air_episode_tests`: 5/5 cases, 81/81 assertions passed.
- No-regression set:
  `matmul_v4_rc_air_quotient_tests,matmul_v4_rc_gkr_tests,matmul_v4_rc_gkr_integration_tests`
  passed: 90/90 selected cases, 5405/5405 assertions.
- Fp3 seam grep on the episode AIR path found no Fp2 lookup/append seam in
  `matmul_v4_rc_air_episode.{h,cpp}` or its test. The episode path is
  `AirConstraintSystem<Fp3>` / `AirQuotientProof<Fp3>` / `AirQuotientVerify<Fp3>`
  / Fri3 end-to-end.

## Mechanism-level forgery rejects

- `ArbitraryAbFactorization`: `v7c:air:shard 0: quotient identity C(y) != Q(y)*Z_H(y)`
- `FabricatedTraceWires`: `v7c:air:shard 0: quotient identity C(y) != Q(y)*Z_H(y)`
- `IdenticalFabricatedLookup`: `v7c:air:shard 0: quotient identity C(y) != Q(y)*Z_H(y)`
- `FabricatedExtractIO`: `v7c:air:shard 0: quotient identity C(y) != Q(y)*Z_H(y)`
- `UnrelatedLayerRoots`: `v7c:tiletree:tiletree:root_mismatch`
- `overdegree_quotient_rejected`: `v7c:air:shard 0: quotient degree bound mismatch`

These are mechanism relations, not digest/target/trivial-gate accepts.

## What changed in this patch

The remote WIP had introduced Stage-A `P_root` but left the verifier
implementation calling the old shard seed/challenge API and regenerating
preprocessed columns. This patch wires the verifier to the Stage-A path:

- validates `proof.p_shard_roots` and `proof.p_openings` against `proof.p_root`;
- absorbs `p_root` into every shard seed/challenge;
- supplies root-pinned preprocessed columns to `AirQuotientVerify`;
- avoids verifier-side SHA XOF/PRF regeneration on the default path;
- leaves `EpisodeAirVerifyOptions{.regenerate_preprocessed/.attest_p_root}` as
  the explicit O(N) differential/attestation path.

The overdegree test now reaches the intended structural relation again. The
root mismatch check remains enforced inside `AirQuotientVerify`, after the
degree-bound checks.

## Measured toy anchor

- params: `rounds=1`, `d_head=32`, `n_q=32`, `n_ctx=64`, `L=2`, `d_model=32`,
  `b_seq=32`, `T_leaf=64`
- AIR rows: 22,528
- shards: 1
- carried-witness v7 proof bytes: 3,369,260
- compact AIR proof bytes, measured serialized estimate: 5,930,940
- full v7 baseline `verify_s`: 0.817499 s
- `GroundEpisodeInCircuit` row scan: 0.099773916 s
- compact verifier total: 0.528893042 s
- compact components:
  - gates: 0.000021375 s
  - carried-column root binding: 0.445476083 s
  - Fri3 batch verify: 0.020793000 s
  - layer checks: 0.000376375 s
  - AIR preprocess / P_root opening: 0.000002500 s
  - AIR quotient: 0.055987083 s
  - chain checks: 0.000009458 s
  - tile-tree closure: 0.006207209 s
  - `n_tiletree_sha`: 719
- episode AIR prove, prover-side only: 26.316909417 s

Stage-A succeeded at the intended local target: verifier-side preprocessed
acquisition is no longer the SHA/XOF row scan. It fell from the old
~80 microsecond toy regenerate path to ~2.5 microseconds for row layout plus
`P_root` opening checks. The dominant toy compact cost is still carried-column
root binding, not AIR preprocessing.

## Medium anchor status

Medium params are `rounds=1`, `d_head=32`, `n_q=32`, `n_ctx=64`, `L=1`,
`d_model=32`, `b_seq=8192`, `T_leaf=64`.

The current checked-in medium measurement harness still begins by constructing
the carried-witness v7 proof and then the AIR proof. That prover work is O(N)
and is expected miner-side work, not the verifier budget. Bounded Mac Studio
runs entered `measure_medium_dims` but did not reach the first medium timing
print before timeout/interruption. The latest bounded run timed out after
600 seconds with no `medium v7 prove_s` line.

This means there is no real medium verifier anchor from this run. That is a
measurement-harness limitation: the verifier is the Stage-I consensus budget;
the prover is allowed to materialize production-size witness columns.

Static medium layout:

- AIR rows: 1,584,128
- shards at current `kEpisodeAirMaxShardRows=2^16`: 25
- padded AIR slots: 1,638,400
- direct tile-tree SHA compressions: 73,823

## Production projection

Production params: `rounds=4`, `d_head=128`, `n_q=512`, `n_ctx=786432`,
`L=16`, `d_model=4096`, `b_seq=16384`, `T_leaf=1024`.

Closed-form PCS core model requested:

`verify ≈ Q * [#columns * Merkle_depth(log2 N_lde) + Σ constraint_degrees]
+ preprocessed-root acquisition + direct-SHA tile-tree`

Constants from the implementation:

- Q = 128
- AIR trace columns = 26, plus quotient = 27 committed columns per shard
- constraint count = 17
- sum of declared constraint degrees = 31
- `kEpisodeAirMaxShardRows = 2^16`

Production static layout:

- AIR rows / LogUp rows in this branch: 15,301,345,280
- shards at current cap: 233,480
- per-shard Merkle depth at the current cap: `log2(2^16 * 16) = 20`
- query terms per current shard: `128 * (27*20 + 31) = 73,088`
- current-shard-cap AIR quotient projection from toy AIR-quotient timing:
  about 13,721 s
- ideal single/aggregated-shard PCS-core projection from toy AIR-quotient
  timing at production depth `log2(2^34 * 16) = 38`: about 0.109 s

The ideal single/aggregated-shard number is not the current branch. The current
branch is still linear in shard count.

## Residual (a): preprocessed columns

Default Stage-A verifier path:

- `kEpSelElem`, `kEpSelFwd`, `kEpSelLeaf`, `kEpScaleE0`, `kEpScaleE1`,
  `kEpLeafExpect`, `kEpGemmGf`, `kEpGemmA`, `kEpGemmB`: root-pinned through
  `P_root`; no verifier-side SHA XOF/PRF regeneration.
- `kEpGemmGf`, `kEpGemmA`, `kEpGemmB`: also value-pinned from proof-public
  layout values; represented today as per-shard vectors.
- `kEpTfp`: regenerated from the 16-entry `T_M` table and gamma; represented
  today as a per-shard vector.

Default path SHA workload for preprocessed acquisition:

- `sha_prf_calls = 0`
- `sha_xof_digests = 0`

Remaining A-residual:

- `P_root` is not itself proven canonical in the default verifier. The
  direct attestation path (`attest_p_root`) recomputes it with O(N) SHA and is
  deliberately outside the sublinearity claim. Production still needs a
  succinct preprocessed-builder proof/recursion, not a trusted prover-chosen
  `P_root`.
- the current implementation still materializes value pins for the sparse GEMM
  claim columns and the fixed `T_M` column as length-`N` vectors per shard.
  That is no longer the SHA/XOF bottleneck, but it is still not the final
  constant-size verifier shape.

## Residual (b): direct tile-tree SHA

With segment leaves disabled, round stream bytes are:

`n_q*d_head + L * (2*b_seq*d_model + d_model^2)`

Production:

- stream bytes per round: 2,415,984,640
- data leaves per round at `T_leaf=1024`: 2,359,360
- padded leaves per round: 4,194,304
- SHA-256 compressions per data-leaf SHA256d: 18
- SHA-256 compressions per internal-node SHA256d: 3
- `n_tiletree_sha` total over 4 rounds: 220,205,564
- ratio vs this branch's AIR/LogUp rows: 1.439%
- ratio vs 2^43 rows: 0.00250%
- projection from toy measured tile-tree timing: about 1,901 s

Verdict: residual (b) is O(stream bytes) and far too large for a 0.9 s verifier
budget on CPU. Next step: arithmetize/commit the tile-tree SHA path via a
lookup/hash proof, or replace the direct closure with a succinct committed
tile-tree proof; do not keep direct SHA recomputation in the consensus verifier.

## Verdict

NO-GO for activation and NO-GO for merging this WIP into the PR head as an
activation-ready change.

What is fixed:

1. the over-degree quotient structural-reject test is green;
2. the five §9 fabricated-witness attacks still reject at mechanism relations;
3. the episode path stays uniformly Fp3/Fri3;
4. Stage-A `P_root` is now actually used by the default verifier and removes
   verifier-side SHA-derived preprocessed regeneration.

What still blocks the ~0.9 s production verifier budget:

1. fixed 2^16 sharding makes the AIR quotient verifier linear in shard count;
2. carried-column root binding dominates toy compact verify and is not yet a
   product-dimension succinct closure;
3. `P_root` still needs a succinct correctness proof/recursive builder instead
   of optional O(N) direct attestation;
4. direct tile-tree SHA closure remains O(stream bytes).

Keep this on `wip/air-episode-compact` with the numbers above. The next
production step is an aggregated/recursive shard verifier plus succinct
preprocessed-root and tile-tree commitments. Do not set heights or enable the
arbiter from this branch.
