# BTX v4.5 episode AIR compact verifier measurement — 2026-07-22

Branch: `wip/air-episode-compact`

Base commit tested: `7018dd448d451a0477985165e36fe4ba67f5d933`

Scope: additive verifier-only measurement scaffold. No activation flags were flipped:
`kRCGkrFormalSoundnessReady=false`, `nMatMulRCHeight=INT32_MAX`, arbiter off.

## Test results

- Build target: `test_btx` succeeded.
- `matmul_v4_rc_air_episode_tests`: 5/5 cases, 81/81 assertions passed.
- No-regression set before the measurement-print patch:
  `matmul_v4_rc_air_quotient_tests,matmul_v4_rc_gkr_tests,matmul_v4_rc_gkr_integration_tests`
  passed: 90/90 selected cases, 5405/5405 assertions.

## Mechanism-level forgery rejects

- `ArbitraryAbFactorization`: `v7c:air:shard 0: quotient identity C(y) != Q(y)*Z_H(y)`
- `FabricatedTraceWires`: `v7c:air:shard 0: quotient identity C(y) != Q(y)*Z_H(y)`
- `IdenticalFabricatedLookup`: `v7c:air:shard 0: quotient identity C(y) != Q(y)*Z_H(y)`
- `FabricatedExtractIO`: `v7c:air:shard 0: quotient identity C(y) != Q(y)*Z_H(y)`
- `UnrelatedLayerRoots`: `v7c:tiletree:tiletree:root_mismatch`
- `overdegree_quotient_rejected`: `v7c:air:shard 0: quotient degree bound mismatch`

These are mechanism relations, not digest/target/trivial-gate accepts.

## Measured toy anchor

- params: `rounds=1`, `d_head=32`, `n_q=32`, `n_ctx=64`, `L=2`, `d_model=32`,
  `b_seq=32`, `T_leaf=64`
- AIR rows: 22,528
- shards: 1
- carried-witness v7 proof bytes: 3,369,260
- compact AIR proof bytes, measured serialized estimate: 5,930,940
- full v7 baseline `verify_s`: 0.791754 s
- `GroundEpisodeInCircuit` row scan: 0.094764041 s
- compact verifier total: 0.508441417 s
- compact components:
  - gates: 0.000020209 s
  - carried-column root binding: 0.425378625 s
  - Fri3 batch verify: 0.019657500 s
  - layer checks: 0.000341250 s
  - AIR preprocess: 0.000079916 s
  - AIR quotient: 0.057595500 s
  - chain checks: 0.000005167 s
  - tile-tree closure: 0.005351041 s
  - `n_tiletree_sha`: 719

## Medium anchor status

Medium params are `rounds=1`, `d_head=32`, `n_q=32`, `n_ctx=64`, `L=1`,
`d_model=32`, `b_seq=8192`, `T_leaf=64`.

The current harness did not reach the first medium timing print in bounded runs:

- full-suite medium attempt was interrupted after an extended CPU-bound run in
  `measure_medium_dims`;
- targeted medium-only attempt entered `measure_medium_dims` and stayed CPU-bound
  before printing `medium v7 prove_s`.

This is a harness limitation of the current carried-witness prover path. It is
not evidence against the verifier-side AIR quotient relation, but it means the
requested real medium verify anchor is not available from this run.

Static medium layout:

- AIR rows: 1,584,128
- shards at current `kEpisodeAirMaxShardRows=2^16`: 25
- padded AIR slots: 1,638,400
- direct tile-tree SHA compressions: 73,823

## Production projection

Production params: `rounds=4`, `d_head=128`, `n_q=512`, `n_ctx=786432`,
`L=16`, `d_model=4096`, `b_seq=16384`, `T_leaf=1024`.

Closed-form PCS core model requested:

`verify ≈ Q * [#columns * Merkle_depth(log2 N_lde) + Σ constraint_degrees]`
`+ preprocessed-root regeneration + direct-SHA tile-tree`

Constants from the implementation:

- Q = 128
- AIR trace columns = 26, plus quotient = 27 committed columns per shard
- constraint count = 17
- sum of declared constraint degrees = 31
- `kEpisodeAirMaxShardRows = 2^16`

Production static layout:

- AIR rows / LogUp rows in this branch: 15,301,345,280
- shards at current cap: 233,480
- per-shard Merkle depth: `log2(2^16 * 16) = 20`
- query terms per shard: `128 * (27*20 + 31) = 73,088`
- current-shard-cap AIR quotient projection from toy AIR-quotient timing:
  about 14,155 s
- ideal single-shard PCS-core projection from toy AIR-quotient timing:
  about 0.115 s

The ideal single-shard number is not the current branch. The current branch has
a linear shard-count verifier residual.

## Residual (a): preprocessed columns

Current verifier regenerates public/preprocessed row vectors in
`BuildEpisodePublicData` and `ShardPreprocessed`.

Per shard, each listed column is materialized as `N = shard_rows` Fp3 entries:

- `kEpSelElem`: per-row selector, scales with AIR rows
- `kEpSelFwd`: per-row selector, scales with AIR rows
- `kEpSelLeaf`: per-row selector, scales with AIR rows
- `kEpScaleE0`: per-row scale bit, scales with AIR rows
- `kEpScaleE1`: per-row scale bit, scales with AIR rows
- `kEpLeafExpect`: per-row canonical leaf expansion, scales with leaf rows
- `kEpGemmGf`: sparse layer-claim data but represented as per-shard row vector
- `kEpGemmA`: sparse layer-claim data but represented as per-shard row vector
- `kEpGemmB`: sparse layer-claim data but represented as per-shard row vector
- `kEpTfp`: 16-row fixed table but represented as per-shard row vector

Production sizes:

- AIR rows: 15,301,345,280
- leaf rows: 4,026,793,984
- per full-row preprocessed column: 15,301,345,280 Fp3 entries
- all 10 preprocessed vectors if materialized naively: 153,013,452,800 Fp3 entries

Verdict: residual (a) is O(N) in the verifier today. Next step: replace per-row
preprocessed regeneration with compact commitments/formula openings, sparse
selector intervals, and fixed-table commitments instead of full row vectors.

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

Verdict: residual (b) is O(stream bytes) and far too large for a 0.9 s verifier
budget on CPU. Next step: arithmetize/commit the tile-tree SHA path via a
lookup/hash proof, or replace the direct closure with a succinct committed
tile-tree proof; do not keep direct SHA recomputation in the consensus verifier.

## Verdict

NO-GO for activation.

The algebraic core is working and the §9 forgeries reject at mechanism-level
relations. The compact AIR quotient itself can be sublinear in an ideal
single-shard PCS model, but the current branch does not clear the production
verifier budget because these verifier-side O(N) residuals remain:

1. carried-column root regeneration in `VerifyWinnerProofV7Compact`;
2. fixed 2^16 sharding, which makes the AIR quotient verifier linear in shard count;
3. per-row preprocessed/public column regeneration;
4. direct tile-tree SHA closure.

Do not merge to PR head for activation. Keep this on `wip/air-episode-compact`
until the residuals above are removed or replaced with succinct commitments.
