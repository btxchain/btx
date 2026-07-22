# BTX MatMul v4.6 — coupled v7 production-succinct workplan

Status: local optimization branch only. Do not merge to PR #89 main until the
acceptance gates below are green and externally reviewed.

Companion construction contract:
`doc/btx-matmul-v4.6-coupled-v7-production-succinct-construction-2026-07-22.md`.

## Current blocker

`VerifyWinnerCoupledV7` is sound by native grounding, but not production
succinct. It still:

- calls `RecomputeCoupledPuzzleReference`;
- calls `BuildCoupledWires`;
- derives bank pages natively;
- rebuilds every coupled column root from native columns;
- recomputes permutation/mix/Extract/barrier roots locally;
- checks all Extract tiles through native-grounded AIR/LogUp, but does not yet
  bind proof-carried Extract AIR trace columns;
- sets `proof.over_budget=true` / `timing.over_budget=true`.

That is a safe shadow verifier, not a block-sized proof-only consensus verifier.

## Cryptographic review basis

The required cutover is consistent with the standard GKR/FRI/LogUp model:

- GKR/sumcheck reduces verification of committed arithmetic computation to
  random-point checks; it does not make verification succinct if the verifier
  still materializes the witness/reference trace.
- FRI binds low-degree committed codewords via Merkle roots and queried
  openings; every claimed value used by the higher-level IOP must be tied back
  to those openings.
- LogUp/log-derivative lookups are the right family for Extract/range/table
  constraints. The shadow verifier now aggregates all coupled Extract tiles
  natively; production still must move those AIR trace columns into the proof.
- Recent sumcheck optimization work helps prover time/memory, especially for
  small-value products and equality-polynomial factors, but it does not remove
  the need for bank, permutation, mix, Extract, SHA and digest relations.

## Required end state

A production-succinct coupled v7 verifier must accept using only:

- public inputs: header, height, V3-sized params, V4+ proof-friendly transcript
  options, target, claimed digest;
- proof-carried commitments: bank/page roots, state/accumulator roots, AIR roots,
  batched-FRI roots;
- proof-carried openings: sampled page/state/GEMM/exchange/perm/mix/Extract/SHA
  openings bound by one batched FRI/evaluation argument;
- Fiat-Shamir challenges derived after all relevant commitments are absorbed.

It must not:

- re-run the coupled puzzle;
- regenerate the 96 GiB expanded bank;
- rebuild full native witness columns;
- hash all barrier states locally;
- verify by comparing against an int64 reference digest except in explicit
  ExactReplay fallback/dispute mode.

## Implementation phases

1. Proof object split
   - Add a distinct `RCGkrCoupledProofV7Succinct` or versioned mode.
   - It must carry roots/openings only, not native columns.
   - Legacy native-grounded `RCGkrCoupledProofV7` remains shadow-only.

2. Bank PCS
   - Commit each canonical packed page under `bank_root`.
   - Prove selected page openings for every sampled GEMM relation.
   - Bind page schedule to `(header, height, params, sigma, b, lobe)`.
   - Reject unrelated bank pages without calling `DeriveCoupledBankPages`.

3. Full-schedule GEMM aggregation
   - Keep V3 schedule: barriers=8, lobes=8, pages/slot=24, rows_per_lobe=128.
   - Aggregate all page products per `(barrier,lobe)` into the lobe output claim.
   - The verifier checks Thaler/product sumchecks plus page openings, not native
     GEMM recomputation.

4. Exchange and accumulation
   - Prove fixed segment placement: lobe `ell` writes only segment
     `[ell*M*W, (ell+1)*M*W)`.
   - Prove page-sum accumulation over the 24 scheduled pages.
   - Include V3 material-exchange rounds in the transcript and committed columns.

5. Permutation proof
   - For proof-only production, use the V4 proof-friendly bit-affine
     permutation family over the V3-sized workload. Legacy V1-V3 Fisher-Yates
     is not succinctly evaluable by the verifier without either scanning
     `StateBytes()` or proving a committed permutation table.
   - Replace native `Σ eq(r, pi[x]) * e[x]` over all `StateBytes()` cells with
     `p~(r_dst) = e~(pi^-1(r_dst))` openings bound by Construction I.
   - The verifier should do `O(log StateBytes)` or sampled opening work, not
     `O(StateBytes)`.

6. Mix proof
   - Arithmetize the butterfly add/sub network over the defined uint64-wrap
     ring used by V3.
   - Prove all mix stages with chunked AIR/composition columns.
   - No verifier-side full-state butterfly.

7. Extract proof for every tile
   - Reuse the episode Extract AIR, but commit the whole coupled post-mix stream.
   - The native-grounded shadow verifier already removed the old
     `max_tiles=16` sample and covers all `barriers * StateBytes()/32` tiles.
   - Production still must carry committed AIR/LogUp columns in the proof,
     rather than letting the verifier trace each tile locally.
   - The verifier checks sampled openings of the AIR composition, not every tile.

8. Barrier-root and digest proof
   - Commit SHA/tile-tree AIR for every barrier root.
   - Bind final digest = `SHA256d(EPISODE || bank_root || barrier_roots...)`.
   - Bind target check to the proof-carried digest.
   - No native barrier-state hashing on the happy path.

9. κ/chunking
   - Respect Goldilocks κ: no committed column may exceed `2^28` coefficients.
   - Split production V3 bank/state/AIR columns deterministically.
   - The transcript must bind chunk IDs, offsets, logical dims, and zero padding.

10. Budget and evidence
    - Production V3 shape: 96 GiB expanded bank, ~51 GiB packed, 12 TiMAC/nonce,
      active state 8 MiB.
    - Happy-path verifier target: ≤ `kRCHappyPathVerifyBudgetS` = 0.9s at a
      90s block interval on the reference validation machine.
    - Proof byte target: ≤ `kRCGkrProofBytesBudget`.
    - Report absolute verifier wall time, proof bytes, query count, columns,
      chunks, and peak RSS.

## Activation gate

Activation is still NO-GO unless all are true:

- `AssessCoupledV7Succinctness(MakeProductionV3RCCoupParams(), MakeV4RCCoupOptions()).genuinely_succinct == true`
- `RCGkrCoupledV7ReadyForProofOnlyConsensus(MakeProductionV3RCCoupParams(), MakeV4RCCoupOptions(), ...) == true`
- coupled adversarial fabricated-witness tests reject at mechanism relations
  (`coupled:*`, `v7:ground:*`, `v7:logup:*`), not only digest/target gates;
- production V3-sized / V4+ transcript proof verifies under Stage-I budget;
- external cryptographic review signs off on the composed GKR/FRI/LogUp bound;
- public heights are still changed only by an explicit activation-height commit.
