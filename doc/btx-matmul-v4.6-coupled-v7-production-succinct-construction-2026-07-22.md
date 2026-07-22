# BTX MatMul v4.6 — coupled v7 production-succinct construction

Status: local construction note for the `coupled-v7-succinct` branch. This is
not an activation document and does not set public heights.

## Claim

The current coupled v7 verifier is sound by native grounding, but production
succinctness requires a different happy path:

```
Accept iff a single transcript proves:
  canonical V3/V4 bank pages -> full-schedule GEMM -> fixed exchange ->
  proof-friendly permutation -> V3 material mix -> Extract -> barrier SHA roots ->
  episode digest -> target
```

The verifier must not call `RecomputeCoupledPuzzleReference`, rebuild
`BuildCoupledWires`, regenerate bank pages, scan the full active state, or hash
the full barrier state on the happy path.

## Cryptographic basis

- Sumcheck/GKR is the right shape for the matrix products and state-transition
  checks because it reduces high-volume arithmetic assertions to random MLE
  openings. See Thaler's sumcheck notes and GKR discussion:
  <https://people.cs.georgetown.edu/jthaler/small-sumcheck.pdf> and
  <https://zkproof.org/2020/03/16/sum-checkprotocol/>.
- Batched FRI is the transparent PCS substrate. The verifier checks proximity
  and low-degree openings through Merkle-authenticated queries, not by reading
  the committed witness. See Haböck's FRI summary:
  <https://eprint.iacr.org/2022/1216>.
- Extract/range/table constraints should use logarithmic-derivative lookup
  aggregation, with GKR-style improvements for large lookup batches. See:
  <https://eprint.iacr.org/2022/1530> and <https://eprint.iacr.org/2023/1284>.

## Mandatory transcript version

Production-succinct coupled consensus cannot use the V1-V3 Fisher-Yates
permutation as the proof-only permutation relation. A verifier cannot evaluate
the MLE of an arbitrary seeded Fisher-Yates permutation at a random point without
either:

1. scanning/rebuilding the full permutation, or
2. proving and committing the permutation table itself.

The local code therefore treats `ENC_RC_V4`'s seeded bit-affine permutation as
the production-succinct direction:

```
pi(src)[out_bit] = src[in_bit_perm[out_bit]] XOR mask[out_bit]
```

Then:

```
p~(r_dst) = e~(pi^{-1}(r_dst))
```

is one committed-opening equality under Construction I. This gives verifier
cost proportional to the state bit-length, not `StateBytes()`.

The workload dimensions can remain V3-sized:

```
barriers = 8
lobes = 8
W = 8192
M = rows_per_lobe = 128
pages_per_barrier_lobe = 24
bank_pages = 1536
packed bank ~= 51 GiB
expanded bank = 96 GiB
MACs = 12 TiMAC / nonce
```

But the transcript family for a proof-only cutover must be proof-friendly
(`ENC_RC_V4` or later), not legacy Fisher-Yates V3.

## Commitments

All witness columns are committed in one batched FRI transcript unless a column
would exceed the Goldilocks `2^28` coefficient cap, in which case it is split
deterministically by:

```
chunk_id = H("BTX_RC_COUP_CHUNK_V1" || role || barrier || lobe || page || offset)
```

Every root absorbs:

```
role, version, params fingerprint, options fingerprint, logical length,
chunk offset, zero-padding length, root
```

The verifier rejects if any claimed opening refers to a role/chunk that is not
uniquely determined by `(header, height, params, options, sigma)`.

## Fiat-Shamir order

The transcript must be commit-then-challenge:

1. Absorb public statement:
   `header_without_nonce_commitment`, `height`, `target`, `params`, `options`,
   `sigma`, expected profile/version, and claimed digest.
2. Absorb all primary roots:
   bank/page roots, A/B/Y roots, exchange roots, permutation/mix roots,
   Extract AIR roots, SHA/tile-tree roots, digest-comparison roots.
3. Draw product-sumcheck points for GEMM.
4. Draw wiring/permutation points.
5. Draw LogUp gamma and dual alpha challenges.
6. Draw AIR composition challenges.
7. Run batched opening reduction.
8. Run batched FRI query challenges.

No challenge may be sampled before all roots it is meant to bind are absorbed.

## Relations

### R1 — bank/page PCS

For every selected `(barrier, lobe, page_id)`:

```
Page = MxExpand(seed(header,height,sigma,page_id), W, W)
```

The prover commits to page chunks and the MxExpand AIR columns. The verifier
checks:

- page_id equals `SelectCoupledBankPageIds(...)`;
- MxExpand SHA/XOF/mantissa/scale AIR constraints hold;
- the B-fold column equals the sum of the 24 selected page columns at the
  sampled matrix point.

Reject labels:

```
coupled:bank_page_schedule
coupled:bank_page_air
coupled:bank_page_opening
coupled:bank_fold_sum
```

### R2 — full-schedule GEMM

For each `(barrier, lobe)`, with `A` shape `M x W`, folded `B` shape `W x W`,
and output `Y` shape `M x W`:

```
Y[i,j] = sum_k A[i,k] * B[k,j]
```

The existing Thaler product sumcheck is the right relation. Its openings must
be bound by Construction I (`BatchedOpeningProve/Verify`) so the verifier does
not pay a per-claim FRI/eval union.

Reject labels:

```
coupled:sumcheck
coupled:final_eval
coupled:opening:*
```

### R3 — fixed-segment material exchange

For lobe `ell`, the output segment is:

```
exchange[ell * M * W + row * W + col] = Y_ell[row,col]
```

This is already expressible as a subcube opening:

```
e~(r_col, r_row, bits(ell)) = Y_ell~(r_row, r_col)
```

For production, it must be enforced without rebuilding the exchange column
natively.

Reject labels:

```
coupled:exchange_segment
coupled:opening:*
```

### R4 — proof-friendly permutation

Use `ENC_RC_V4` or later:

```
p~(r_dst) = e~(pi^{-1}(r_dst))
```

where `pi^{-1}` is computed by the verifier in `O(log StateBytes())` from the
public bit-affine descriptor.

Reject labels:

```
coupled:perm_affine_point
coupled:opening:*
```

Legacy Fisher-Yates V1-V3 is not production-succinct unless a separate committed
permutation-table proof is added.

### R5 — V3 material mix

The V3 mix/exchange-round network must be expressed as AIR over committed
uint64-wrap lanes:

```
lane_out = lane_in +/- peer_lane +/- round_mask (mod 2^64)
```

Required committed columns:

- low/high 32-bit limbs per lane;
- carry/borrow witnesses;
- round mask/XOF limbs;
- source/destination lane wiring;
- round boundary state roots.

Reject labels:

```
coupled:mix_air
coupled:mix_wiring
coupled:mix_range
```

### R6 — Extract all tiles

The shadow verifier now runs the committed-cell Extract AIR and canonical
T_M/T_X/T_R16 LogUp over every tile instead of the old 16-tile sample.
Production must still commit the full Extract AIR for every tile:

```
tiles_per_barrier = StateBytes() / 32
```

For V3 production this is `262144` tiles per barrier and `2097152` tiles per
nonce over all barriers. The production verifier must check committed AIR
composition and LogUp aggregates from proof-carried roots/openings, not iterate
the tiles locally.

Reject labels:

```
coupled:extract_air
coupled:extract_logup
coupled:extract_state_out_opening
```

### R7 — barrier roots

Each barrier root is:

```
SHA256d(BARRIER_TAG || barrier_index || state_out_bytes)
```

The SHA/tile-tree AIR must bind committed `state_out` bytes to the proof-carried
barrier root. The verifier must not hash the entire state.

Reject labels:

```
coupled:barrier_sha_air
coupled:barrier_root_binding
```

### R8 — digest and target closure

The final digest relation is:

```
digest = SHA256d(EPISODE_TAG || bank_root || barrier_root[0] || ... || barrier_root[B-1])
digest <= target
header.matmul_digest == digest
```

The digest SHA can be verified directly because its input is small. The target
comparison is a deterministic integer comparison over the proof-bound digest.

Reject labels:

```
coupled:digest_from_roots
coupled:digest_not_header_bound
coupled:target
```

## Acceptance gate

`RCGkrCoupledV7ReadyForProofOnlyConsensus(...)` may return true only when:

- no verifier path calls `RecomputeCoupledPuzzleReference`;
- no verifier path calls `BuildCoupledWires`;
- all `RCGkrCoupledV7RelationStatus.native_grounded == false`;
- all mandatory relations above are proof-bound;
- production V3-sized / V4-transcript proofs verify under the Stage-I budget;
- adversarial fabricated-witness tests reject at the mechanism relation, not at
  a trivial digest/target gate;
- independent cryptographic review signs off on the composed bound.
