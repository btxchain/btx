# MatMul v4 per-stage wall-time benchmark

A standing check for the **§K.2a-WT wall-time invariant**: it runs the whole v4
per-nonce hot path on the GPU and reports the measured per-stage split, so "the
tensor GEMM must dominate measured wall-time" can be verified on real silicon
rather than inferred from MAC or byte counts. Contributed from the PR #89 review
that surfaced the operand-XOF issue.

## What it measures

Per nonce, on-device, over a batch:
- **stage 1 operand-gen** — A, B, U, V via the wide counter-mode XOF (`--wide`,
  bit-exact to `ExpandBalancedS8Stream`: count -> prefix sum -> scatter), or the
  retired per-element XOF (default, for a before/after comparison).
- **stage 2 INT8 GEMM** — cuBLASLt `s8->s32`, P = U*A and Q = B*V (§E.3).
- **stage 3 mod-q combine** — tiled `Chat = P*Q mod q` over q = 2^61-1.

It reports per-stage ms, the INT8 tensor share of wall-time, nonce/s, board power
(NVML) and a machine-parseable `CSV,...` row.

## Bit-exactness

`--emit` prints `H(sigma||Chat)` for fixed seeds and is **bit-exact to the CPU
reference** at n=4096 (verified across CPU, sm_90 and sm_120), so it exercises the
real consensus derivation, not an approximation. `--verify` diffs cuBLASLt against
a scalar INT32 GEMM.

## Build / run

```
nvcc -O3 -arch=native matmul_v4_stage_bench.cu -lcublasLt -lnvidia-ml -o v4bench
./v4bench 4096 32 --wide         # per-stage split at the launch dimension
./v4bench 4096 1  --emit --wide  # reference-matching digest
```

## What it shows today

With the wide XOF (`f50f0f8`) the operand-gen SHA cost drops ~32x, and the
**mod-q combine becomes the dominant non-tensor stage** — the INT8 tensor GEMM is
still a single-digit to low-double-digit percent of wall-time at n=4096-8192.
That is the input to activation item C-13 (limb-decompose `P*Q` onto s8 tensor
GEMMs): re-run this after C-13 to confirm the tensor GEMM actually dominates.
