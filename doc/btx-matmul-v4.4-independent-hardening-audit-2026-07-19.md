# BTX MatMul v4.4-LT independent hardening audit (2026-07-19)

Status: **PUBLIC ACTIVATION NO-GO**. All public activation heights remain inert.

This document records an independent adversarial review of PR #89 through
`668f282`, plus the exact CPU/Metal reference work added on top. It distinguishes
implemented miner-local alternatives from activation evidence and from unresolved
consensus/network hardening.

## Integrated in this follow-up

- Added a fail-closed Metal 4 MPP integer path for LT `s8*s8->s32` and exact
  `s32*s8->s32` lowering through balanced base-256 limbs. Runtime qualification
  now covers multiple output tiles/threadgroups and both two- and three-limb
  inputs. Canonical CPU fallback remains authoritative.
- Corrected the older Metal v4 tensor operand types/lifetimes and kept all
  accelerated output byte-checked before it can be used.
- Added an exact one-level Strassen CPU oracle with checked transforms,
  accumulation, and output conversion. It is deliberately unwired and is an
  algorithm-tournament reference, not a production speed claim.
- Added an independent adaptive base-256 oracle: four dense INT8 GEMMs plus
  exact sparse high-limb corrections, with deterministic fallback when the high
  plane is dense. This is miner-local and does not alter consensus bytes.
- Scaled LT verification job knobs into Q* leaf-work units with saturation,
  removed the second global-budget charge from mandatory consensus validation,
  and made global/pending arithmetic overflow-safe.
- Made legacy Metal batching-policy tests explicitly select the legacy solver;
  regtest's v4/nonce-seed heights can no longer silently change what those tests
  exercise.

## Independent M4 result

On the 32-core M4 Max, the Metal path was byte-exact at `n=512`, `1024`, `2048`,
and `4096`. At `n=4096`, one earlier comparative run measured approximately:

- CPU `s8*s8`: 96.58 ms; MPP: 4.50 ms
- CPU `s32*s8`: 88.14 ms; MPP: 18.09 ms
- Combined GEMMs: 184.71 ms CPU; 22.59 ms MPP (about 8.18x)

This is **not** end-to-end nonce throughput. It excludes ChaCha Extract,
projection, combine, digest, transfers outside the two GEMMs, and seal work.
The current MPP implementation is a correct baseline, not a peak-performance
kernel architecture.

## Remaining activation blockers

### 1. Q* network accounting is not yet single-owner end to end

The inner consensus double-charge is removed here, but compact-block admission
still owns resources too early:

- a compact block that falls back to a full block can consume the peer/global
  allowance twice;
- immediate zero-missing-transaction reconstruction can reserve pending work
  once in the compact handler and once again in `ProcessBlock`;
- compact messages that do not reach recomputation can still consume budget.

Move budget and pending-slot ownership to the actual recompute enqueue boundary,
or carry a one-shot admission token through `CMPCTBLOCK -> BLOCKTXN/full BLOCK`.
Add state-transition tests at Q64/Q128 and pending cap one.

### 2. Header anti-DoS must be enforced before work credit/resource charging

The unsafe bit-26 variable-length wire/hash design was correctly withdrawn in
`f21a282`; headers remain 182 bytes and public activation stays disabled. Before
any replacement HeaderPoW design is activated, one shared height-aware gate must
run before headers-presync credit, redownload storage, claimed-work accounting,
pending-slot reservation, and Q* budget consumption.

### 3. Extract transcript and fastest-exact calibration remain open

The ChaCha CPU/CUDA/HIP signed-shift UB is fixed and parity vectors exist, but:

- `uint32(raw) XOR lane` is not injective domain separation. Independently
  tagged mantissa/scale subkeys with an injective nonce transcript are preferred.
- `mu == 0` (probability 1/11) lets an optimized miner skip the scale block,
  saving about 4.55% of extractor blocks relative to the reference.
- rare `remix > 0` behavior needs constructed cross-backend vectors.
- exact byte order for every transcript component must be normative.

Difficulty/economic calibration must use the fastest exact implementation, not
the current reference loop.

### 4. Activation evidence currently overstates tensor work

The report counts all MatExpand-B time as tensor time even though it now includes
scalar ChaCha Extract. A device batch/equality success also does not prove that
CUDA/HIP used IMMA/MFMA. Split timings into GEMM, Extract, projection, combine,
digest, and seal; require device-side timing/counters plus an explicit native
tensor capability before certifying tensor share.

The staged seal report must construct real slot nonces, bind full slot IDs into
seeds, and match `ComputeSealDigestBMX4CLT` byte-for-byte.

### 5. Fastest-exact algorithm tournament is incomplete

The Strassen and sparse-limb code in this follow-up are correctness oracles.
They are not wired into production and do not establish a practical shortcut.
Required evidence includes randomized/boundary differential tests, native
backend implementations, production-size distributions, randomized lane order,
warm medians/error bars, selective-abort economics, and independent silicon.

### 6. Native backend optimization is still incomplete

The M4 path uses host limb decomposition/recombination, large intermediate
buffers, one simdgroup per threadgroup, raster traversal, and dynamic extents.
Production qualification must cover `n=8192`, memory pressure, repeated windows,
and end-to-end nonce/seal throughput. CUDA/HIP/Ascend claims must likewise remain
fail-closed until the real native library/kernel path self-qualifies on silicon.

## Verification performed on the integrated tip

- AppleClang Release build with Metal enabled: PASS.
- Focused HeaderPoW/unified activation, LT, BMX4, Strassen, verification-worker,
  and PoW suites: **210/210 cases, 352,716/352,716 assertions PASS**.
- `git diff --check`: PASS.

No result in this document authorizes public activation. Activation requires the
network-accounting fixes, transcript review, honest device evidence, fastest-
exact calibration, independent multi-vendor silicon results, and external
cryptanalysis.
