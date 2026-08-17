# An independent ENC_RC implementation reproduces the episode golden (2026-08-17)

**Status:** implementation report from a third-party miner author, plus one small
documentation request.
**Scope:** ENC_RC (v4) Epoch-A Profile 1. No consensus change is proposed here.

## Summary

`matador-miner` is a GPU miner for BTX with its own ENC_RC episode implementation,
written against the spec and this repository's CPU reference. To be exact about what
"independent" means here: it vendors a trimmed subset of this project's consensus
sources (header/primitive/serialization types, with the upstream MIT notices retained)
so that header layouts and seed derivation cannot drift, but the episode itself and
the entire GPU path are separate code, not a copy of `src/cuda/`. As of today it is
open source under MIT
(<https://github.com/vanities/matador-miner>), the same license as this project, so
anything in it can be taken here without asking.

It reproduces this repository's episode golden byte-for-byte, on CPU and on GPU:

```
5b1bff3c835b1c8e7816a2cccb181eb2fc30a99d97a971d73108c52a8238acd4
```

That is the value in `contrib/matmul-v4/rc-golden-gate.py` (`FROZEN_V1_HEX`),
`src/matmul/matmul_v4_rc.h`, and the `matmul_v4_rc_tests` expectations.

Two independent implementations agreeing bit-exactly is worth recording for a
consensus rule: it is evidence the episode construction is specified tightly enough
to be reimplemented without ambiguity, which is the property that matters when
third-party miners and verifiers have to agree with nodes.

## What was verified

Measured 2026-08-17 against tag `v0.33.3` / `a5aa3b41`, on an RTX 5090 (sm_120),
CUDA 13.3:

| check | harness | result |
|---|---|---|
| CPU oracle == golden | `rc_probe` | pass |
| GPU backend == golden | `rc_gpu_accel_probe` | pass |
| GPU backend == CPU oracle | `rc_gpu_accel_probe` | pass |

```
sigma  = 86c171d7ee6152a3a2a592a5c400adb9a680a06f3247b55f1e0935e129282fe2
digest = 5b1bff3c835b1c8e7816a2cccb181eb2fc30a99d97a971d73108c52a8238acd4
EXPECT = 5b1bff3c835b1c8e7816a2cccb181eb2fc30a99d97a971d73108c52a8238acd4
=> ENC_RC episode BYTE-EXACT (5b1bff3c)

  cpu oracle : 5b1bff3c835b1c8e7816a2cccb181eb2fc30a99d97a971d73108c52a8238acd4
  gpu backend: 5b1bff3c835b1c8e7816a2cccb181eb2fc30a99d97a971d73108c52a8238acd4
=> cpu==golden 1, gpu==golden 1, gpu==cpu 1
```

The equality is enforced as a release gate: a `matador-miner` binary is not
published unless both probes agree with the golden. Reproduction steps are in that
repository's `BUILDING.md`; the episode itself is in
`clean-stack/core/matmul/matmul_v4_rc.cpp` with the GPU path under
`clean-stack/core/cuda/`.

Scope note, to be precise about what is and is not claimed: this covers the Epoch-A
Profile-1 episode digest only. It is not a statement about the coupled leg, the
Freivalds carrier, or the BMX4C/LT encoding profiles, and it is not a performance
comparison against this repository's `src/cuda/matmul_v4_rc_exact_replay_cuda.cu`.

## Documentation request: `matmul_n` in `getblocktemplate`

One concrete ask, from a solo-mining interop bug we shipped a fix for today.

`getblocktemplate` returns a top-level `matmul_n` (`src/rpc/mining.cpp`, set from
`block_header.matmul_dim`), commented as a backward-compatible field retained for
existing miners. For a solo miner that field is doing more work than "backward
compatible" suggests: it is the only in-band signal that ENC_RC is active.

The failure mode, which we hit: consensus requires `matmul_dim == nMatMulV4Dimension`
at and above `nMatMulRCHeight` and rejects anything else, and the dimension is inside
both the seed-V3 and sigma preimages. A solo miner that does not learn activation
from somewhere will stamp the pre-ENC_RC dimension and run the pre-ENC_RC solver, and
every block it solves is unacceptable with no diagnostic pointing at the cause. Pool
miners are covered because the pool announces a profile string, but a solo miner
talking to its own node has only `getblocktemplate`.

Reading `matmul_n` fixes it cleanly, because the node has already resolved the
correct dimension for the next height. The request is just that this be documented as
a stable field rather than a legacy one, so third-party miners can rely on it:

- state in the `getblocktemplate` RPC help that `matmul_n` carries the required
  header `matmul_dim` for the next block, and
- note that a miner should treat `matmul_n == nMatMulV4Dimension` as the activation
  signal rather than compiling an activation height in.

Compiled-in heights are the thing to avoid: this one moved several times before Epoch
A settled at 185000, and every miner that hardcoded an earlier value produced work
the network could not accept.

## Offered, not included here

The MIT relicensing was done so this project can take whatever is useful. Two things
we are happy to prepare as separate PRs if there is interest:

1. **Episode/ExactReplay GPU work.** This repository already has a mature CUDA
   ExactReplay path, so we are deliberately not opening a "replace it" PR on
   assertion. If a measured comparison would be welcome, we will run it at a locked,
   iso operating point (fixed clocks and power limit, single process on the device,
   both arms in the same GPU state) and post the method and numbers before proposing
   any code change.
2. **Negative results.** We have a fair amount of measured record on optimization
   axes that did not pay off, which may save duplicated effort. We would rather
   contribute those as dated measurements with the hardware and code state attached
   than as verdicts, since several of our own earlier "closed" conclusions were later
   overturned by our own testing.

Contact: <https://github.com/vanities/matador-miner> (issues welcome).
