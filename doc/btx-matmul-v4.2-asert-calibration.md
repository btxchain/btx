# BMX4-C — ASERT Rescale Calibration (B2b) Methodology

*How to determine the one-time `nMatMulBMX4CAsertRescaleNum/Den` at the v3→v4.2
fork, from live network difficulty + a CPU v3-vs-BMX4-C throughput ratio, refined
by GPU measurement and self-corrected by ASERT. Price-independent by construction
(§0.7-(4)): only difficulty / hashrate / block-time / height are used — never
price, market cap, or sats.*

## 0. Why precision is not safety-critical (the key fact)

ASERT is a moving-target retarget with a **3600 s half-life** (`CalculateMatMulAsertTarget`
reads only timestamps, heights, and constants — it is price-free). The one-time
rescale only sets the **anchor difficulty of the first BMX4-C epoch**; ASERT then
re-anchors from *actual* block times over ~one half-life (≈40 blocks at 90 s). So:

- A rescale that is off by a factor `f` produces a transient of fast/slow blocks
  that decays with the 3600 s half-life — **not a stall or a split**. The current
  `1/1` placeholder is therefore already *safe* (it degenerates to ordinary ASERT
  re-anchoring); a calibrated value only makes the transition **smoother**.
- The goal of calibration is to minimize that transient, not to hit a magic number.

## 1. The calibration identity

With the target/difficulty encoding unchanged across the fork (same 256-bit target
space, difficulty-1 = same target — BMX4-C reuses the v4 verifier core), block-time
continuity requires the anchor difficulty to scale with the **network throughput
ratio**:

```
Num/Den  =  D_bmx4c / D_v3  =  R_bmx4c / R_v3
```

where `R_v3` = network v3 solve-attempts/s (encoded in the *current live difficulty*
`D_v3`) and `R_bmx4c` = network BMX-4C nonce/s once miners re-point hardware. `R_v3`
is observable **now** (live difficulty); `R_bmx4c` is the unknown the calibration
estimates.

## 2. The CPU proxy for the per-device work ratio

`R_bmx4c / R_v3` factors as (per-device work ratio) × (hardware-mix shift). The
**per-device ratio** is measurable on any one machine:

```
r  =  (v3 solve-attempts/s on device X)  /  (BMX-4C nonce/s on device X)
Num/Den ≈ 1 / r        (first-order, assuming a uniform hardware-mix shift)
```

Measured on **CPU** this is `r_cpu`. It is a *defensible first-order estimate* — far
better than `1/1` — because both v3 and v4.2 are the SAME class of workload (a
seed-derived matmul PoW, GPU-accelerated), so the relative v3→BMX-4C slowdown is
correlated across CPU and GPU. **Measure it with:**

```
# both paths, same host, same build; report attempts/s (v3) and nonce/s (bmx4c):
BTX_V4_STAGE_BENCH_DIM=4096 ./build/bin/bench_btx -filter='MatMulV4Stage.*'   # bmx4c marginal nonce/s
./build/bin/bench_btx -filter='MatMulSolve.*'                                  # v3 solve attempts/s
# r_cpu = v3_attempts_per_s / bmx4c_nonce_per_s ;  recommended Num/Den ≈ round(1/r_cpu)
```

(CPU baseline already recorded in `btx-matmul-v4.2-datacenter-measurement-runbook.md`:
BMX-4C marginal MACs/nonce = `n²m + 16m²n` = 8.59×10¹⁰ at n=4096 — the denominator of
the CPU nonce/s.)

### The honest caveat on the proxy
`r_cpu` is a **proxy, not the answer**. BMX-4C is FP4-tensor-native on datacenter GPUs
in a way a CPU cannot mirror, and v3's SHA-gate behaves differently on CPU vs GPU, so
`r_gpu` can differ from `r_cpu` by a modest factor. This is exactly why B2b is
GPU-measurement-gated. **Use `r_cpu` for the *initial* `Num/Den`; refine with the
`measure-hardware.sh --profile bmx4c` throughput (`backend_nonce_per_s`) on the
reference GPU (B2b), and let the first ~40 post-fork blocks (ASERT) absorb the rest.**

## 3. Live-difficulty anchor at fork-planning time

`D_v3` (live difficulty) enters as the block-time-continuity check, obtained from the
**node's canonical source** at the time the activation height is chosen — NOT scraped
from a dashboard (the public SPAs at explorer.btxbyronbay.com / btxprice.com expose
price/peer/leaderboard telemetry but not raw difficulty at a stable API path, and any
value scraped today is stale by activation):

```
btx-cli getdifficulty          # or getmininginfo / getblockchaininfo -> difficulty
btx-cli getmininginfo          # networkhashps, blocks (height)
```

Sanity check at activation planning: with the chosen `Num/Den` and the live `D_v3`,
the predicted first-epoch block time = `90 s × (Num/Den) × (r_gpu_reference)` should
land near 90 s; if not, adjust `Num/Den` toward `1/r_gpu_reference`.

## 4. Procedure (at fork-activation planning, on real hardware)

1. Read live `D_v3` and `networkhashps` from the node (`getdifficulty` / `getmininginfo`).
2. Measure `r_gpu` on the reference GPU: `measure-hardware.sh cuda --profile bmx4c`
   gives BMX-4C `backend_nonce_per_s`; measure the v3 solve rate on the same GPU.
3. Set `nMatMulBMX4CAsertRescaleNum/Den ≈ round(1/r_gpu)` (fall back to `1/r_cpu` if no
   reference GPU is available — still better than 1/1).
4. Confirm block-time-continuity via §3; commit the value in `CMainParams`
   alongside the activation height (the `nMatMulV4Height` rescale precedent, §B6).
5. Ship; ASERT absorbs residual error within a half-life.

## 5. What is set now vs later

- **Now (this branch):** the rescale *mechanism* is wired at `nMatMulBMX4CHeight`
  with `Num/Den = 1/1` (behaviorally identical to ordinary ASERT re-anchoring — no
  regression), validated by `ValidateMatMulAsertParams`. Activation is mechanical.
- **At activation:** replace `1/1` with the §4 calibrated value. This is a one-line
  change gated on the B2b GPU measurement, exactly like the `nMatMulV4Height` rescale.

**Bottom line:** the calibration is *properly determinable* from live difficulty + a
measured v3-vs-BMX-4C throughput ratio, and it is **not safety-critical** — ASERT's
self-correction means a good first-order `Num/Den` (from `r_cpu` now, `r_gpu` at
activation) is sufficient, and `1/1` is safe in the interim. No price input anywhere.
