# BTX MatMul v4.2 — BMX4-C Datacenter Measurement Readiness Runbook

*Status: MEASUREMENT-OPS deliverable. Not a code change, not a consensus change,
not a new claim about hardware ordering. Companion to
`doc/btx-matmul-v4.2-bmx4c-spec.md` (normative spec, source of every parameter
cited here), `doc/btx-matmul-v4-multiplatform-roadmap.md` (per-platform
feasibility + the INT8-vs-frontier decoupling analysis), and `ACTIVATION.md`
Gate C (the tracked measurement checklist this doc feeds). Written 2026-07-16.*

> **Posture, stated up front and re-stated at every section boundary below:**
> this program has had **two prior peak-based/model ordering estimates
> falsified by real measurement** — the b=8→b=4 batched-sketch tensor-share
> ordering (PR #89) and at least one other v4.1 peak-TOPS ordering claim (see
> `doc/btx-matmul-v4.2-bmx4c-spec.md` §6, `doc/btx-matmul-v4-committed-object-
> redesign.md` §"falsified", `doc/btx-matmul-v4-multiplatform-roadmap.md`
> executive summary). Consequently: **every number in §3 of this document is
> MODELED, not measured, and is explicitly barred from being load-bearing**
> (spec §6, §9; `Consensus`-facing activation logic reads none of it — humans
> do, per §0.7-(4)). The real measurement — §K.2b GO/NO-GO — is a gap this
> document cannot close because **there is no GPU in this repository or its
> execution environment.** §4 states that gap plainly.

---

## 0. What this runbook is for

An operator with access to real datacenter/consumer/Apple silicon (B200, B300,
RTX 5090, MI355X, Trainium3, TPU v7, Apple M5, or any subset) needs exactly
three things to produce Gate C evidence:

1. **A CPU baseline** they can diff their own results against, and a worked
   example of what the tool's output and JSON look like (§1 — produced here,
   on this machine, right now, no GPU required).
2. **The exact one-command sequence** to run on their hardware (§2) and what
   to send back.
3. **A honest model** of what the measurement *should* show if the design's
   own MAC-count arithmetic and published vendor peak numbers hold — clearly
   separated from what has actually been measured (§3), plus the one gap real
   silicon must close (§4).

Nothing here edits consensus code, the GPU backends, or the spec. Everything
in §1 is real output from `build_wallet/bin/matmul-v4-report`, the existing
binary, run read-only on the CPU-only machine this doc was written on.

---

## 1. CPU baseline (real output, run on this machine, 2026-07-16)

### 1.0 Build status

`build_wallet/bin/matmul-v4-report` already exists in this checkout (built by
prior work in this session — no build was triggered to produce this section):

```
$ ls -la build_wallet/bin/matmul-v4-report
-rwxr-xr-x 1 root root 774936 Jul 16 06:19 build_wallet/bin/matmul-v4-report
```

No separate `build_dcbench` build was needed. (Had the binary been absent,
the correct move per the task's rules would have been a narrow
`cmake --build build_dcbench --target matmul-v4-report` — deliberately
**not** exercised here since the existing binary was present and current.)

### 1.1 `--profile bmx4c --mt24 --n 256 --window 8`

Command run:

```
./build_wallet/bin/matmul-v4-report --profile bmx4c --mt24 --n 256 --window 8 \
    --backend cpu --out mtr-bmx4c-n256.json
```

Full real output:

```
== MatMul v4.2 (ENC-BMX4C) hardware report (vm) ==
profile          : bmx4c
resolved backend : cpu  [compiled=yes available=yes admissible=yes]
device identity  : consensus_reference_always_available
host cpu arch    : x86_64
dims             : n=256 b=4 window(Q)=8 rounds=3

[B1-analogue] BMX4-C bit-exact determinism gate
  ComputeDigestBMX4C determinism + VerifySketchBMX4C round-trip over 8 nonces: PASS
  NOTE: no on-device BMX4-C dispatch exists in this build yet (only v4.1 ENC-S8 has
  cuda/metal/hip kernels); this gate certifies the CPU reference only.

[B2g-analogue] BMX4-C per-stage marginal wall-time (n=256, window Q=8)
  S0  template Ahat,U,V + P=U*Ahat (amortized):     4.243 ms
  S1b per-nonce expand Bhat   (SHA/int)  :     1.276 ms   13.0%
  S2  per-nonce GEMM Q=Bhat*V (tensor)   :     2.466 ms   25.1%
  S3  combine P*Q chosen=limb-tensor  :     5.939 ms   60.4%
      (limb-tensor 47.513 ms vs ALU-direct 110.784 ms, whole window)
  S4  serialize + digest      (SHA/int)  :     0.155 ms    1.6%
  per-nonce MARGINAL total (S0 amortized):     9.837 ms   stage-bit-exact=YES
  tensor-stage share (§K.2a-WT majority gate): 85.4%

[M-t24] accumulator-exactness boundary-vector suite (spec §5.3/C-1')
  e8m0_scale_exactness_precondition          expected=48           actual=48           PASS (precondition)
  t14_odd_step_base_product                  expected=16416        actual=16416        PASS (2^14 rung)
  t19_high_magnitude_real_gemm               expected=589824       actual=589824       PASS (2^19 rung)
  t22_limb_pair_boundary_n4096               expected=4194304      actual=4194304      PASS (2^22 rung)
  t23_limb_pair_boundary_n8192               expected=8388608      actual=8388608      PASS (2^23 rung)
  t24_boundary_pin_base2e7_limb_n4096        expected=16777216     actual=16777216     PASS (2^24 rung)
  proven exact-accumulator bits : 24  (>= t=24: NATIVE PATH threshold met)
  M-t24 verdict                 : PASS
  device native kernel wired    : yes
  native path eligible           : YES
  reason                         : CPU is a true int64/int32 accumulator by construction; all C-1'
  boundary vectors are bit-exact up to and including the proven t=24 threshold.

[GO/NO-GO §K.2b + M-t24] GO: BMX4-C bit-exact PASS, M-t24 PASS (proven t=24), tensor-stage share is
a majority (85%) -- native path ELIGIBLE on this device
```

JSON (`mtr-bmx4c-n256.json`), verbatim:

```json
{
  "tool": "matmul-v4-report",
  "schema_version": 2,
  "host": "vm",
  "host_cpu_arch": "x86_64",
  "backend": "cpu",
  "device": {"compiled": true, "available": true, "admissible": true,
             "reason": "consensus_reference_always_available"},
  "n": 256, "b": 4, "window": 8, "rounds": 3, "profile": "bmx4c",
  "mt24_pass": true, "proven_accumulator_bits": 24, "native_path_eligible": true,
  "bit_exact": true,
  "stages": {
    "n": 256, "b": 4, "m": 64, "window": 8, "bit_exact": true,
    "s0_template_ms": 4.24304, "s1b_expand_ms": 10.211437,
    "s2_gemm_ms": 19.729217, "s3_limb_combine_ms": 47.513016,
    "s3_alu_direct_ms": 110.784337, "s3_chosen": "limb-tensor",
    "s4_digest_ms": 1.242812, "marginal_per_nonce_ms": 9.83706025,
    "cpu_reference_nonce_per_s": 101.6563866222127,
    "marginal_tensor_macs_per_nonce": 20971520,
    "tensor_share_pct": 85.44503043986136, "tensor_util_pct": "unknown"
  },
  "tensor_share_pct": 85.44503043986136, "tensor_util_pct": "unknown",
  "device_peak_int8_tops": 0,
  "mt24": {
    "device_native_kernel_wired": true,
    "native_path_reason": "CPU is a true int64/int32 accumulator by construction; all C-1' boundary vectors are bit-exact up to and including the proven t=24 threshold.",
    "required_proven_bits": 24,
    "vectors": [
      {"name": "e8m0_scale_exactness_precondition", "expected": 48, "actual": 48, "pass": true, "regime_pow2": -1},
      {"name": "t14_odd_step_base_product", "expected": 16416, "actual": 16416, "pass": true, "regime_pow2": 14},
      {"name": "t19_high_magnitude_real_gemm", "expected": 589824, "actual": 589824, "pass": true, "regime_pow2": 19},
      {"name": "t22_limb_pair_boundary_n4096", "expected": 4194304, "actual": 4194304, "pass": true, "regime_pow2": 22},
      {"name": "t23_limb_pair_boundary_n8192", "expected": 8388608, "actual": 8388608, "pass": true, "regime_pow2": 23},
      {"name": "t24_boundary_pin_base2e7_limb_n4096", "expected": 16777216, "actual": 16777216, "pass": true, "regime_pow2": 24}
    ]
  },
  "verdict": "GO: BMX4-C bit-exact PASS, M-t24 PASS (proven t=24), tensor-stage share is a majority (85%) -- native path ELIGIBLE on this device",
  "gates": {
    "B1_analogue": "bit_exact (BMX4-C determinism + verifier round-trip)",
    "B2g_analogue": "tensor_share_pct (§K.2a-WT/§K.2b tensor-stage majority)",
    "Mt24": "mt24_pass + proven_accumulator_bits + native_path_eligible (spec §5.3/C-1')"
  }
}
```

### 1.2 `--profile bmx4c --mt24 --n 512 --window 8`

Command run:

```
./build_wallet/bin/matmul-v4-report --profile bmx4c --mt24 --n 512 --window 8 \
    --backend cpu --out mtr-bmx4c-n512.json
```

Full real output:

```
== MatMul v4.2 (ENC-BMX4C) hardware report (vm) ==
profile          : bmx4c
resolved backend : cpu  [compiled=yes available=yes admissible=yes]
device identity  : consensus_reference_always_available
host cpu arch    : x86_64
dims             : n=512 b=4 window(Q)=8 rounds=3

[B1-analogue] BMX4-C bit-exact determinism gate
  ComputeDigestBMX4C determinism + VerifySketchBMX4C round-trip over 8 nonces: PASS

[B2g-analogue] BMX4-C per-stage marginal wall-time (n=512, window Q=8)
  S0  template Ahat,U,V + P=U*Ahat (amortized):    27.904 ms
  S1b per-nonce expand Bhat   (SHA/int)  :     5.403 ms    7.3%
  S2  per-nonce GEMM Q=Bhat*V (tensor)   :    20.576 ms   28.0%
  S3  combine P*Q chosen=limb-tensor  :    46.954 ms   63.8%
      (limb-tensor 375.634 ms vs ALU-direct 912.856 ms, whole window)
  S4  serialize + digest      (SHA/int)  :     0.677 ms    0.9%
  per-nonce MARGINAL total (S0 amortized):    73.611 ms   stage-bit-exact=YES
  tensor-stage share (§K.2a-WT majority gate): 91.7%

[M-t24] accumulator-exactness boundary-vector suite (spec §5.3/C-1')
  (identical 6/6 PASS ladder to §1.1 -- the M-t24 vectors are fixed-shape and
  dimension-independent; proven exact-accumulator bits: 24, verdict PASS)

[GO/NO-GO §K.2b + M-t24] GO: BMX4-C bit-exact PASS, M-t24 PASS (proven t=24), tensor-stage share is
a majority (92%) -- native path ELIGIBLE on this device
```

JSON stage block (`mtr-bmx4c-n512.json`, `stages`):

```json
{
  "n": 512, "b": 4, "m": 128, "window": 8, "bit_exact": true,
  "s0_template_ms": 27.904164, "s1b_expand_ms": 43.223632,
  "s2_gemm_ms": 164.609081, "s3_limb_combine_ms": 375.634069,
  "s3_alu_direct_ms": 912.856074, "s3_chosen": "limb-tensor",
  "s4_digest_ms": 5.417544, "marginal_per_nonce_ms": 73.61054075,
  "cpu_reference_nonce_per_s": 13.58501092114311,
  "marginal_tensor_macs_per_nonce": 167772160,
  "tensor_share_pct": 91.74011366028444, "tensor_util_pct": "unknown"
}
```
(Top-level `mt24_pass`/`proven_accumulator_bits`/`native_path_eligible` are
identical to §1.1: `true` / `24` / `true` — the M-t24 vector suite uses fixed
internal shapes and does not vary with the report's `--n`.)

### 1.3 The M-t24 ladder — verdict

| Rung (2^t) | Vector | Expected | Actual (this CPU) | PASS? |
|---|---|---|---|---|
| precondition | `e8m0_scale_exactness_precondition` | 48 | 48 | YES |
| 2^14 | `t14_odd_step_base_product` | 16,416 | 16,416 | YES |
| 2^19 | `t19_high_magnitude_real_gemm` | 589,824 | 589,824 | YES |
| 2^22 | `t22_limb_pair_boundary_n4096` | 4,194,304 | 4,194,304 | YES |
| 2^23 | `t23_limb_pair_boundary_n8192` | 8,388,608 | 8,388,608 | YES |
| 2^24 | `t24_boundary_pin_base2e7_limb_n4096` | 16,777,216 | 16,777,216 | YES |

**M-t24 verdict on this CPU: PASS, proven_accumulator_bits = 24, native_path_eligible = true.**
This is the expected, trivial self-test result: a CPU is a true int64/int32
accumulator by construction (`RunMt24` in `src/matmul-v4-report.cpp` reports
`device_native_kernel_wired=true` and `native_path_eligible=true` **only**
for `backend=cpu`). **It certifies the harness and the BMX4-C reference
implementation are internally correct — it certifies nothing about any GPU.**
For any non-CPU `--backend`, this same tool honestly reports
`native_path_eligible=false` with an explicit `native_path_reason` ("no
on-device BMX4-C block-scaled tensor kernel is wired into this build...")
rather than fabricating an on-silicon pass — see §4.

### 1.4 Stage-timing read (CPU, illustrative of methodology only)

Both runs: `s3_chosen=limb-tensor` (the 16 limb-pair combine beats the
ALU-direct mod-q combine on this CPU by ~2.3–2.4×), and the **tensor-stage
share** (S2 `B̂·V` GEMM + the chosen S3 combine) is a strict majority of
marginal per-nonce wall time at both sizes: **85.4% at n=256, 91.7% at n=512**
— rising with n, consistent with the O(n³) tensor stages outgrowing the O(n²)
XOF/digest stages as n grows. This is the CPU-reference shape of the
§K.2a-WT/§K.2b tensor-majority argument; **it is not evidence about any GPU's
tensor-stage share** — CPU has no tensor cores, so "tensor-stage share" here
means "share of wall time spent in the GEMM-shaped stages," a necessary but
far from sufficient precondition. Per-nonce CPU throughput on this host:
101.7 nonce/s at n=256, 13.6 nonce/s at n=512 — again a CPU reference number
useful only as a sanity anchor, not a mining-rate estimate for any target
dimension (mainnet targets n=4096; that run was not attempted here — see §1.5.

### 1.5 What was deliberately NOT run here, and why

- **n=4096 / n=8192 (the actual consensus dimensions).** The stage-timing
  loop is O(n³)-dominated (S2/S3); extrapolating from the n=256→n=512 scaling
  observed here (S3 grew ~8× for a 2× dimension increase, consistent with
  cubic growth) puts an n=4096 run at roughly 1,000–4,000× the n=512 wall
  time — many minutes to tens of minutes of single-threaded CPU work for a
  measurement whose entire point (the M-t24 vectors, the bit-exactness gate)
  is already dimension-saturated at n=256/512. Per the task's rule against
  triggering a long build/run, this was not attempted; an operator with time
  to spare MAY run `--n 4096 --window 32` to match the spec's canonical
  §K.2a-WT shape (Q ≥ 32), but it changes no CPU verdict above.
- **A separate `build_dcbench` build.** Not needed: `build_wallet/bin/
  matmul-v4-report` was already present and current in this checkout.
- **The BMX4-C-specific stage bench (`src/bench/matmul_v4_stage_bench.cpp`).**
  Checked and confirmed: this bench file implements only the v4.1 ENC-S8
  stage boundaries (no `bmx4`/`BMX4` reference anywhere in it — verified by
  direct grep). The BMX4-C per-stage split is exercised **only** through
  `matmul-v4-report --profile bmx4c` (§1.1–1.2 above), which is the CPU
  reference's own `MeasureStagesBMX4C` path — there is no second, independent
  BMX4-C stage-bench binary to run. This is itself a minor tooling gap worth
  noting for the backlog (extending `matmul_v4_stage_bench.cpp` with a
  `--profile bmx4c` mode would give a second, standalone confirmation of the
  same numbers `matmul-v4-report` already produces).

---

## 2. The turnkey operator runbook (real hardware, one command per box)

This section is the exact sequence a datacenter operator with access to real
silicon runs. It requires no familiarity with the codebase beyond a shell.

### 2.1 Prerequisites

- A clone of this repo at the commit under test, on the target machine.
- The vendor toolchain for the box's accelerator (CUDA ≥ the arch's minimum
  for NVIDIA; Xcode 26+ for Apple Metal; ROCm/HIP for AMD). `measure-
  hardware.sh` configures and builds `matmul-v4-report` itself — no manual
  cmake invocation is required.
- Nothing else. The scripts are read-only with respect to consensus code —
  they build one report tool and run it.

### 2.2 The one-command sequence, per platform

```bash
# --- B200 / B300 / any CUDA sm>=75 NVIDIA part ---
CUDA_ARCH="90;100"  \
  contrib/matmul-v4/measure-hardware.sh cuda --profile bmx4c --mt24 \
    --n 4096 --window 32

# --- RTX 5090 (consumer Blackwell, CUDA) ---
contrib/matmul-v4/measure-hardware.sh cuda --profile bmx4c --mt24 \
    --n 4096 --window 32

# --- MI355X (AMD CDNA4) ---
HIP_ARCH=gfx950 \
  contrib/matmul-v4/measure-hardware.sh hip --profile bmx4c --mt24 \
    --n 4096 --window 32

# --- Apple M-series (Metal; M5-class for the tensor path) ---
contrib/matmul-v4/measure-hardware.sh metal --profile bmx4c --mt24 \
    --n 4096 --window 32

# --- Trainium3 (NKI, no in-tree backend yet) / TPU v7 (Pallas, no in-tree
#     backend yet): no Kind::TPU / Kind::Trainium accelerator exists in this
#     repo (T-1 / M-1 backlog items, roadmap §5). Until one lands, run the
#     CPU-reference "cpu" backend AS A SANITY CHECK ONLY on a host attached to
#     that fleet, and separately capture the vendor's own FP4/MX microbench
#     of the block-scaled MAC shapes in §3 -- it does NOT substitute for an
#     M-t24 PASS, and the report tool will not claim one:
contrib/matmul-v4/measure-hardware.sh cpu --profile bmx4c --mt24 \
    --n 4096 --window 32
```

Equivalent direct-verification form (build + run in one call, PASS/FAIL exit
code, no JSON aggregation step) for any of cuda/metal/hip:

```bash
contrib/matmul-v4/verify-backend.sh cuda  --profile bmx4c   # B200/B300/5090-class
contrib/matmul-v4/verify-backend.sh hip   --profile bmx4c   # MI355X
contrib/matmul-v4/verify-backend.sh metal --profile bmx4c   # Apple M-series
```

**What each run produces, and what it decides:**

| Gate | What it checks | Where in the JSON |
|---|---|---|
| **M-t24 (native-path eligibility)** | Proven exact-accumulator bits via the §5.3 boundary-vector ladder (§1.3 table, same vectors, real device path once a vendor FP4/MX kernel is wired) | `mt24_pass`, `proven_accumulator_bits`, `native_path_eligible`, `mt24.vectors[]` |
| **B1 bit-exactness gate** | `ComputeDigestBMX4C` run-to-run determinism + `VerifySketchBMX4C` round-trip over the nonce window | `bit_exact` |
| **§K.2b per-stage tensor-share** | S1b/S2/S3(limb vs ALU)/S4 wall-time split on the STACKED window; tensor-stage (S2 + chosen S3) as % of marginal per-nonce time | `stages.*_ms`, `tensor_share_pct` |
| **B2b ASERT-throughput input** | Sustained marginal nonce/s on the resolved backend (device raw batched throughput when a device kernel exists, else the CPU batched-miner marginal) — pass `--device-peak-int8-tops <TOPS>` and `--v3-hashrate <H/s>` to get the tool's own utilization/rescale-candidate arithmetic | `stages.cpu_reference_nonce_per_s` (CPU) or the device-path equivalent; `tensor_util_pct` when a peak TOPS figure is supplied |

**IMPORTANT, and this is the load-bearing caveat for every non-CPU run
today:** no BMX4-C block-scaled device kernel is wired into this repository
for ANY backend yet (only the v4.1 ENC-S8 `s8×s8→s32` IMMA/MFMA/TensorOps
kernels exist in `src/cuda`, `src/hip`, `src/metal`). Running
`--backend cuda|metal|hip --profile bmx4c --mt24` on real hardware **today**
still exercises the CPU-reference boundary vectors and per-stage timers on
that host's CPU, and the tool will honestly report
`"native_path_eligible": false` with
`"native_path_reason": "no on-device BMX4-C block-scaled tensor kernel is
wired into this build for backend '<X>' ... this run exercised the
CPU-reference boundary vectors only ... it does NOT constitute an on-silicon
M-t24 measurement for this device."` **Do not mistake that run for an
on-silicon M-t24 PASS.** Wiring a real vendor FP4/MX block-scaled GEMM behind
this same vector table (so the boundary vectors execute the device's own
accumulator, not the CPU's) is the prerequisite follow-up named in spec §9
item 1 and tracked as ACTIVATION.md Gate C item C2 — out of scope for this
runbook, which only makes the *measurement plumbing* turnkey.

### 2.3 What JSON to send back, and how to aggregate

Send back the `matmul-v4-report-<hostname>.json` file `measure-hardware.sh`
prints the path to (or the `--out` path if you set one), one file per
box/backend. To settle the ordering (spec §9 items 1 and 4; ACTIVATION.md
Gate C items C2/C4-b), the minimum aggregate set is:

1. **≥ 1 datacenter part** (B200 or B300 `cuda`, or MI355X `hip`) — needed
   for the frontier-DC anchor and (once a real BMX4-C device kernel lands)
   the M-t24 PASS/FAIL on that vendor's block-scaled accumulator.
2. **≥ 1 consumer part** (RTX 5090 `cuda`) — the consumer-frontier anchor
   for the §K.2b tensor-share and B2b throughput comparison; also a second,
   independent M-t24 data point (different silicon, same vendor family).
3. **≥ 1 Apple part** (`metal`, M5-class for the tensor path) — the M-class
   anchor; M-t24 on Apple's Neural Accelerator/TensorOps path is one of the
   two "genuinely uncertain" outcomes flagged in the spec's residual-open-
   questions section (§10).

**M-t24 activation requires PASS on ≥ 2 *independent vendors'* frontier
parts** (spec §9 item 1) — e.g. one NVIDIA (B200/B300) PASS plus one AMD
(MI355X) PASS, or one NVIDIA PASS plus one Trainium3 PASS once that backend
exists; two NVIDIA parts alone do not satisfy the cross-vendor requirement.
Aggregation is manual (paste the JSONs into ACTIVATION.md Gate C's table,
§9 item 3's ≥2-vendor/≥3-jurisdiction golden-vector tally, and the §K.2b
tensor-majority + B2b marginal-nonce/s comparison across the collected set)
— there is no automated aggregator in this repo, by design (per §0.7-(4) the
protocol itself reads none of this; only humans do, in the open, before an
episode).

---

## 3. The modeled datacenter tax-inversion / ordering projection — MODELED, NOT MEASURED

**Read §0 again before reading this section. Every number below is MODELED
and explicitly barred from being load-bearing** (spec §6: "rate figures are
illustrative cited peaks/measurements, never load-bearing — ordering ships
only after the §9 measurements"). This section exists to give an operator a
falsifiable expectation to check their real §2 measurement against — not a
result.

### 3.1 The real, implemented BMX4-C per-stage MAC counts (from code + spec, not modeled)

These MAC counts are **not** modeled — they are read directly from
`src/matmul/matmul_v4_bmx4.{h,cpp}`, `doc/btx-matmul-v4.2-bmx4c-spec.md` §2.4/§3,
and the `marginal_tensor_macs_per_nonce` field the report tool actually
computes and printed in §1's JSON (`n²·m + 16·m²·n` MACs/nonce at `m = n/4`):

| Stage | Real MAC count (exact) | At n=4096 (b=4, m=1024) |
|---|---|---|
| Expand B̂ (XOF, not tensor) | — (SHA-256 counter-mode; ≈5.88 bits/element ⇒ ≈385k SHA compressions/nonce at n=4096, spec §1.5) | not a MAC stage |
| S2: `Q = B̂·V` (the marginal GEMM, one shape everywhere) | n·n·m MACs | 4096² · 1024 ≈ 1.72 × 10¹⁰ |
| S3: base-2⁶ combine, 16 limb-pair GEMMs `S_ij = P_i·Q_j` | 16 · m·m·n MACs | 16 · 1024² · 4096 ≈ 6.87 × 10¹⁰ |
| **Total tensor MACs/nonce** (`marginal_tensor_macs_per_nonce`, `matmul-v4-report`'s own field) | **n²m + 16m²n** | **≈ 8.59 × 10¹⁰** (n=4096) |
| digest `H(σ‖Ĉ)` | — (SHA-256 over the 8 MiB payload, not tensor) | not a MAC stage |

Confirmed against this run's own JSON at n=256 (`m=64`):
`256²·64 + 16·64²·256 = 4,194,304 + 16,777,216 = 20,971,520`
— **matches `marginal_tensor_macs_per_nonce: 20971520` exactly** (§1.1 JSON).
At n=512 (`m=128`): `512²·128 + 16·128²·512 = 33,554,432 + 134,217,728 =
167,772,160` — **matches `167772160` exactly** (§1.2 JSON). So the formula
below is not a guess; it is the code's own accounting, cross-checked against
two independent real runs.

At the consensus dims (n=4096, b=4, m=1024): **1 MAC = 2 INT8-equivalent ops**
(the spec's own convention, matmul-v4-report.cpp `marginal_tensor_ops = 2 *
marginal_tensor_macs`) ⇒ **≈1.72 × 10¹¹ INT8-equivalent ops/nonce**, i.e. the
combine (S3, the 16 limb-pair GEMMs) is **≈4× the raw MAC volume of S2** —
consistent with the CPU wall-time split actually observed in §1 (S3 dominates
S2 by roughly 2–3×, the gap from the ideal 4× explained by S2's larger
single-GEMM efficiency vs 16 smaller limb-pair GEMMs on this CPU — exactly the
kind of gap real accelerator measurement (§2) must re-confirm, since GEMM
efficiency at small tile shapes is architecture-specific).

**GEMM-count tax under BMX4-C, per the design's own accounting (spec §5.2,
§6):** on any device that PASSES M-t24 (proven t≥24 exact accumulator on the
block-scaled path), BOTH tensor stages (S2 and the S3 limb-tensor combine) run
as **1 native block-scaled FP4/MX GEMM each** — **k²=1, no promotion, no
slicing** — because every per-MAC bound (2304 for the base product envelope,
288 for P/Q, 1024 for a limb-pair entry) sits under 2²⁴ ≤ 2²³ at production n
(spec §2.4 table). On a device that fails M-t24 but has a true INT8 int32
accumulator, the SAME stages run as **1 pre-shifted s8 GEMM** (still k²=1 —
the profile's headline property vs the old ENC-S8/pre-BMX4 4-GEMM slice
tax, spec §5.2/§6). The GEMM-count arithmetic itself (k²=1 in both cases) is
exact, not modeled; what is modeled is which *rate* (native FP4/MX vs INT8)
each vendor's silicon actually delivers for these exact shapes — that is
precisely what §2's real run measures and this section cannot.

### 3.2 Published dense FP4/INT8 TOPS by device — cited figures, MODELED usage

TOPS figures below are **cited from vendor materials / peer benchmarks
already vetted elsewhere in this repo** (`doc/btx-matmul-v4-frontier-native-
format.md` §5, `doc/btx-matmul-v4-multiplatform-roadmap.md` §2/§3.2,
`doc/btx-matmul-v4-china-accelerators.md`), reproduced here for convenience.
**Citing them is not measuring them for THIS workload** — see §3.3.

| Device | Dense INT8 TOPS (cited) | Dense FP4/MX TOPS (cited) | Source |
|---|---|---|---|
| H100/H200 | 1,979 | — (no FP4 unit) | arXiv:2512.02189 |
| B200 | 3,927 | 7,702 (measured, not datasheet) | arXiv:2512.02189 |
| B300/GB300 | reduced vs B200 (unpublished exact figure — "cut... to fund NVFP4") | ≈1.5× B200 FP4 ⇒ **≈11,553 modeled** | Tom's Hardware; NVIDIA Blackwell Ultra blog |
| Rubin/Rubin Ultra | not listed as first-class (flat/unconfirmed ⚠) | vendor roadmap class ≈35,000–50,000 (PF-class, 2× width for FP4/FP8 only) | NVIDIA Rubin blog; SemiAnalysis |
| RTX 5090 (consumer Blackwell) | 838 | ≈2× its INT8 ⇒ **≈1,676 modeled** | roadmap doc §5 (illustrative ratio, not a vendor FP4 spec) |
| MI355X (CDNA4) | retained, isolated rate **not pinned in any source found** | ≈10,100 TOPS-class (OCP MXFP4) | AMD blog; STH Hot Chips CDNA4 |
| Trainium3 (NKI Matmul-MX) | **none — no INT8 matmul unit on the systolic Tensor Engine** | ≈4× its BF16 rate (vendor-relative, no absolute TOPS pinned) | AWS NKI Trainium2/3 docs |
| TPU v7 (Ironwood) | native INT8 retained | FP8 ≈4,614 TF-class cited elsewhere; no dense FP4 unit confirmed | frontier-native-format.md §5.2 |
| Apple M5 Max | ~130 (third-party microbench, no first-party figure) | MX-format support arriving OS 27, no TOPS figure published | roadmap doc §2 |
| Ascend 950 (Huawei, China-domestic, illustrative only — export-banned from global rentability) | not the relevant path (E8M0/MXFP4 native) | ≈2 PFLOPS ≈ 2,000 TOPS-class ≈ ¼ of B200's dense FP4 | china-accelerators.md §"illustrative figures" |

### 3.3 The modeled expected-throughput / ladder table (BMX4-C, k²=1 assumption)

Combining §3.1's exact MAC accounting with §3.2's cited peaks, under the
**assumption that M-t24 PASSES on that device's native block-scaled path**
(k²=1, no promotion tax) or, failing that, its 1-GEMM INT8 fallback also
applies at k²=1:

| Device | Native path assumed | k² (GEMM-count tax) | MODELED effective rate (illustrative TOPS, ÷k²) | MODELED vs own frontier |
|---|---|---|---|---|
| **B300/GB300** | native `mxf4` block-scaled, **M-t24 must PASS** | 1 | **≈11,553** (modeled from §3.2) | ≈1× — this is the "9× tax removed" headline IF M-t24 passes |
| **Rubin** | native FP4 block-scaled ⚠ INT8 survival unconfirmed | 1 | **≈35,000–50,000 class** (vendor roadmap, wide uncertainty) | ≈1× ⚠ |
| **MI355X** | native OCP MXFP4, **M-t24 must PASS** | 1 | **≈10,100** | ≈1× |
| **B200** | native `mxf4` (same block-scaled kinds as B300) | 1 | **≈7,702** (this figure IS a real measurement — arXiv:2512.02189 — for FP4 peak; its APPLICATION to BMX4-C's exact shapes is still modeled) | ≈1× |
| **RTX 5090** | FP4 with 2^e in UE4M3 scale slots (exact embed), or INT8 fallback | 1 | **≈1,676 modeled (FP4) / 838 measured (INT8)** | ≈1× |
| **Trainium3** | native Matmul-MX (MXFP4), **M-t24 outcome flagged "genuinely uncertain" in spec §10** | 1 if PASS | ≈4× its BF16 rate (no absolute TOPS pinned) | ≈1× IF M-t24 PASSES; otherwise this device has **no fallback** (no INT8 matmul unit at all) |
| **TPU v7** | FP8 scale-fold (needs proven t≥24), else INT8 native | 1 | FP8 ≈4,614 TF-class OR native INT8 rate | ≈1× either way |
| **H100/H200** | no FP4/MX unit at all; 1-GEMM INT8 (true int32 accum, proven) | 1 | **1,979 measured** | ≈1× — legacy DC, unaffected |
| **Apple M5** | INT8→INT32 (proven), or MX path if OS/hardware supports it | 1 | **≈130 (third-party estimate)** | ≈1× — bottom of the ladder, as intended |

**Headline (MODELED, not a result):** IF M-t24 PASSES on ≥2 independent
vendors' frontier DC parts (the spec's own activation bar), the BMX4-C
profile's k²=1 design removes the 4–9× GEMM-count tax the OLD ENC-S8/pre-
BMX4 objects imposed on FP4-frontier chips (roadmap §5.1/§5.2, reproduced
above) — collapsing the ladder to something close to raw published FP4/MX
TOPS ratios, i.e. datacenter FP4 (B300/MI355X/Rubin, ~10,000–50,000-TOPS
class, MODELED) ≫ consumer FP4/INT8 (5090, ~1,700/838, MODELED/measured) ≫
M-class INT8 (M5, ~130, third-party estimate) — the intended scaled-reward
ordering. **This is exactly the same shape of claim that has been falsified
twice before in this program.** The specific failure modes that would
invalidate it, all real and all requiring §2's measurement to rule out:

- M-t24 FAILS on Blackwell TMEM (spec §10: "genuinely uncertain") — B200/B300
  fall to their FP8 fold or 1-GEMM INT8 fallback, collapsing the "≈1×" cells
  above to the FP8-vs-FP4 gap or to plain INT8, i.e. B300's modeled 11,553
  becomes its INT8 rate (unpublished, but "cut... to fund NVFP4" — could be
  well under B200's 3,927).
- Trainium3 has **no INT8 fallback at all** (roadmap §4.1/§2 matrix) — if its
  M-t24 outcome is FAIL, it is excluded from BMX4-C mining entirely, not
  merely taxed.
- The §K.2a-WT tensor-stage majority (spec §9 item 4: "the combine's
  predicted ~70–80% share is a model, not a result") could come in as a
  MINORITY on some device's actual instruction mix, which would flip the
  GO/NO-GO regardless of the MAC-count/TOPS arithmetic above.
- Every "modeled" TOPS-derived rate in the table ignores memory-bandwidth,
  kernel-launch, and host↔device transfer floors that §K.2a-WT/§K.2b exist
  specifically to surface (roadmap §4.2's systolic/cloud caveat applies
  doubly to any device whose per-nonce nonce-fresh B̂ (16 MiB at n=4096) must
  cross a host↔device link every nonce).

---

## 4. The one gap this document cannot close: the actual on-silicon measurement

**There is no GPU, TPU, NPU, or any other accelerator in this repository's
execution environment.** Every command in §1 ran on CPU only, and the tool
itself is explicit about the consequence: for `--backend cpu`, `RunMt24`
reports `device_native_kernel_wired=true` / `native_path_eligible=<the CPU
self-test result>` because a CPU genuinely is a true int64/int32 accumulator
by construction (§1.3). **For every other backend, and on every machine
available to produce this document, that same code path reports
`native_path_eligible=false` with the reason "no on-device BMX4-C block-scaled
tensor kernel is wired into this build ... this run exercised the
CPU-reference boundary vectors only ... it does NOT constitute an on-silicon
M-t24 measurement for this device."**

Concretely, the gap is two-layered and neither layer can be closed from here:

1. **No BMX4-C device kernel exists yet in this codebase** for CUDA, HIP, or
   Metal (only the v4.1 ENC-S8 `s8×s8→s32` kernels are wired — spec §9 item 1
   names wiring a real vendor FP4/MX block-scaled GEMM behind the M-t24
   vector table as the required follow-up, tracked ACTIVATION.md Gate C item
   C2/C1). Writing that kernel is out of scope for this measurement-readiness
   task (and out of scope for this session's mandate, which touches only this
   one new doc).
2. **Even with that kernel wired, this environment has no B200, B300, RTX
   5090, MI355X, Trainium3, TPU v7, or Apple M5 hardware to run it on.** §2's
   one-command sequence is fully turnkey — an operator with such hardware
   needs nothing beyond this document and a clone of the repo — but *running*
   it, collecting the JSON, and aggregating ≥2 independent vendors' frontier-
   part PASSes (spec §9 item 1; ACTIVATION.md Gate C) is a step this session
   cannot perform.

**Until that real measurement lands, ENC-BMX4C's datacenter-favoring ordering
remains, by the spec's own explicit rule, a hypothesis — never a result — and
`nMatMulBMX4CHeight` correctly stays at its default-disabled `INT32_MAX` on
every network** (spec Activation status banner; ACTIVATION.md Gate C banner).
This document's contribution is making the eventual real measurement
turnkey (§2) and giving it a falsifiable, honestly-labeled expectation to
check itself against (§3) — not producing that measurement itself.

---

## References

`doc/btx-matmul-v4.2-bmx4c-spec.md` (normative; every constant and gate cited
here) · `doc/btx-matmul-v4-multiplatform-roadmap.md` (per-platform feasibility,
the INT8-vs-frontier decoupling analysis, confidence table) ·
`doc/btx-matmul-v4-frontier-native-format.md` §5 (the tax-inversion table this
doc's §3.3 extends to ENC-BMX4C's pinned S=3/E_max=48 parameters) ·
`doc/btx-matmul-v4-china-accelerators.md` (Ascend illustrative figures,
measurement-gated posture) · `ACTIVATION.md` Gate C (the tracked checklist) ·
`src/matmul-v4-report.cpp`, `src/matmul/matmul_v4_bmx4.{h,cpp}` (the tool and
reference this doc's §1 output and §3.1 MAC counts come from) ·
`contrib/matmul-v4/measure-hardware.sh`, `contrib/matmul-v4/verify-backend.sh`
(the §2 one-command sequence).
