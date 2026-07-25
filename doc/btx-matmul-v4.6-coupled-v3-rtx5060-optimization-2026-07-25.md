# MatMul v4.6 coupled V3: RTX 5060 bounded-memory optimization

Date: 2026-07-25  
Status: WIP performance implementation; not public-activation evidence  
Working branch: `wip/matmul-v46-coupled-v3-consumer-gpu-fri-fix`  
Optimization base: `d6b445726f9f7bbd4757a751429930e5da90862a`  
Optimization tip: `64643ae043b3d29aa14be9dc73660eeb5910d865`  
Consensus profile: `ENC_RC_COUPLED`, transcript V3

## Summary

The frozen coupled-V3 production shape can execute on an 8 GiB NVIDIA RTX
5060 without allocating either the approximately 51 GiB canonical packed bank
or the 96 GiB expanded bank.

The retained implementation does not materialize the complete bank. It:

- computes the template commitment as an ordered page stream;
- regenerates scheduled pages on demand;
- generates and consumes most scheduled pages directly in an exact CUDA GEMM;
- releases each page after commitment or computation;
- memoizes only the template-scoped bank root for repeated nonce attempts;
- retains an empty-backend CPU path for winning-candidate reseal and strict
  consensus validation.

The full barrier schedule still processes all 1,536 pages exactly once. In the
final mixed schedule, 1,408 pages use fused CUDA generation/GEMM and 128 pages
use the overlapped CPU producer. Observed CUDA allocation was approximately
698 MiB, and the two-episode process peaked at approximately 1.62 GiB host
RSS.

For a same-template production episode:

- the initial correctness-first streamed implementation took `368.303537 s`;
- the first retained optimization round reached `70.578571 s`;
- the final retained implementation reached `22.877278 s`;
- final throughput was `0.04371149 episode/s`, or `157.3614 episode/hour`.

This is a 16.10x throughput increase and a 93.79% wall-time reduction relative
to the initial streamed path. A later mining-only device-page callback reduced
cold commitment to `49.974085 s` and cold total to `72.989330 s`, while the
warm episode remained approximately 23 seconds.

The complete empty-backend CPU production replay was also measured and
optimized. It improved from `455.011832 s` to `312.676 s`. Winning-candidate
reseal and subsequent strict local validation remain separate CPU passes, so
their serial workstation cost is approximately 10.4 minutes.

No consensus mathematics, transcript byte, production dimension, activation
height, or CPU-validation trust boundary was changed.

## Test system

```text
GPU: NVIDIA GeForce RTX 5060
VRAM: 8,151 MiB
Compute capability: 12.0 / SM120 family
Driver: 610.43.02
CPU: Intel Core i5-14400F
CPU topology: 10 physical cores / 16 logical CPUs
Host RAM: 62 GiB
Build tree: build-cuda-review
Exact device provider: cuda_imma
Native package: SM120 MMA linked and byte-qualified
```

The results are specific to this workstation and software revision. They do
not establish multi-GPU scaling or performance on other Blackwell products.

## Frozen production shape

| Parameter | Value |
|---|---:|
| Barriers | 8 |
| Lobes | 8 |
| Lobe width | 8,192 |
| Rows per lobe | 128 |
| Bank pages | 1,536 |
| Pages per barrier/lobe | 24 |
| Material-exchange rounds | 4 |
| Expanded bank | 96 GiB |
| Canonical packed bank | approximately 51 GiB |
| One expanded page | 64 MiB |
| Scheduled exact work | approximately 12 TiMAC |

The complete packed or expanded bank is not a consensus residency
requirement. The bank commitment hashes expanded pages in canonical order and
can be computed incrementally. The barrier schedule can likewise regenerate,
consume, and release one page at a time.

The estimators at the optimization tip reported:

| Execution mode | Estimated resident bytes |
|---|---:|
| Full expanded bank | 103,154,712,832 bytes (`96.0703 GiB`) |
| Streamed working set | 142,606,592 bytes (`136.000 MiB`) |

Actual process memory also includes the CUDA context, code, worker state,
temporary results, and benchmark harness.

## Execution architecture

### Cold template commitment

For a fresh template, every page is generated in page order and fed to the
ordered host SHA-256 commitment. The mining-only path can use a qualified CUDA
page generator, but hashing remains ordered on the host. CPU reseal and
validation do not use this callback.

After the first complete commitment, a small process-local memo may retain the
template-scoped bank root. Its key binds:

- template hash;
- parameter fingerprint;
- height;
- transcript version;
- bank-page count; and
- page width.

The memo contains no bank pages. Winning-candidate CPU reseal clears it, and
strict validation does not receive it.

### Warm barrier episode

The final schedule assigns one host-generated page for every eleven
device-generated pages:

```text
1,536 scheduled pages
  = 128 overlapped CPU pages
  + 1,408 fused CUDA pages
```

The device path performs deterministic mantissa/scale generation,
dequantization, and exact INT8-to-INT32 GEMM without a 64 MiB
device-to-host-to-device page round trip. Any generator status failure, CUDA
failure, or self-qualification mismatch declines the path and preserves the
CPU oracle/fail-closed behavior.

The host tail parallelizes:

- counter-addressable material-exchange XOF work;
- proof-friendly nonce permutation construction;
- butterfly mix; and
- ExtractMX tiles.

Operations whose serial order is consensus-visible, including Fisher–Yates
draw order and accumulation order, remain ordered.

### CPU reseal and validation

Winning reseal and strict validation share a bounded Streamed execution
policy, but they run through the empty accelerator backend. The final
16-worker allocation was:

- five workers for bank generation plus ordered SHA;
- five workers for scheduled next-page expansion;
- six workers for exact AVX2 GEMM.

The bank and episode execute concurrently with disjoint worker budgets.
Scheduled page expansion overlaps exact GEMM, and MX scales are applied in
place to avoid a second full-page buffer.

## Production measurements

### Cumulative GPU result

| Implementation state | New-template wall | Same-template wall | Same-template rate | Hourly rate |
|---|---:|---:|---:|---:|
| Initial streamed baseline | 368.303537 s | 368.303537 s | 0.00271515/s | 9.77455 |
| Root memo only | 365.742345 s | 172.583140 s | 0.00579431/s | 20.8595 |
| Fused CUDA pages | — | 101.521084 s | 0.00985017/s | 35.4606 |
| Right-sized CUDA XOF | — | 79.041564 s | 0.01265157/s | 45.5457 |
| First retained round | 264.739769 s | 70.578571 s | 0.01416861/s | 51.0070 |
| Mixed scheduler through `b4d199b` | 217.414685 s | 22.877278 s | 0.04371149/s | 157.3614 |
| Device-generated cold bank (`fd054d5`) | 72.989330 s | approximately 22.996369 s | approximately 0.043485/s | approximately 156.55 |

The baseline did not have a meaningful memo-hit distinction. The
device-generated commitment optimization affects cold mining only.

### Final cold/warm phase detail

| Metric | Cold run | Warm run |
|---|---:|---:|
| Total | 217.414685 s | 22.877278 s |
| Bank commitment | 194.396068 s | 0.000002 s |
| Barrier schedule | 22.999967 s | 22.858130 s |
| Fused CUDA pages | 1,408 | 1,408 |
| Overlapped CPU pages | 128 | 128 |
| Host page-expansion sum | 13.849608 s | 13.755488 s |
| Combined page/GEMM timer | 12.706288 s | 12.674899 s |
| Material exchange | 3.414748 s | 3.341778 s |
| Main permutation | 0.778779 s | 0.767337 s |
| Mix | 0.557256 s | 0.548426 s |
| ExtractMX | 0.094866 s | 0.091150 s |

Host expansion and CUDA page/GEMM timers overlap and must not be added to
infer barrier wall time. The barrier aggregate is authoritative.

The stable full-production digest was:

```text
0587420ebf2490c5a06648d9a988432b1064aa173d3125a59da6bd1b3831e605
```

The full production runs used explicit benchmark-only reference skipping
where stated. They are performance/feasibility evidence, not an independently
implemented production golden vector.

### CPU replay progression

All rows use the full production shape, an empty accelerator backend, no
bank-root memo, and CPU-derived commitment and scheduled pages:

| CPU replay state | Bank | Barriers | Total | Change from control |
|---|---:|---:|---:|---:|
| Direct measured control | 152.756172 s | 302.238257 s | 455.011832 s | — |
| Page expansion/GEMM overlap | 152.935577 s | 256.713865 s | 409.666621 s | -10.0% |
| Bank/episode overlap | 312.257 s | 329.114 s | 329.138 s | -27.7% |
| In-place MX page scaling | 272.303 s | 312.654 s | 312.676 s | -31.3% |

The bank timer increases in the overlapped rows because it receives fewer
workers and contends with the episode. It still completes before the episode,
so it is hidden from the final critical path. `total_s`, rather than the sum of
overlapping phase timers, is the end-to-end metric.

## Retained implementation series

### Exactness, measurement, and bounded execution

| Commit | Result |
|---|---|
| `ac43c88` | Replaced lossy signed-four-bit packed conversion with an exact E2M1/UE8M0 codec; malformed values fail closed. |
| `15b4d8a` | Added production V3, production-width smoke, and explicit benchmark provenance. |
| `50035e1` | Added detailed coupled phase timing. |
| `b52b64f` | Selected the qualified exact dense CUDA lane for coupled row-scale pages. |
| `06cb244` | Made nonresident execution truly streamed and selected it above the 8 GiB estimate; oversized fallback uses `Q=1`. |
| `27b41c1` | Added direct canonical packed-page generation and parallel unpack. |
| `f0526d3` | Memoized only the template-scoped bank root outside validation/reseal. |

### Fused device path and host tail

| Commit | Result |
|---|---|
| `2e3bc62` | Fused deterministic CUDA page generation with exact GEMM. |
| `1aeddb4` | Generated only the nonce-fresh `128 × 8192` activation prefix required by V3. |
| `9297151` | Right-sized mantissa-XOF capacity while retaining status-word fail closure. |
| `287732a` | Overlapped host and CUDA page producers without changing accumulation order. |
| `29e501e` | Parallelized material-exchange XOF and collision-free scatter. |
| `3cddb4d` | Parallelized deterministic nonce-permutation construction. |
| `a9a652a` | Parallelized butterfly mix over disjoint output ranges. |
| `885de5d` | Parallelized active-state ExtractMX tiles. |
| `85661d6` | Rebalanced host/GPU producers. |
| `644db71` | Replaced the serial CUDA mantissa-prefix walk with a deterministic two-level scan. |
| `b4d199b` | Retuned the measured producer ratio to 1:11. |

### Cold mining and CPU replay

| Commit | Result |
|---|---|
| `1e97ec4` | Pipelined ordered CPU bank hashing with expansion of the next page. |
| `dbece59` | Added row-parallel exact CPU GEMM and bounded Streamed reseal/validation. |
| `a7da9e3` | Added runtime-qualified AVX2 signed-int8 exact GEMM with scalar fallback. |
| `bd73532` | Reused hot right-operand rows across AVX2 output rows. |
| `fd054d5` | Generated cold mining commitment pages on the qualified GPU while retaining host hashing and CPU-only replay. |
| `4051b09` | Overlapped scheduled CPU page expansion with exact CPU GEMM. |
| `9b1dd0c` | Overlapped independent CPU bank commitment with the barrier episode. |
| `64643ae` | Applied MX row-block scales in place. |

## Correctness and fail-closed posture

Focused tests passed:

```text
matmul_v4_rc_accel_policy_tests
matmul_v4_rc_coupled_tests
matmul_v4_rc_packed_bank_tests
matmul_v4_rc_datacenter_tests
```

V3 CI CUDA matched the CPU reference:

```text
digest: a4bb0cc42e2b97631d126a0dcdae26ad83b2f287d885322392a564990a95bac4
device provider: cuda_imma
matched_cpu_exactgemm: true
```

All production-width backend, expansion, prefix-scan, and scheduler
comparisons produced:

```text
8005aa9ab8c521d26f8eb47533e24eddca880cbf1e054ee4cb1bedd08e6902db
```

Required trust boundaries:

- exact device paths self-qualify against the CPU oracle;
- generator or GEMM failure falls back or fails closed;
- page and accumulation order remain unchanged;
- execution-only worker counts do not alter transcript bytes;
- consensus validation uses an empty device backend;
- winning reseal clears the mining bank-root memo;
- no benchmark switch changes consensus activation.

The CPU and CUDA results are cross-path equality within this implementation.
Independent mathematical, cryptographic, and production-golden review remains
required.

## Rejected and non-retained experiments

| Experiment | Decision |
|---|---|
| 51 GiB packed disk cache | Rejected. Cold was slower; after separating the root-memo effect, warm read plus unpack was approximately equal to regeneration. |
| Atomic material-exchange queue | Rejected because scheduling overhead regressed the exchange phase. |
| Separate or fused exchange XOR fold | Rejected because neither improved complete phase wall time. |
| One host page plus 23 GPU pages | Rejected after the CUDA scan changed producer balance; 1:11 was faster. |
| Scalar `k`-major CPU GEMM | Rejected before AVX2 because it provided no useful improvement. |
| Dedicated CUDA page-only branch | Rejected because skipping a dummy one-row GEMM did not materially improve commitment time. |
| Packed four-`k` AVX2 dot kernel | Rejected because page repacking and cache disruption regressed GEMM. |
| Manual 32-column AVX2 unroll | Rejected because compiler scheduling/register allocation was better. |
| Persistent exact-GEMM worker pool | Inconclusive and not retained; launch cost was not material. |
| 4-row × 16-column register blocking | Rejected because strided right-operand scans regressed GEMM by roughly 4x. |
| Post-in-place 12+4 CPU worker split | Rejected by full production (`330.455 s` versus `312.676 s`). |

These approaches should not be repeated without a materially different
storage, scheduling, or fusion design.

## Activation-shaped regtest result

An isolated activation-shaped regtest at the optimization tip observed:

- height 4 selected `ENC-RC-COUPLED`, profile 3, production dimensions;
- the RTX 5060 used bounded streaming rather than a 51 GiB allocation;
- sampled GPU memory was approximately 710 MiB;
- sampled GPU utilization was 66–84%;
- the accelerated episode took approximately 22–25 seconds after cold bank
  construction;
- the winning candidate entered the deliberate CPU-only reseal.

The profile-3 CI shape completed end to end through CUDA mining, strict local
acceptance, P2P relay, and independent CPU-only acceptance by a fresh second
node. The production-shape attempt demonstrated correct path selection and
bounded memory but remained gated by the long CPU reseal/validation passes.

This was test-only evidence and did not change public activation heights.

## Remaining bottlenecks

### Fresh templates

Cold mining commitment is still approximately 50 seconds. The ordered host
SHA stream and page transfers are now larger than the approximately 23-second
accelerated episode.

### Warm mining

The remaining episode includes hybrid page generation, exact CUDA GEMM,
approximately 3.34 seconds of material exchange, and approximately 1.41
seconds of permutation/mix/extraction. GEMM-only tuning is no longer
sufficient.

### Nonce batching

The oversized-bank fallback uses `Q=1`, giving up intended Q-batch
amortization. A bounded streamed Q-batch should reuse each page across several
nonce states before eviction.

### CPU reseal and validation

Each mandatory CPU pass takes approximately 312.7 seconds on this workstation,
far above the target block interval. The next CPU work should investigate
safe page/lobe parallelism, topology-aware worker placement, and exact kernels
with better right-row locality without trusting device output.

### Shutdown behavior

An in-progress production CPU reseal was not cooperatively cancellable in the
node-level test. Miner-local preparation and reseal need bounded cancellation
latency.

## Inclusion status

The retained stack establishes:

- production V3 memory feasibility on an 8 GiB RTX 5060;
- exact bounded-memory CUDA mining;
- measurable and bounded CPU replay;
- stable digests across retained scheduling/backend changes; and
- explicit fail-closed boundaries.

It does not establish:

- public-network activation readiness;
- accepted blocks per hour;
- an independently generated production golden vector;
- permission to weaken CPU-only validation;
- multi-GPU behavior; or
- resolution of the cryptographic and pooled-mining audits.

The exact-V3 proof research intended to address the CPU replay bottleneck is
documented separately in
`doc/btx-matmul-v4.6-coupled-v3-boolean-word-proof-2026-07-25.md`.
