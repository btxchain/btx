# Google Cloud TPU bounded-exact GEMM boundary

## Exactness argument

The BTX TPU path is compile-time optional and fail-closed. A separately built,
version-pinned PJRT/libtpu bridge may use either a native integer MXU dot or a
BF16-input, FP32-accumulated MXU dot for the LT S8 lane.

The latter is exact—not approximate floating consensus arithmetic—when BTX's
host gate proves

```text
inner * max_abs(left) * max_abs(right) <= 2^24.
```

Every S8 integer is exactly representable in BF16. Every S8 product is exactly
representable in FP32. The absolute sum bounds every possible intermediate
partial sum, and every integer in `[-2^24, 2^24]` is exactly representable in
IEEE FP32. Equality is intentionally allowed and unit-tested. Calls one unit
above the bound are rejected before the provider runs. This is the PR's proven
`t=24` lane; it is not permission to use floating arithmetic elsewhere.

Official sources:

- TPU v5e specifications list native INT8 throughput:
  <https://docs.cloud.google.com/tpu/docs/v5e>
- Cloud TPU documents BF16 multiplication with FP32 accumulation:
  <https://docs.cloud.google.com/tpu/docs/bfloat16>
- Google's AQT article says TPU INT8 tensor operations may accumulate in INT32
  or BF16, so the string `INT8` alone is not an exactness proof:
  <https://cloud.google.com/blog/products/compute/accurate-quantized-training-aqt-for-tpu-v5e>
- XLA describes `preferred_element_type` as a recommendation, not a guarantee:
  <https://openxla.org/xla/operation_semantics#dot>
- StableHLO leaves dot-algorithm support backend-dependent:
  <https://openxla.org/stablehlo/spec#dot_general>
- PJRT C API is the supported device/plugin boundary:
  <https://openxla.org/xla/pjrt>

`IsTpuPjrtExactGemmAvailable()` becomes true only after the registered provider
matches CPU `ExactGemmS8S8` on odd, rectangular, TPU-tiled, cancellation,
maximum-magnitude, production-K, and `2^24`-boundary probes. The provider must
also attest that a TPU MXU executed. A PJRT CPU/host fallback is rejected.

## Provider requirements

The bridge must initialize and retain one TPU PJRT client, cache executables per
shape, keep reusable device buffers resident, synchronize PJRT futures, and
register `TpuPjrtExactGemmProviderV1` before backend resolution. For a BF16
executable it must:

1. convert S8 inputs to BF16 without scale or zero point;
2. require BF16 MXU multiplication and FP32 accumulation;
3. reject host callbacks and CPU fallback;
4. verify every FP32 result is finite, integral, and in S32 range before exact
   FP32-to-S32 conversion; and
5. set `used_exact_mxu=true` only with compiler/profiler native-path evidence.

BTX independently repeats the bound check for every launch. `S32 x S8 -> S32`
remains unavailable and falls back to CPU.

## Build and resolver wiring

The source and tests are wired into the default build. `BTX_ENABLE_TPU_PJRT`
stays OFF by default; enabling it compiles the provider registration boundary
but still does not link OpenXLA/libtpu or make TPU available by itself. A
matching external bridge must register before backend resolution and pass the
self-qualification above.

Set `BTX_MATMUL_LT_EXACT_BACKEND=tpu` to inject the qualified S8 callback into
MatExpand while the full v4 digest backend remains CPU. The S32 callback stays
null, failed launches fall back to CPU per call, and accelerated winners are
CPU-resealed. A qualification artifact should record device kind, PJRT and
compiler versions, production shapes, bound, native-path evidence, and CPU
parity hash before deployment.
