# AWS Trainium / Neuron bounded-exact GEMM boundary

## Exact BF16 lane

AWS NKI does not document an integer `S8 x S8 -> S32` Tensor Engine operation.
Its `nc_matmul` contract does document BF16 inputs and FP32 accumulation/results:

<https://awsdocs-neuron.readthedocs-hosted.com/en/latest/general/nki/api/generated/nki.isa.nc_matmul.html>

That floating datapath is nevertheless bit-exact for the bounded LT S8 GEMMs.
Before any provider call, BTX proves

```text
inner * max_abs(left) * max_abs(right) <= 2^24.
```

S8 values are exact in BF16, their products are exact in FP32, and the bound
makes every possible partial sum an exactly representable FP32 integer.
Equality at `2^24` is admitted and tested; a call above it is rejected before
NRT executes. This is the v4.4-LT proven-`t=24` construction, not generic use of
floating arithmetic for consensus.

Neuron Runtime exposes C/C++ APIs for loading a precompiled NEFF and executing
it on Trainium:

- <https://awsdocs-neuron.readthedocs-hosted.com/en/latest/neuron-runtime/api/index.html>
- <https://awsdocs-neuron.readthedocs-hosted.com/en/latest/neuron-runtime/nrt-api-guide.html>

The official NKI samples illustrate Tensor Engine tiling and compilation:

<https://github.com/aws-neuron/nki-samples>

## Provider requirements

A separately built NKI/Neuron bridge must precompile and version-pin BF16
`nc_matmul` NEFFs for the required static LT shapes. It registers
`TrainiumNeuronExactGemmProviderV1`, which becomes available only after CPU
parity probes covering odd/tiled panels, cancellation, production K=4096, and
the inclusive `2^24` boundary. The bridge must:

- convert S8 inputs exactly to BF16 with no quantization scale;
- keep all contraction chunks in FP32 PSUM;
- check FP32 outputs are finite, integral, and S32-range before conversion;
- attest `used_bf16_tensor_engine=true` only when native Tensor Engine—not a
  NEFF CPU function or NRT host fallback—ran; and
- retain loaded models and reusable device tensors across nonces.

BTX checks the proof bound on every call and CPU-reseals mining winners.
`S32 x S8 -> S32` has no proven Tensor Engine construction and always declines.

## Build and resolver wiring

The source and tests are in the default build. The OFF-by-default
`BTX_ENABLE_TRAINIUM_NEURON` option compiles the provider registration boundary
but does not link Neuron/NRT or make Trainium available by itself. A
version-pinned external NEFF/NRT provider must register and self-qualify; the
mere presence of `libnrt.so` or a device is never enough.

Set `BTX_MATMUL_LT_EXACT_BACKEND=trainium` to inject only the qualified S8
callback while the full v4 digest backend remains CPU. S32S8 stays null, failed
launches fall back to CPU per call, and accelerated winners are CPU-resealed.
Persist Neuron SDK/compiler/device/native-path evidence with the CPU parity
report before deployment.
