# Profile-1 ExactReplay Metal golden corpus

Status: **Metal reproduction complete; HIP pending globally**. Ratification
gates remain false, the production golden manifest remains empty, and public
Epoch-A heights remain disabled.

## Reproduction

- Source revision: `9dd88b8e54d92a848c4006aa9affca2ab3e0c91c`
- Hardware class: Apple Silicon M4 Max-class Metal
- Provider: `metal_int8_mpp_tensorops_fused_extract`
- Frozen production canary nonces: 1 through 8
- `matmul_dim`: 4096
- All consensus MACs on device: true
- Device calls: 1,088
- CPU GEMM calls/fallbacks: 0/0
- Mean ExactReplay wall time: approximately 28.08 seconds
- Observed range: approximately 28.04 to 28.18 seconds

All eight frozen headers and ExactReplay digests match the committed CUDA set
byte-for-byte. The combined result is recorded in
`../multi-gpu-profile1-goldens-2026-08-01/multi-gpu-digest-compare.json`.

## Privacy and activation boundary

The harness ran with public-evidence mode, which replaces host-derived device
identity before writing the artifact. This directory contains no hostname,
account name, filesystem path, device serial, credential, or private deployment
information.

Portable CPU ExactReplay is not counted as an independent production-golden
backend. HIP reproduction on an AMD/ROCm device is still required before
`complete_multi_gpu_match` can become true or the manifest can be considered
for population.

See `raw/profile1-metal-8.json` for the frozen Metal records. The local
Metal-only comparison remains incomplete by design because it does not contain
CUDA or HIP inputs; the canonical cross-backend comparison is in the sibling
directory above.
