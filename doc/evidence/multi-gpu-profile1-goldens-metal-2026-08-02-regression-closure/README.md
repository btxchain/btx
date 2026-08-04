# Post-regression-closure Metal Profile-1 corpus

Status: **Metal complete for the final non-CUDA code freeze; matching CUDA
rerun pending.**

This corpus was generated from revision
`0d89a930ea3745aeb1cfecffa069dae93d87a560` using the strict
`metal_int8_mpp_tensorops_fused_extract` provider on Apple Silicon M4 Max-class
Metal. The build-relevant source-tree fingerprint is
`e5efdc22090d9de6533d5ab6405b6a85079a78336c607ee30c02f72d2e2711cf` and
the provider-specific harness SHA-256 is
`5d7608bda60f765027f5dd69da74ad44e74700b5acb227120c1160fade67f55b`.

## Result

- Eight canonical 182-byte production canary headers, nonces 1 through 8.
- `matmul_dim=4096` for every header.
- `all_consensus_macs_on_device=true`.
- 1,088 device calls and 1,129,198,441,725,952 device MACs.
- Zero CPU GEMM calls, MACs, or fallbacks.
- No provider, provenance, canonical-header, or acceleration coverage failure.
- Mean production ExactReplay wall time 28.1768 seconds (eight samples; p50
  28.1670 seconds, observed maximum 28.2913 seconds). This is not a p99 claim.

The partial comparator intentionally reports `complete_multi_gpu_match=false`
because this directory contains only the exact-freeze Metal provider. It
reports zero mismatch and zero coverage failure. Independent field-level
comparison confirms that all eight canonical header byte strings and
ExactReplay digests remain byte-identical to the earlier CUDA corpus. That
historical CUDA result cannot close the gate: production policy requires CUDA
to rerun from this same revision and source fingerprint.

Only a reviewed exact-freeze comparison with
`complete_multi_gpu_match=true` may populate
`CommittedRCProductionGoldenManifest()`. The manifest, public activation
heights, and ratification settings remain fail-closed in this branch.

## Artifacts

- `raw/profile1-metal-8.json` contains the public-evidence harness result.
- `multi-gpu-digest-compare.json` contains the fail-closed partial comparison.

The artifacts expose machine-class and provider/runtime capability data only.
They contain no hostname, account name, filesystem path, device serial or other
unique hardware identifier, network address, credential, or deployment secret.
