# Exact-head Metal Profile-1 corpus

Status: **Metal complete for the current code freeze; matching CUDA rerun
pending.**

This corpus was generated from revision
`5ba47d59c65747b8acf7e56bd58918d0269949c2` using the strict
`metal_int8_mpp_tensorops_fused_extract` provider on Apple Silicon M4 Max-class
Metal. The build-relevant source-tree fingerprint is
`e12212f9983ad93e054efb9e1c4e6fa90969e858bd2c12b44f287605173da2c3` and
the provider-specific harness SHA-256 is
`43a633900ca231be516814b8a6a8131eb1f90829d6be409c1465b9f3f5757c0d`.

## Result

- Eight canonical 182-byte production canary headers, nonces 1 through 8.
- `matmul_dim=4096` for every header.
- `all_consensus_macs_on_device=true`.
- 1,088 device calls and 1,129,198,441,725,952 device MACs.
- Zero CPU GEMM calls, MACs, or fallbacks.
- No provider, provenance, canonical-header, or acceleration coverage failure.
- Mean production ExactReplay wall time 28.1694 seconds (eight samples; p50
  28.1459 seconds, observed maximum 28.3494 seconds). This is not a p99 claim.

The partial comparator intentionally reports `complete_multi_gpu_match=false`
because this directory contains only the exact-head Metal provider. It reports
zero mismatch and zero coverage failure. Independent comparison also confirms
that all eight canonical header byte strings and digests remain byte-identical
to the earlier CUDA corpus. That historical CUDA result cannot close the gate,
however: the production policy requires CUDA to rerun from this same revision
and source fingerprint after all build-relevant fixes.

A successful exact-head CUDA reproduction can then be compared with this
artifact. Only a reviewed comparison with `complete_multi_gpu_match=true` may
populate `CommittedRCProductionGoldenManifest()`; the manifest and all public
activation/ratification settings remain fail-closed in this branch.

## Artifacts

- `raw/profile1-metal-8.json` contains the public-evidence harness result.
- `multi-gpu-digest-compare.json` contains the fail-closed partial comparison.

The artifacts expose machine-class and provider/runtime capability data only.
They contain no hostname, account name, filesystem path, device serial or other
unique hardware identifier, network address, credential, or deployment secret.
