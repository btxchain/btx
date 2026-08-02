# Final-code-freeze Metal Profile-1 corpus

Status: **Metal complete; CUDA reproduction pending**.

This corpus was generated from code freeze
`602a9d08fa95d1e751e7814157a897ec499f83ed` using the strict
`metal_int8_mpp_tensorops_fused_extract` provider on Apple Silicon M4 Max-class
Metal. The source-tree fingerprint is
`4649ffd436459622ea2be55fa34c0ee4877ee8c69760db5f21d6f805f2e98483` and
the provider-specific harness SHA-256 is
`8bd1c7438a23b79f6aa05644390d6cb4e8d000f0fa214d1116d1b62f146dff7f`.

## Result

- Eight canonical 182-byte production canary headers, nonces 1 through 8.
- `matmul_dim=4096` for every header.
- `all_consensus_macs_on_device=true`.
- 1,088 device calls and 1,129,198,441,725,952 device MACs.
- Zero CPU GEMM calls, MACs, or fallbacks.
- No provider, provenance, canonical-header, or acceleration coverage failure.
- Mean production ExactReplay wall time approximately 28.08 seconds.

The partial comparator intentionally reports `complete_multi_gpu_match=false`
because this directory contains only the final-freeze Metal provider. It
reports no mismatch and no coverage failure. A CUDA provider must reproduce
the same revision, source-tree fingerprint, headers, and digests before the
CUDA+Metal cohort may populate `CommittedRCProductionGoldenManifest()`.

## Artifacts

- `raw/profile1-metal-8.json` contains the public-evidence harness result.
- `multi-gpu-digest-compare.json` contains the fail-closed partial comparison.

The artifacts expose machine-class and provider/runtime capability data only.
They contain no hostname, account name, filesystem path, device serial, network
address, credential, or deployment secret.
