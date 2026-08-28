# v0.34.4 GPU-optimization CUDA+Metal Profile-1 ExactReplay goldens

Measured on clean freeze `ae3aef69` after replaying the reviewed CUDA
optimizations and operational fixes onto the v0.34.4 header-catch-up release.
The obsolete v0.34.3 seal was excluded; only functional source commits were
carried forward, and their range-diff against the reviewed branch is exact.

CUDA (`sm_120`) and Metal (`m4_class`) both built and verified `btxd`,
`btx-cli`, and `matmul-v4-rc-harness` from the exact freeze. The strict
combined comparison reports `complete_multi_gpu_match=true`,
`allow_partial=false`, and `cuda_metal_match=true`, with zero mismatches and
zero coverage failures.

| | |
|---|---|
| Source revision | `ae3aef695d5f156bb3ae6ee38abface9f40c3259` |
| Fingerprint | `18a8271cbc100b7324e7d7af8de3700d5b70f32d02ea9bd8fbbc54a5e10050e7` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| CUDA harness SHA-256 | `b48da45ad5c088bf2cbc91ae07430034bf568483bccd4b848b95e066156d0aa4` |
| CUDA artifact SHA-256 | `a8a393f2d4b442fcadd9f1cf051c4f43123107136b1f6320c879bb5cae309f1d` |
| Metal harness SHA-256 | `fff5de5a84adf7ddec1983d09137dfbdbcddec21a4d2cbde3199f886112ca393` |
| Metal artifact SHA-256 | `c632e2dd6ecb9a46144a1b0d50e20f043eddbbd6bb2fa7137931fe49ce9af952` |
| Episodes and nonces | 8 episodes, nonces 1 through 8 |
| Device execution | 1,088 calls and 1,129,198,441,725,952 MACs per backend |
| CPU execution | zero calls, MACs, and fallbacks on both backends |

Both platform release-binary gates passed. The evidence is public,
machine-class-only output and contains no hostname, device SKU, local path,
daemon configuration, datadir, or signing-key material.
