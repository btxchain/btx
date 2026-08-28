# v0.34.4 GPU-optimization logging-fix CUDA+Metal Profile-1 goldens

Measured on the clean private-branch freeze `00ea04a6` after correcting the
false same-height dual-quorum warning and the trusted-mirror deferred-body
cleanup retry loop. No source change was made between the freeze and either
provider measurement.

CUDA (`sm_120`) and Metal (`m4_class`) both built and verified `btxd`,
`btx-cli`, and `matmul-v4-rc-harness` from the exact freeze. The strict
combined comparison reports `complete_multi_gpu_match=true`,
`allow_partial=false`, and `cuda_metal_match=true`, with zero mismatches and
zero coverage failures.

| | |
|---|---|
| Source revision | `00ea04a67ae329f0947e5b258a6f1a929906d9fe` |
| Fingerprint | `366d683af0aae7100a446858b406f1143f16bed747e4ed1cd5e38c3fbac4d955` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| CUDA harness SHA-256 | `4d07d007e069adaf4b5a5e0b850bfb4a0a9a44c50e4e8769e5010bbe8d914289` |
| CUDA artifact SHA-256 | `27c2804705fb4b7fc18afab9e5bada1c09cc3bdee0a44928e7ac94c68067283b` |
| Metal harness SHA-256 | `ab429351fb273e6daeb2d0d55f8b2e2b2bd6f5023b859108ac31b8371929d1cb` |
| Metal artifact SHA-256 | `04877f329ebb8369e68b647e2775ad8c43cdde4439171014eb56f0c4ae903604` |
| Episodes and nonces | 8 episodes, nonces 1 through 8 |
| Device execution | 1,088 calls and 1,129,198,441,725,952 MACs per backend |
| CPU execution | zero calls, MACs, and fallbacks on both backends |

Both platform release-binary gates passed. The evidence contains only
machine-class provider identity and public corpus data; it contains no
hostname, device SKU, local path, daemon configuration, datadir, or signing
key material.
