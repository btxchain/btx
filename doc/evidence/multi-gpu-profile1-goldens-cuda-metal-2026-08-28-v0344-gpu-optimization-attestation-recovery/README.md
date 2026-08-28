# v0.34.4 GPU-optimization attestation-recovery CUDA+Metal Profile-1 goldens

Measured on the clean private-branch freeze `827185ab` after adding the
emergency RPC path that freshly ExactReplays the stored active-chain block and
durably clears an off-chain local attestation occupying the same height. No
source change was made between the freeze and either provider measurement.

CUDA (`sm_120`) and Metal (`m4_class`) both built and verified `btxd`,
`btx-cli`, and `matmul-v4-rc-harness` from the exact freeze. The strict
combined comparison reports `complete_multi_gpu_match=true`,
`allow_partial=false`, and `cuda_metal_match=true`, with zero mismatches and
zero coverage failures.

| | |
|---|---|
| Source revision | `827185ab7afeedff31a65c4f3ba8224d946570f3` |
| Fingerprint | `46e98488c8ee8782ffe2fe29a7d99d404be583dfe7967572698ab4f13faf6eb7` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| CUDA harness SHA-256 | `dd1181540949b06e1a7c7982cfe270d3961dd3b1a14a309b5133eb9470c635f1` |
| CUDA artifact SHA-256 | `076b4ba8e4b48b354161c1bd1d81eb861a759049cd86a89fc1daa2a22146a822` |
| Metal harness SHA-256 | `1323b904fadcf64b5f83e897c4f120173df19ecb90d4c59bcee74574d9c22945` |
| Metal artifact SHA-256 | `f37ca7167561c69708d505d3dc4cfce95afe5d9f0cab5a8b28abd610e85d6f64` |
| Episodes and nonces | 8 episodes, nonces 1 through 8 |
| Device execution | 1,088 calls and 1,129,198,441,725,952 MACs per backend |
| CPU execution | zero calls, MACs, and fallbacks on both backends |

Both platform release-binary gates passed. The evidence contains only
machine-class provider identity and public corpus data; it contains no
hostname, device SKU, local path, daemon configuration, datadir, or signing
key material.
