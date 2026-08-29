# v0.34.4 GPU-optimization active-chain-recovery CUDA+Metal Profile-1 goldens

Measured on the clean private-branch freeze `230e2330` after adding stale body
download-root handoff and integrated signer/mirror active-chain migration. No
source change was made between the freeze and either provider measurement.

CUDA (`sm_120`) and Metal (`m4_class`) both built and verified `btxd`,
`btx-cli`, and `matmul-v4-rc-harness` from the exact freeze. The strict
combined comparison reports `complete_multi_gpu_match=true`,
`allow_partial=false`, and `cuda_metal_match=true`, with zero mismatches and
zero coverage failures.

| | |
|---|---|
| Source revision | `230e23300ea9ab5cb37530c766e95a2091faec33` |
| Fingerprint | `2bd4592ec3d1ef2d193ba5f601374282dd6611c3896e412a341cbc49ae44bb64` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| CUDA harness SHA-256 | `a855eb9c3e7e9efcc69c13dcddf5fdc731962e6f1698a053b49948976e3b46fd` |
| CUDA artifact SHA-256 | `ab5ceb31dcd16048a23a871f9e254b116ba7895ad41765f13f589779554aa078` |
| Metal harness SHA-256 | `46c8ee310c1e6e2a68a58d8586b3354721a78dc8e82ca600ed0fccef0529fd23` |
| Metal artifact SHA-256 | `ba2bd984cde64f0410b79d10f708eab7e17fde97f111d3c422e8ebd9b0e4d3a4` |
| Episodes and nonces | 8 episodes, nonces 1 through 8 |
| Device execution | 1,088 calls and 1,129,198,441,725,952 MACs per backend |
| CPU execution | zero calls, MACs, and fallbacks on both backends |

Both platform release-binary gates passed. The evidence contains only
machine-class provider identity and public corpus data; it contains no
hostname, device SKU, local path, daemon configuration, datadir, or signing
key material.
