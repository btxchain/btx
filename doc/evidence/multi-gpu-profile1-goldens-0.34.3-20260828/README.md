# 0.34.3 freeze CUDA+Metal Profile-1 ExactReplay goldens

Measured on freeze `633d9e08` after CUDA (macpro2, `sm_120`) and Metal
(macstudio-1, `m4_class`) both linked `btxd`, `btx-cli`, and
`matmul-v4-rc-harness` with `WITH_ZMQ=ON` at `F`. Compare reports
`complete_multi_gpu_match=true`, `allow_partial=false`, `cuda_metal_match=true`.
Nonce-1 digest is unchanged from 0.34.1/0.34.2; the reseal is required because
`validation.cpp`, `net_processing.cpp`, and `CLIENT_VERSION_BUILD=3` moved the
BUILD_RELEVANT fingerprint.

| | |
|---|---|
| Source revision | `633d9e08c929b97b35ac64138b34822c7604fb4d` |
| Fingerprint | `afbbe3215335e0364e515de39f4d96321734fc172df20be7abbcf4af448ffe74` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| CUDA harness SHA-256 | `2815bf08808ea1d18d68242379ddcce407c9bb6c6fc239883513284fb46aefbb` |
| Metal harness SHA-256 | `79e21b5146bcf1753f8f1bea1bad3224835756e4dbb2a50aebbf1bc917c80c70` |
| Kept run | this directory (2026-08-28 CUDA+Metal corpus at the 0.34.3 freeze) |
