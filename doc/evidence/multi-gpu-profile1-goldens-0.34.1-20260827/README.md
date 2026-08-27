# 0.34.1 freeze CUDA+Metal Profile-1 ExactReplay goldens

Measured on freeze `8c5efb91` after CUDA (macpro2, `sm_120`) and Metal
(macstudio-1, `m4_class`) both linked `btxd`, `btx-cli`, and
`matmul-v4-rc-harness` with `WITH_ZMQ=ON`. Harnesses were relinked at `F`
so `embedded_source_revision` matches the freeze. Compare reports
`complete_multi_gpu_match=true`, `allow_partial=false`, `cuda_metal_match=true`.

| | |
|---|---|
| Source revision | `8c5efb91cd7eab9f3dbc3bfe6ae16a8cd6d59155` |
| Fingerprint | `5773990f7bee74099d5dda5aa12c825d3559d40c0599cec424313362f53f3678` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| CUDA harness SHA-256 | `1844a54f7b5e2411a4f55a163362205eb2d6ab085d97fff53eec0ad910fa45a5` |
| Metal harness SHA-256 | `92d49683babfd612d03eb3df5ca50cb5e2351c536032799cf63c0c7782e47db9` |
| Kept run | this directory (2026-08-27 CUDA+Metal corpus at the 0.34.1 freeze) |
