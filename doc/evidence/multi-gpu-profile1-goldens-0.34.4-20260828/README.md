# 0.34.4 freeze CUDA+Metal Profile-1 ExactReplay goldens

Measured on freeze `855f220b` after CUDA (macpro2, `sm_120`) and Metal
(macstudio-1, `m4_class`) both linked `btxd`, `btx-cli`, and
`matmul-v4-rc-harness` with `WITH_ZMQ=ON` at `F`. Compare reports
`complete_multi_gpu_match=true`, `allow_partial=false`, `cuda_metal_match=true`.
Nonce-1 digest is unchanged from 0.34.1/0.34.2/0.34.3; the reseal is required
because `validation.cpp`, `net_processing.cpp`, `src/node/header_sync.h`,
`src/node/chainstate.cpp`, and `CLIENT_VERSION_BUILD=4` moved the
BUILD_RELEVANT fingerprint.

| | |
|---|---|
| Source revision | `855f220b9e980addf4832654c2d5aefe85a6624b` |
| Fingerprint | `b9c6e4852ab1dc1cc7f998c7199a16f4b9fbd37af16fe00872f1fad2491adbc3` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| CUDA harness SHA-256 | `054d5dba37eaf3d6b8dd0f8583784088f865cd0d43c35d69763826a455da3b33` |
| Metal harness SHA-256 | `bc04611256e6ffd28faa2eface2de907cd2c78da32c7e531d8acaa5704aac05d` |
| Kept run | this directory (2026-08-28 CUDA+Metal corpus at the 0.34.4 freeze) |
