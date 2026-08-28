# 0.34.2 freeze CUDA+Metal Profile-1 ExactReplay goldens

Measured on freeze `791d82d7` after CUDA (macpro2, `sm_120`) and Metal
(macstudio-1, `m4_class`) both linked `btxd`, `btx-cli`, and
`matmul-v4-rc-harness` with `WITH_ZMQ=ON` at `F`. Compare reports
`complete_multi_gpu_match=true`, `allow_partial=false`, `cuda_metal_match=true`.
Nonce-1 digest is unchanged from 0.34.1; the reseal is required because
`chainparams.cpp` and `CLIENT_VERSION_BUILD` moved the BUILD_RELEVANT
fingerprint.

| | |
|---|---|
| Source revision | `791d82d7e2a74d42399c495d6789ff574a25a7ac` |
| Fingerprint | `187e19ba0e56b738b162245c3f270903d8a23f50906a4bc93699373be49be34c` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| CUDA harness SHA-256 | `b5c3ca7b102f3f2cdb269b951e1273e102a3a21fe94649dc4ef8e21418ae5913` |
| Metal harness SHA-256 | `9b188293f0ececb891a08890d102a733b7702121d49df6780077c560d2076f1e` |
| Kept run | this directory (2026-08-28 CUDA+Metal corpus at the 0.34.2 freeze) |
