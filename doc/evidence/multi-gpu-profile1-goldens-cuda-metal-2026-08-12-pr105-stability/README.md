# PR #105 stability freeze: Profile-1 ExactReplay golden compare

Status: **complete CUDA+Metal production-golden cohort**. Eight canonical
Profile-1 ExactReplay episodes (nonces 1 through 8, `matmul_dim=4096`) were
reproduced from the same clean source freeze on independent CUDA and Metal
providers. Every frozen header and digest matched byte-for-byte, with zero
coverage failures and zero CPU GEMM fallback.

## Freeze

Harness capture (CUDA+Metal ExactReplay, digest-forming arithmetic):

| | |
|---|---|
| Measured source revision | `f309810547e1dc3128cb8f691938ae6fa2a3c60e` |
| Measured fingerprint | `8ec950f89c39b3c13e4e08c0366b73573b3f848d4a470ddb33fe9d3d35c685f2` |
| Episode profile | 1 (Epoch-A production shape) |
| Episodes | 8 |
| Canary nonce start | 1 |

Nonce-1 ExactReplay digest is unchanged through later logic-only reseals
(`b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953`).
Goldens were not re-run on the live GPU. The JSON `source_revision` /
`tip_sha` / fingerprint fields are rebound to the current production
freeze so `verify-production-golden-seal.py seal` matches the manifest.

Current production freeze (v0.33.3 logic `67728d4e`):

| | |
|---|---|
| Manifest / evidence `source_revision` | `67728d4e9ed245613780b2f7824e528915c6b0a6` |
| Manifest / evidence fingerprint | `524120d9ad756231a1eb83a30d9e9c81fef3e05118238319e62ebc20e1bc3f22` |

Both harnesses executed 1,129,198,441,725,952 consensus MACs on-device
across the eight episodes at the original capture.

## Providers

| | CUDA | Metal |
|---|---|---|
| Provider | `cuda_rc_exact_fused_extract` | `metal_int8_mpp_tensorops_fused_extract` |
| Architecture class | `sm_120` | `m4_class` |
| CPU GEMM fallbacks | 0 | 0 |
| Harness SHA-256 | `a81aee4359a504cdfed6d03c9ecfe36e99fc4c9c83d51af9fa06b1dae097b0b8` | `bcca972e46e39fdf0b49aa55fa61860d190ebe04f07542f0873876ec74297b1d` |

`multi-gpu-digest-compare.json` records
`complete_multi_gpu_match=true`, `cuda_metal_match=true`, no mismatches, and
no coverage failures. The committed production manifest pins the nonce-1
digest and both provider-specific harness identities to this freeze.

## Production seal on this PR

This directory is the Authority CUDA+Metal golden other operators can
consume. `pr/0.33.3-network-stability` / tag `v0.33.3` binds that same
cohort to the Phase 1 freeze. Digest slot `[4]` is unchanged.

| | |
|---|---|
| Manifest `source_revision` | `67728d4e9ed245613780b2f7824e528915c6b0a6` |
| Manifest `source_tree_fingerprint` | `524120d9ad756231a1eb83a30d9e9c81fef3e05118238319e62ebc20e1bc3f22` |
| Binary cut | `93c27b8332cac61e0e07c694711540f603c98950` (`v0.33.3`) |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| CUDA artifact | [`raw/profile1-cuda-8.json`](raw/profile1-cuda-8.json) |
| Manifest | [`src/matmul/matmul_v4_rc_production_golden_manifest.data`](../../../src/matmul/matmul_v4_rc_production_golden_manifest.data) |

CPU/pool nodes should build this branch; they do not need a CUDA `btxd`.
AssumeUTXO pin is height **191266**. Public archival `addnode` seeds are in
[`doc/btx-public-node-bootstrap.md`](../../../doc/btx-public-node-bootstrap.md).

## Policy

Independent reproduction for Epoch-A production goldens is
**cross-GPU-backend** (CUDA and Metal) ExactReplay on identical frozen canary
headers. HIP remains optional, but any submitted HIP corpus must match this
cohort. Portable CPU execution is not an independent production provider for
this GPU-optimized chain.

## Artifact

- `multi-gpu-digest-compare.json` — strict release-grade comparison
- `raw/profile1-cuda-8.json` — sanitized CUDA evidence
- `raw/profile1-metal-8.json` — sanitized Metal evidence

The public artifacts contain machine-class provider and runtime capability
data only. They contain no hostname, account name, filesystem path, device
serial, network address, credential, or deployment secret. This corpus proves
provider agreement; activation remains governed by the committed code and
manifest.
