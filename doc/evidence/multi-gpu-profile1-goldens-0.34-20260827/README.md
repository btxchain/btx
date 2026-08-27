# 0.34 freeze CUDA Profile-1 ExactReplay goldens

Measured on the freeze commit that dropped the Metal device-name admission
gate. Metal rows are not shipped in this tree; builders add their own class
row per `doc/btx-fork-golden-self-sufficiency.md`.

| | |
|---|---|
| Source revision | `606f86101ebe6550f13b4f18cc7c4b207f76e4f5` |
| Fingerprint | `d3453bc32f4aca1bf30ceca95c87965b6f1e1c8a242206b9c12ca2e42d217912` |
| Backend | `cuda_rc_exact_fused_extract` / `sm_120` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| Kept run | this directory (2026-08-27 CUDA corpus at the freeze) |
