# 0.34 freeze CUDA Profile-1 ExactReplay goldens

Measured on freeze `267b8834` (ADDR gossip kept on authority nodes, plus
the 30-day `-maxtipage` default). Metal rows are not shipped in this
tree; builders add their own class row per
`doc/btx-fork-golden-self-sufficiency.md`.

| | |
|---|---|
| Source revision | `267b8834b69e1680b3e02c65f3ac87cbce828e3a` |
| Fingerprint | `f54be6a09cb369ec7951830c5239ba1d19a15c7bcd2a284b1043bc8dc77ca140` |
| Backend | `cuda_rc_exact_fused_extract` / `sm_120` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| Harness SHA-256 | `559d3df8fccf03b4d212fc69a5fe350d025f85f2b3273f062d20c7f23af87d5a` |
| Kept run | this directory (2026-08-27 CUDA corpus at the ADDR freeze) |
