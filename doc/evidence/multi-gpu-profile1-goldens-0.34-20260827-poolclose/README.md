# 0.34 freeze CUDA Profile-1 ExactReplay goldens

Measured on freeze `ecfaa6c9` (shielded pool closed at height 199300,
plus the ECC `GetPubKey`-before-`ECC_Start` start fix). Metal rows are
not shipped in this tree; builders add their own class row per
`doc/btx-fork-golden-self-sufficiency.md`.

| | |
|---|---|
| Source revision | `ecfaa6c96cc9dde4be9062f57e0fa2cdfdd8eb54` |
| Fingerprint | `68bc97a7bb0fa0aebca823c6af0cd689596df3c46e85497a54df7b01b7b3873a` |
| Backend | `cuda_rc_exact_fused_extract` / `sm_120` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| Harness SHA-256 | `12d3c47773785d105d65c3ae23a33b899fc1db57001d8c7609abd08f060352d7` |
| Kept run | this directory (2026-08-27 CUDA corpus at the pool-close freeze) |
