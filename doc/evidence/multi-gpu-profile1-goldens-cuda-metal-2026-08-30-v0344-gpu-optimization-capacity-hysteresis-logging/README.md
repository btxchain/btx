# v0.34.4 GPU-optimization capacity/hysteresis logging CUDA+Metal Profile-1 goldens

Measured on the clean private-branch freeze `0270262d` after adding causal
pending-capacity wakeups for retained ExactReplay bodies and making shallow
reorg hysteresis warning/stat emission idempotent. No source change was made
between the freeze and either provider measurement.

CUDA (`sm_120`) and Metal (`m4_class`) both built and verified `btxd`,
`btx-cli`, and `matmul-v4-rc-harness` from the exact freeze. The strict
combined comparison reports `complete_multi_gpu_match=true`,
`allow_partial=false`, and `cuda_metal_match=true`, with zero mismatches and
zero coverage failures.

| | |
|---|---|
| Source revision | `0270262db202dd2d4edf47397d5bef352bec7e2e` |
| Fingerprint | `6dae2db3a8db866e518be9c01f19991d58aafe35c63057b07e4e6cbd75d653ed` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| CUDA harness SHA-256 | `d57094f64ac2fa98d9efb94a652c6d22dd8020b485e73f65d278ed8460a506fe` |
| CUDA artifact SHA-256 | `936b13938077af7214ed8a0bcc6e82558b986d4af08b0f1b709b9d1d48a0c0ee` |
| Metal harness SHA-256 | `301e0453493af87fce4fb122ce9230ec0b4af392b5c69364f0689d576a99075d` |
| Metal artifact SHA-256 | `e8c4b1a99e63216d13e60565430ffdc46d2040d0c307866a12c8a86b6d1b8b5f` |
| Episodes and nonces | 8 episodes, nonces 1 through 8 |
| Device execution | 1,088 calls and 1,129,198,441,725,952 MACs per backend |
| CPU execution | zero calls, MACs, and fallbacks on both backends |

Both platform release-binary gates passed. The evidence contains only
machine-class provider identity and public corpus data; it contains no
hostname, device SKU, local path, daemon configuration, datadir, or signing
key material.
