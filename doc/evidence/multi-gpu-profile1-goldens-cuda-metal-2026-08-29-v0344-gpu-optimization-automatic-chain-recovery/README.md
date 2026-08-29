# v0.34.4 GPU-optimization automatic-chain-recovery CUDA+Metal Profile-1 goldens

Measured on the clean private-branch freeze `98f9570d` after adding fully
automatic greater-work recovery for ExactReplay signers, automatic
post-reorg attestation reconciliation for non-signing mirrors, and bounded
body-request owner handoff without same-peer GETDATA churn. No source change
was made between the freeze and either provider measurement.

CUDA (`sm_120`) and Metal (`m4_class`) both built and verified `btxd`,
`btx-cli`, and `matmul-v4-rc-harness` from the exact freeze. The strict
combined comparison reports `complete_multi_gpu_match=true`,
`allow_partial=false`, and `cuda_metal_match=true`, with zero mismatches and
zero coverage failures.

| | |
|---|---|
| Source revision | `98f9570d317c10ccf2f61f341b111f470889f2e3` |
| Fingerprint | `a6a502c6ce0ff75537bd29dfc398f41613d935b3190c48486b406802bee4ddc1` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| CUDA harness SHA-256 | `9ea49936823a6cf64b76312d08ccec81ee63ce1169e2e0fcd438085a4a12c181` |
| CUDA artifact SHA-256 | `806044479b0f5b76767cb1549044a31dfb33c99e03fb46173eccc61bf9b52fad` |
| Metal harness SHA-256 | `49a78cc9fb7cd0b4ba208d8bbbb79102b5cb34658bdf80c7e85e382838189b85` |
| Metal artifact SHA-256 | `86d09c51ee0f564ffdc3ed58e639ba3b69087a6a189e730d2af5d04e08f5d4db` |
| Episodes and nonces | 8 episodes, nonces 1 through 8 |
| Device execution | 1,088 calls and 1,129,198,441,725,952 MACs per backend |
| CPU execution | zero calls, MACs, and fallbacks on both backends |

Both platform release-binary gates passed. The evidence contains only
machine-class provider identity and public corpus data; it contains no
hostname, device SKU, local path, daemon configuration, datadir, or signing
key material.
