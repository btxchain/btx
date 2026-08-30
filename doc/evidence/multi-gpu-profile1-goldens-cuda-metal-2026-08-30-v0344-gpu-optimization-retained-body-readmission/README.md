# v0.34.4 GPU-optimization retained-body-readmission CUDA+Metal Profile-1 goldens

Measured on the clean private-branch freeze `a16476cf` after fixing retained
greater-work recovery-root readmission. A retained header-only lost-twin path
can now receive a one-shot retry wake without discarding its existing retry
state, allowing the block body to be requested again after the prior owner or
capacity condition clears. No source change was made between the freeze and
either provider measurement.

CUDA (`sm_120`) and Metal (`m4_class`) both built and verified `btxd`,
`btx-cli`, and `matmul-v4-rc-harness` from the exact freeze. The strict
combined comparison reports `complete_multi_gpu_match=true`,
`allow_partial=false`, and `cuda_metal_match=true`, with zero mismatches and
zero coverage failures.

| | |
|---|---|
| Source revision | `a16476cf998edee001945abf75a4251198d8e575` |
| Fingerprint | `f7ed4385941cf987a943499fb12bb727adfd3fce86587935152622de39cc19d4` |
| Nonce-1 digest | `b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953` |
| CUDA harness SHA-256 | `5810e95ea2eff22af84d73c47deed88d4e5f90a129ae209d1be7199b99205181` |
| CUDA artifact SHA-256 | `851f9b2c29b1127b1b3193c2c6f9fe168e4f8086d1665035d5cf16c87d0341f0` |
| Metal harness SHA-256 | `a162a549dbae05ccaaf939e779c3c8a0f54a9611a591e70fd349edf36d925053` |
| Metal artifact SHA-256 | `d753551e3483508264ad9db5cb83441aaa347f0fd77fe13dfd23360f42014ce9` |
| Episodes and nonces | 8 episodes, nonces 1 through 8 |
| Device execution | 1,088 calls and 1,129,198,441,725,952 MACs per backend |
| CPU execution | zero calls, MACs, and fallbacks on both backends |

Both platform release-binary gates passed. A transient read error affected one
generated Metal build object; it was quarantined and regenerated successfully,
with no tracked/source change. The evidence contains provider architecture and
device-class identity plus public corpus data; it contains no hostname, local
path, daemon configuration, datadir, or signing key material.
