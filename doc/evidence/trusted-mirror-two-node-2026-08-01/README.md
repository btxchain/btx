# Historical toy two-node trusted-mirror rehearsal

This artifact is toy-dimension functional coverage only. It is not a
production-shape strict-device closure result, does not carry the current
source/binary provenance schema, and must not be used to close activation or
release evidence gates.

GPU ExactReplay archive (CUDA consensus + attestation signer/serve) paired with a
CPU-only `-matmulvalidation=trusted` mirror.

## Result

- Archive services include `MATMUL_CONSENSUS` + `MATMUL_ATTESTATION_ARCHIVE`
- Mirror services include `MATMUL_TRUSTED_MIRROR` (no `MATMUL_CONSENSUS`)
- Mirror followed archive tip through toy Profile‑1 activation
- `getmatmultrustedstatus`: `accepted=3`, `blocks_with_quorum=3`, `wait_timeouts=0`
- Runner: `contrib/matmul-v4/two-node-trusted-mirror-rehearsal.py`

Machine-class evidence only.
