# Multi-GPU Profile-1 ExactReplay golden compare

Status: **non-authorizing corpus-runner output**. Inspect
`multi-gpu-digest-compare.json` for the fail-closed comparison result. This
artifact does not change consensus parameters, ratification flags, or the
committed production manifest. The release gate closes only after CUDA and
Metal reproduce the exact final clean code freeze and the reviewed seal is
committed through `CommittedRCProductionGoldenManifest()`.

## Policy

Independent reproduction for Epoch-A production goldens is **cross-GPU-backend**
(CUDA and Metal) ExactReplay on identical frozen canary headers. HIP is an
optional provider whose submitted evidence must also match. Portable CPU
oracle reproduction is not required for this GPU-optimized chain.

## Artifact

This run used the clean corrective source freeze
`4abae57fd32578e42e706b9ad031e4d6ec95015d`, source-tree fingerprint
`edd804597ccfcc26d4438b571805291ea31959312dc62dad99df4a68c71e37cb`,
and harness SHA256
`abc49254b129e841154305e71b9a657283bbe35b3b74336e423971dece7e55d1`.
The harness embedded the same full source revision and reported a clean source
tree.

The Metal provider was `metal_int8_mpp_tensorops_fused_extract` on the public
`m4_class` architecture. Eight production-dimension Profile-1 episodes
(canary nonces 1 through 8) completed with:

- all 1,129,198,441,725,952 consensus MACs on the device;
- 1,088 device calls;
- zero CPU GEMM calls, MACs, or fallbacks; and
- a mean measured episode time of approximately 28.21 seconds.

All eight digests match the previously recorded frozen sequence. That fact is
not sufficient to authorize activation: this directory intentionally contains
only the Metal half of the required current-freeze cohort. The generated
comparison therefore reports `complete_multi_gpu_match=false` and
`authorizes_activation=false`. CUDA must independently reproduce the same
nonces from the exact source freeze, fingerprint, and clean embedded revision;
the reviewed combined comparison and manifest seal must then be committed by a
later evidence-only revision.

See `raw/profile1-metal-8.json` for the raw harness report and
`multi-gpu-digest-compare.json` for the fail-closed comparison result.
