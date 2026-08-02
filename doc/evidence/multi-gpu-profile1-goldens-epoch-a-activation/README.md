# Epoch-A activation cohort — goldens reproduced at the shipped commit

Status: **`complete_multi_gpu_match: true` at `6cfd2097`**, the commit that
carries the activation height, the installed ASERT rescale, both ratification
flags and the populated manifest. This is the evidence that matches the binary
a node will actually run.

## Provenance

- `source_revision` `6cfd20977ff52d7d0c632a0e41871438a9dfe664`
- `source_tree_fingerprint`
  `2fd64e549c82204023190d86c3efab2c9968dbe39278a69126f55f48d95b9287`

Both halves generated from clean checkouts at that commit, so the corpus
script's guards (revision resolution, fingerprint-matches-revision,
fingerprint-matches-HEAD, dirty-tree refusal) all passed.

## Result

Eight canonical 182-byte production canary headers, nonces 1–8,
`matmul_dim=4096`. All eight ExactReplay digests byte-identical across CUDA
(Blackwell-class `sm_120`) and Metal (M4-class Apple silicon), verified
independently of the comparator.

## Why this is stronger than the earlier seals

`CommittedRCProductionGoldenManifest()` records the freeze at which its goldens
were **measured** — `78a88af5` — and necessarily so: a manifest cannot cite the
commit that contains it. What matters is whether those recorded digests still
describe the shipped predicate.

They do, and this directory demonstrates it under harder conditions than the
manifest itself asserts. These corpora were produced by **freshly built harness
binaries at a different commit** (different `harness_sha256` on both providers
than the manifest records) and still reproduce the identical digests — including
the nonce-1 value the manifest pins,
`b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953`.

So the digests are stable across two accelerator vendors **and** across two
independent builds. The relay and consensus changes between `78a88af5` and
`6cfd2097` do not move the ExactReplay predicate, which is what the manifest
claims and what an auditor should be able to check.

## Standing constraint

This is valid for `6cfd2097`. Any later commit touching `src/`, `cmake/` or the
root `CMakeLists.txt` changes the fingerprint; regeneration costs roughly five
minutes per provider on warm build trees, and must be done on **both** against
the same commit.

## Artifacts

- `raw/profile1-cuda-8.json`, `raw/profile1-metal-8.json`
- `multi-gpu-digest-compare.json`

Machine-class and provider capability data only: no hostname, account name,
filesystem path, device serial, network address, or credential.
