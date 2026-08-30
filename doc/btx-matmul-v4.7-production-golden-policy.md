# MatMul v4.7 production-golden assurance policy

Originally dated: 2026-08-02; updated: 2026-08-04

Status: project policy for Epoch-A production goldens. The candidate source
already contains a finite mainnet `H_A` and true ratification flags, which are
technically live if merged unchanged. The valid `df075c5184` CUDA+Metal seal
covers its exact PR-97-only freeze, not later build-relevant changes or the
combined v0.33.2 tree. The production manifest must therefore be resealed from
exact-final, revision-bound CUDA and Metal artifacts before this armed source
may be approved for merge or release.

## Decision

Epoch A records matching production-shape ExactReplay evidence from the
CUDA and Metal implementations this line measured. HIP remains optional
in that comparison corpus. Portable CPU ExactReplay remains the
backend-neutral diagnostic oracle and dispute tool; it is not counted
as an independently viable launch provider because it cannot meet the
production service bound.

**Mining admission does not require a manifest row.** A device that
passes the mandatory byte-exact `ExactGemmS8S8` CPU-versus-GPU
self-test is admissible even when the compiled manifest has no matching
reviewed row (`admission_path=self_qualification`). The manifest is a
comparison corpus, not a network blessing and not a permission list. A
digest **mismatch** against a unique known row is still fail-closed. A
device that fails self-qualification is not admissible. Floating-point-only
paths remain inadmissible. Every correct backend must still compute the
same deterministic predicate; blocks are ExactReplayed by every peer.

This decision concerns operational production-golden **comparison** only.
It does not make device identity, driver version, or provider choice part
of consensus.

## Assurance argument

CUDA and Metal use different accelerator APIs, kernel implementations, runtime
stacks, and hardware families. Their evidence is accepted only when all of the
following fail-closed checks pass:

1. identical canonical 182-byte headers, nonce range, consensus dimension, and
   byte-identical ExactReplay digests;
2. raw provider implementation names consistent with the declared backend;
3. complete public provider-family, architecture-class, driver, and runtime
   metadata;
4. strict-device execution, all consensus MACs on device, positive device work,
   and zero CPU calls, MACs, or fallbacks;
5. an exact code-freeze revision, a SHA-256 fingerprint of the build-relevant
   source tree, and the SHA-256 of each harness binary; and
6. a live startup canary that independently rechecks the deployed provider
   against a unique matching manifest row when one exists. Absence of a
   row is not a refusal; a digest mismatch against a known row is.

These controls replace self-asserted provider labels and stale cross-revision
artifacts. They do not claim that two GPUs prove the absence of a common
specification bug. They are not a blessing from this repository that other
hardware must obtain before mining. The portable implementation, intermediate
diagnostics, frozen headers, and offline replay remain available to
investigate divergence.

## Revision and evidence rule

The corpus `source_revision` is the reviewed code-freeze commit used to build
the harness. An evidence-only descendant may add sanitized artifacts and
documentation without rebuilding; it is equivalent only when the comparator's
build-relevant source-tree fingerprint remains identical. The fingerprint
scope is `CMakeLists.txt`, `cmake/`, `src/`, and `contrib/matmul-v4/`. The sole
exception is the inert manifest `.data` seal: fingerprinted CMake converts it
to a numeric byte array and fingerprinted C++ parses its strict schema. Any
other change in that scope invalidates equivalence and requires new CUDA and
Metal artifacts.

The final activation tuple, including the ASERT coefficient, must therefore be
settled before the exact-final freeze. Calibration may first run against a
candidate freeze to derive a proposed coefficient. Installing or changing that
coefficient creates a new build-relevant tree and invalidates the candidate
corpus. The required closure sequence is: candidate calibration, reviewed
tuple update, final freeze, then a confirmation CUDA+Metal/ASERT campaign on
that unchanged final freeze. Only sanitized evidence, documentation, and the
inert manifest seal may be added afterward. If the confirmation campaign
changes the proposed coefficient, repeat the freeze and all revision-bound
hardware evidence; never relabel an earlier corpus as final.

The in-process C++ parser strictly checks the manifest schema, field shapes,
and cohort consistency, but it has no repository in which to resolve a commit
or recompute a Git tree. A well-formed nonexistent revision could therefore
remain structurally valid while attesting to nothing. Two out-of-process
mechanisms are consequently mandatory, not advisory:

- `contrib/matmul-v4/multi-gpu-golden-corpus.sh` refuses to record a corpus when
  the build-relevant working tree is dirty, when the declared revision does not
  resolve to a commit, or when the declared fingerprint does not match the tree
  of the declared revision. There is no override; work in progress must be
  committed to a scratch branch first.
- `contrib/matmul-v4/verify-evidence-provenance.py` re-checks every artifact
  under `doc/evidence`. **It must pass on the CUDA and Metal corpora before
  `CommittedRCProductionGoldenManifest()` may be populated, and the run must be
  recorded in the activation review.** Historical artifacts that predate this
  rule and cannot be resolved are annotated in their own directory READMEs and
  are not admissible as production goldens.

The verifier runs with `--strict` in the production-readiness target. A
historical artifact with an unrecoverable revision may pass only through an
exact file-and-revision entry in
`contrib/matmul-v4/evidence-provenance-exclusions.json`. Every such entry must
carry a public reason and `production_admissible=false`; the verifier prints
each use and fails on stale exclusions. An exclusion can preserve historical
diagnostic material, but can never satisfy a production-golden gate.

## Activation boundary

This policy does not close hardware campaigns by itself. Matching historical
CUDA and Metal digests demonstrate useful cross-provider consistency, but the
activation gate remains open until the exact final revision reproduces the
corpus, the revision-bound ASERT calibration is independently reviewed, and
the activation review records the disposition of lifecycle soak, multi-peer
public testnet, fault/recovery, and released-binary upgrade evidence. The
current candidate has already installed the tuple and flipped both source
flags, so these requirements are release blockers rather than deferred runtime
conditions: if the source were merged unchanged, the tuple would activate at
its compiled height. Testnet and signet heights remain disabled.
