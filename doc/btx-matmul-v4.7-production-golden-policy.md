# MatMul v4.7 production-golden assurance policy

Date: 2026-08-02

Status: project policy for Epoch-A production goldens. The policy's
requirements were satisfied by the sealed one-freeze CUDA+Metal cohort
(`doc/evidence/multi-gpu-profile1-goldens-cuda-metal-2026-08-03-sealed`),
which is committed as the production golden manifest for the mainnet
height-181'894 activation.

## Decision

Epoch A requires matching production-shape ExactReplay evidence from the CUDA
and Metal implementations. HIP remains optional, but any HIP provider must
reproduce the same corpus before it can be production-authorized. Portable CPU
ExactReplay remains the backend-neutral diagnostic oracle and dispute tool; it
is not counted as an independently viable launch provider because it cannot
meet the production service bound.

This decision concerns operational production-golden eligibility only. It does
not make device identity, driver version, or provider choice part of consensus.
Every correct backend must still compute the same deterministic predicate.

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
6. a live startup canary that independently rechecks the deployed provider and
   exact epoch tuple before readiness is advertised.

These controls replace self-asserted provider labels and stale cross-revision
artifacts. They do not claim that two GPUs prove the absence of a common
specification bug. The portable implementation, intermediate diagnostics,
frozen headers, and offline replay remain available to investigate divergence.

## Revision and evidence rule

The corpus `source_revision` is the reviewed code-freeze commit used to build
the harness. An evidence-only descendant may add sanitized artifacts and
documentation without rebuilding; it is equivalent only when the comparator's
build-relevant source-tree fingerprint remains identical. Any change under
`src/`, `cmake/`, or the root `CMakeLists.txt` invalidates that equivalence and
requires new CUDA and Metal artifacts.

The C++ comparator can only length-check these strings; it has no repository to
resolve them against. A 40-character hex string that names no commit therefore
satisfies every in-process check while attesting to nothing, and the first
final-freeze corpus recorded in this tree did exactly that. Two out-of-process
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

This policy does not close hardware campaigns by itself. Its fail-closed
preconditions were met for Epoch A: the exact final code freeze (`78a88af5`)
has matching CUDA and Metal corpora, the two-rig ASERT calibration and the
bounded lifecycle soak are committed under `doc/evidence/`, and the
activation commit installs the finite mainnet tuple (181'894) and both
ratification flags. The gates that were NOT met before activation (multi-day
soak, multi-peer public testnet, released-binary upgrade behavior) are
recorded as accepted residual risk at the flags in `src/consensus/params.h`.
Testnet and signet heights remain disabled.
