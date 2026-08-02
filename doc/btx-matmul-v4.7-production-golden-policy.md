# MatMul v4.7 production-golden assurance policy

Date: 2026-08-02

Status: project policy for the disabled Epoch-A implementation; not an
activation approval

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

## Activation boundary

This policy does not close hardware campaigns by itself. Activation remains
fail-closed until the exact final code freeze has matching CUDA and Metal
corpora, the provider-bound ASERT and complete lifecycle campaigns are reviewed,
and the separate activation commit installs the finite tuple and ratification
flags. Public heights remain disabled in this implementation branch.

