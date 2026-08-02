# MatMul v4.7 code-readiness audit resolution

Date: 2026-07-31

Status: audited code paths and fail-closed controls are implemented; final
revision-bound accelerator evidence and calibration remain hardware-gated

Canonical transition and activation policy:
[`btx-matmul-v4.7-transition-roadmap.md`](btx-matmul-v4.7-transition-roadmap.md).

This note records the disposition of PR97-CODE-F01 through F05 and the related
Unix daemon CUDA lifecycle audit. It is not an activation approval. The
production canary and manifest mechanism is implemented, but the committed
manifest is intentionally EMPTY. The hardened comparator requires its entries
to come from one final-code-freeze CUDA+Metal corpus. Public ratification gates
remain false and public RC activation heights remain disabled.

## F01: accelerator initialization across Unix daemonization

`AppInitParameterInteraction` now performs configuration validation and selects
the RC execution policy without entering an accelerator resolver or canary.
Provider resolution, self-qualification, runtime identity, the production
canary, and readiness-dependent service advertisement run in `AppInitMain`
after daemonization and before networking snapshots the local service flags.

Immediately before `fork_daemon`, `btxd` checks that the RC resolver is still
unresolved and the canary is still `NotRun`. It aborts instead of inheriting
accelerator runtime state if this invariant is broken.

The opt-in Linux functional test
`feature_matmul_cuda_daemon_lifecycle.py` uses a real CUDA backend in foreground,
`-daemon`, and `-daemonwait` modes. It performs device work after startup and
rejects CUDA initialization or CPU-fallback markers. It is hardware-gated:

```text
BTX_RUN_CUDA_DAEMON_LIFECYCLE_TESTS=1 \
  build-cuda/test/functional/test_runner.py \
  --configfile=build-cuda/test/config.ini \
  feature_matmul_cuda_daemon_lifecycle.py
```

The final two-daemon production RC-boundary path is exercised with the reviewed
manifest and strict-device telemetry; daemon lifecycle coverage remains
hardware-gated in ordinary CI.

## F02: strict digest-mismatch adjudication

A first strict device/header digest disagreement is now
`UnconfirmedDigestMismatch`. It does not quarantine the provider, punish the
peer, cache a negative verdict, or prevent that provider from serving unrelated
headers.

A bounded process registry accepts only providers holding an opaque capability
issued by a successful production canary in the current daemon. The capability
binds the public runtime/device identity, the exact backend callback set, the
Profile 1 epoch, transcript, consensus MatMul dimension, and complete episode
parameters. Callers cannot assert qualification or independence with labels.
At most two alternates may adjudicate a header:

- two independent providers computing the same non-header digest establish
  `InvalidConsensus` without quarantining healthy devices;
- an independent provider reproducing the header quarantines only the provider
  proven faulty; and
- no independent provider, or inconsistent independent results, leaves the
  block retryable in an observable degraded state.

The launch candidate registers no production alternate automatically and
deliberately refuses to treat two production capabilities as independent until
the resolver can bind each canary to a distinct physical-device execution
identity. Different callbacks or labels alone are insufficient. Real
multi-device deployment still requires that resolver binding and an exact
production canary for each device. Restarting the same provider is not
independent adjudication.

## F03: mining-node duplicate ExactReplay

A successful strict, non-toy Profile 1 winner reseal may publish one local
authority record only when its digest satisfies the real block target and its
provider/backend/epoch holds the same current opaque production-canary
capability. The record is bounded, expiring, single-use, and binds the final
header hash, height, previous block, Merkle root, seeds, digest, version, time,
bits, nonce, MatMul dimension, and capability generation.

Local acceptance revalidates the capability against current canary/runtime and
epoch state before consuming the exact record to skip only the immediately
duplicated ExactReplay. It continues all ordinary block-body, transaction,
script, context, and connection validation. A share-only winner cannot publish
authority. A missing, expired, mismatched, evicted, or stale-capability record
falls back to the ordinary replay path.

## F04: production canary epoch identity

`RCProductionEpochIdentity`, exact manifest matching, and the deterministic
canary header now bind `nMatMulV4Dimension`. Zero or non-serializable dimensions
fail closed before manifest lookup or replay. RPC telemetry exposes the bound
dimension so a golden can be reviewed against the exact consensus tuple.

## F05: accelerator owner capacity and call coverage

The process-wide owner now enforces:

- one active owner;
- two waiters per lane and eight total waiters;
- a default 90-second queue deadline;
- exact owner-thread/token/priority release invariants;
- conservative workspace request/reservation estimates, declared capacity,
  provider-measured current use/high-water/sample counts, allocation-failure,
  timeout, and rejection telemetry; and
- retryable local failure on queue or capacity admission refusal.

Post-daemon CUDA and Metal probes publish a conservative usable capacity with
25% retained as driver/allocator/concurrent-work headroom. Strict production
readiness now additionally requires a nonzero capacity at least as large as the
canonical episode workspace estimate. Unknown or insufficient capacity is
reported and withholds validator service; it never changes consensus.

Candidate mining, winner reseal, worker validation, and direct synchronous
replay all submit the same nonzero canonical estimate. The scheduler's
request/reservation high-water values are estimates and are never relabeled as
actual device allocations. Actual current/high-water fields advance only when
a provider explicitly publishes a measured sample; the sample count remains
zero when that provider measurement is unavailable. The present generic
backend ABI does not yet publish that sample, so activation evidence must use
provider/harness measurements and the RPC fields remain explicitly unavailable
rather than relabeling the conservative estimate.

Synchronous validation, local submission, generation, reindex, and other direct
`VerifyBoundedExactReplay` callers enter the same owner. A verification-worker
thread that already owns a lease is detected and does not acquire twice.
Multi-device concurrent ownership is deliberately not enabled in Epoch A; any
registered alternate is serialized through this owner.

## Operator-visible state

`getmininginfo.backend_runtime` now reports:

- typed failure and independent adjudication results;
- primary, adjudicating, and quarantined providers plus attempt counts;
- bounded alternate-registry population;
- scheduler queue limits, timeouts, capacity rejections, workspace telemetry,
  and per-lane state;
- one-shot winner-reseal authority publication/consumption/expiry; and
- the canary's consensus MatMul dimension; and
- an explicit false `correlated_end_to_end_sample` until one exact block binds
  every lifecycle component.

No provider serial, PCI address, hostname, filesystem path, account identifier,
attestation private key, or private deployment information is published.

## Exhaustive Stage-3 regression cleanup

The exhaustive unit run also exposed older Stage-3 research tests and status
text that had not followed later fail-closed construction changes. The cleanup
does not enable Stage-3 authority:

- capability-audit validity now means that the measured composition was
  reconstructed canonically; an honestly open G4 Fiat-Shamir replay gate is
  reported as a gap instead of being mislabeled as noncanonical input;
- active V8 transcript ownership cannot consume V10-domain evidence, so G4,
  the self-similar fixed point, complete-verifier mirror, and authority remain
  false;
- the binary aggregation screen records its measured 98.62/98.30-bit floors
  below the unchanged hard 100-bit target;
- the intentional eighth challenge-bearing family
  (`EpisodeExtractChaCha`) is included in the phase inventory; and
- coupled-bank measurements reflect the raised backend column cap and current
  575-column narrow layout. The 70,974-column algebraic mirror fits the cap,
  but no parent proof is emitted or verified and all proof/resource,
  equivalence, semantic, and transcript readiness gates remain open.

These corrections make test evidence and operator diagnostics describe the
current construction without converting a witness, capacity fit, or research
proof into consensus authority.

## Activation boundary

Admission/scheduler controls, strict daemon lifecycle, trusted-mirror
attestation plumbing, and the fail-closed canary/comparator implementation are
implemented in code. A production strict-device trusted-mirror rehearsal is
deliberately unable to cross the RC boundary while the production-golden
manifest is empty: the archive withholds validator service and cannot produce
the required attestation. Historical CUDA+Metal artifacts remain useful but
must be regenerated from the corrected code freeze under the hardened
provenance checks. Public RC ASERT is neutral `1/1`; the final provider-bound
ratio and complete lifecycle evidence remain CUDA hardware work. HIP is
optional and must match before that provider becomes production eligible.
After those hardware gates close, the remaining consensus change is the
separately reviewed activation height plus same-commit ASERT and ratification
tuple.

Trusted GPU archive attestations remain a separate same-operator deployment
option for RPC/archive mirrors. Such mirrors continue ordinary validation but
do not independently perform ExactReplay and must not advertise themselves as
independent consensus validators.
