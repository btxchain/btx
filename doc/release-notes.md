BTX version 0.33.2 is being prepared for release from:

  <https://github.com/btxchain/btx/releases>

This release carries the disabled MatMul v4.7 Profile 1 ExactReplay
implementation, its resource-admission and GPU-lifecycle hardening, and an
explicit trusted-attestation topology for same-operator RPC/archive mirrors.
It does not set a public activation height, change the currently active
mainnet MatMul v3 rules, or represent activation approval.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

After an official v0.33.2 release is published, shut down the previous node
cleanly, wait for it to exit, and replace its `btxd`, `/path/to/btx-cli`, and related
binaries with signed final release artifacts. Back up wallets and
configuration before upgrading. Do not install unpublished candidate assets.

Upgrading to v0.33.2 alone does not activate MatMul v4.7. All public v4,
BMX4C, and Resident Curriculum activation heights remain disabled. A future
activation requires a separate narrow change after the documented hardware,
network, calibration, audit, ratification, and deployment gates close.
See `doc/btx-matmul-v4.7-transition-roadmap.md` for the canonical activation
contract and evidence requirements.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+. The currently active
MatMul v3 validation behavior is unchanged by this disabled implementation
release.

Production Profile 1 ExactReplay is designed for a qualified accelerator.
CPU ExactReplay remains an explicit pre-activation or diagnostic path, not an
automatic production fallback. The sanitized CUDA+Metal corpus and strict
startup-canary policy record the supported launch classes; each deployed
binary still self-qualifies its live provider and runtime before advertising
readiness.

# Notable Changes

## Disabled MatMul v4.7 Profile 1 implementation

- Epoch A uses the full deterministic Profile 1 episode as ExactReplay
  authority while retaining the fixed, digest-only block header.
- Newly introduced public-network consensus heights remain `INT32_MAX`, the
  ratification gates remain false, and unfinished proof machinery cannot
  become authority through this release.
- A future Epoch-A activation must set the v4, BMX4C, and Resident Curriculum
  heights as one reviewed tuple and install a measured one-time ASERT
  calibration. This release does neither.

## GPU execution and lifecycle hardening

- Production candidate mining and winner reseal require strict qualified
  device execution with complete accelerator coverage and zero CPU GEMM
  fallback.
- Strict validator mode distinguishes consensus-invalid work from local
  accelerator failure, an unconfirmed digest mismatch, and cancellation. A
  first mismatch never lets an untrusted header quarantine a healthy provider;
  bounded adjudication by a distinct, production-canary-authorized backend can
  confirm the non-header digest or identify and quarantine only the faulty
  provider. Qualification and independence cannot be asserted with labels.
  Without an independent provider, the block remains retryable and service
  continues for other work.
- One accelerator owner coordinates authenticated-tip validation, winner
  reseal, candidate mining, and speculative validation with explicit
  priorities, fixed global/per-lane queue limits, deadlines, workspace
  admission telemetry, cancellation, and owner-bound release accounting. All
  synchronous/internal ExactReplay callers enter the same owner.
- A strict, block-target winner reseal can be handed to local block acceptance
  through a bounded, expiring, exact-header-bound, single-use authority. It
  skips only the duplicate local replay; body, transaction, script, context,
  and chain-connection checks still run.
- Accelerator resolution, qualification, canary execution, and readiness
  service bits run after Unix daemonization. A pre-fork invariant rejects any
  early resolver/canary lifecycle regression.
- The automatic provider policy keeps experimental native MXFP4/Ozaki paths
  separate from production eligibility. The dense exact INT8 path remains the
  conservative default unless a provider has the required production
  qualification.
- Operator telemetry reports provider health, quarantine state, device/CPU
  coverage, queue waits, cancellation, and candidate/reseal/validation timing.
- A fail-closed startup/epoch canary mechanism binds production eligibility to
  provider family, public device architecture class, driver/runtime ABI,
  activation height, profile, transcript, consensus MatMul dimension, and
  episode parameters. Its reviewed manifest contains the independently matching
  CUDA and Metal launch cohort; any optional HIP entry remains fail-closed until
  it reproduces the same corpus.
- Exhaustive Stage-3 regression coverage now matches the current fail-closed
  construction: G4 remains open across the active-V8/V10-evidence domain
  mismatch, the aggregation screen remains below its hard 100-bit target, the
  eighth challenge-bearing family is inventoried, and coupled-bank capacity
  telemetry reflects the 575-column layout and raised backend cap. No
  Stage-3 proof or authority gate is enabled by these evidence corrections.

## ExactReplay admission and scheduling hardening

- Header-first and complete-block ExactReplay enter one shared per-peer,
  retained-source/netgroup, global, pending-work, and accelerator-queue budget
  model.
- `rcadmit` storage separates unknown tickets from known, validated tickets,
  prevents a planted invalid candidate from monopolizing a block hash, and
  retains bounded reconnect-resistant accounting.
- Enqueue rejection, cancellation, invalid completion, successful completion,
  and header/body handoff release reservations exactly once. A joined block
  body does not double-charge work already admitted by its header.
- Equal-priority authenticated-tip candidates receive bounded service rather
  than an uninterruptible claim on the only verifier.

## Trusted GPU archive and RPC-mirror topology

- A GPU archive validator may sign a domain-separated ExactReplay attestation
  only after completing authoritative local replay for the exact chain,
  height, block hash, MatMul version, and profile.
- A configured same-operator RPC/archive mirror may accept a one-of-one or
  M-of-N quorum of those attestations instead of running ExactReplay locally.
  It continues to validate headers, block bodies, transactions, scripts, and
  state transitions.
- Such a mirror is intentionally not an independently validating full node.
  Its trust boundary, service advertisement, signer separation, key handling,
  rate limits, retry behavior, and recovery procedures are explicit.
- Archive signers cannot run in trusted/economic/SPV mode, and mirrors cannot
  sign attestations or present ordinary non-replay success as local
  ExactReplay provenance.
- New RPC and P2P paths export, import, request, relay, and report bounded
  attestations. The recommended high-availability deployment uses a quorum;
  one-of-one is available for a deliberately trusted single-operator setup.

See `doc/btx-matmul-trusted-rpc-mirrors.md` and
`doc/btx-matmul-v4.7-gpu-operator-runbook.md` before enabling these roles.

## Benchmark and evidence integrity

- The full-benchmark wrapper now fails closed on harness failure, timeout,
  missing or malformed JSON, and incomplete result status.
- Production runs cannot silently resolve to the serial CPU backend without an
  explicit diagnostic opt-in.
- Repository 100-header Metal and sanitized CUDA measurements are included as
  engineering evidence. The current Metal rerun and the revision-bound CUDA
  corpus use the same frozen headers and produced byte-identical digests with
  full device coverage and zero CPU fallback. The public ratification switch
  remains deliberately coupled to the separate activation-height change.

## Cumulative wallet and notification support

- Browser-compatible `.btxwallet` recovery/import support from the v0.33 line
  remains available. Browser key custody and the public gateway remain
  separately deployed components; never expose node RPC credentials to a
  browser or the public internet.
- The codebase retains the v0.33 ZMQ notification support, including block,
  transaction, wallet-transaction, raw, and sequence publishers when built
  and enabled. Operators should bind notification endpoints deliberately and
  protect them according to their deployment policy.

# Activation Change That Remains

This implementation branch intentionally leaves public heights at `INT32_MAX`
and both ratification constants false. The remaining consensus change is to
choose the live-chain activation height with an adequate upgrade window and,
in one reviewed commit, flip the ratification constants and install the finite
atomic Epoch-A tuple.

# Known Limitations

- Bounded same-process alternate-provider adjudication is implemented, but the
  launch candidate registers no production alternate until per-device binding
  and exact production canary evidence exist. Production independence remains
  fail-closed until the resolver binds a capability to a distinct physical
  device; labels or callback wrappers cannot assert it. A sole provider
  therefore leaves a mismatching header retryable without taking the healthy
  provider offline.
- Provider-measured full-workspace telemetry remains unavailable through the
  generic backend ABI; RPC reports a zero sample count and never presents the
  conservative admission estimate as measured use.
- Latest lifecycle lane samples are explicitly uncorrelated.
  `operationally_ready` remains false until one future observation binds every
  lifecycle component to the same exact block/provider/epoch.
- Trusted RPC/archive mirrors inherit the safety of their configured signer
  set. They should not be described or exposed as independent consensus
  validators.
- Public activation remains disabled. A height must not be inferred from
  repository measurements, wall-clock estimates, or these release notes.

# Credits

Thanks to the contributors and reviewers of the MatMul v4.7 implementation,
GPU lifecycle and admission hardening, trusted-mirror design, wallet and ZMQ
integration, testing, documentation, and release engineering.
