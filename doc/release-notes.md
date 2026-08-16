BTX version 0.33.2 is released from:

  <https://github.com/btxchain/btx/releases>

This release carries the MatMul v4.7 Profile 1 ExactReplay
implementation, its resource-admission and GPU-lifecycle hardening, and an
explicit trusted-attestation topology for same-operator RPC/archive mirrors.
The reviewed Epoch-A tuple activates v4, BMX4C, and Resident Curriculum
together at height 185000 with the conservative ASERT policy coefficient
6931159304/1. Exact-final CUDA+Metal evidence, strict provenance, and the
live-tip runway check passed for the sealed release tree.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

To upgrade, shut down the previous node cleanly, wait for it to exit, and
replace its `btxd`, `btx-cli`, and related binaries with signed v0.33.2
artifacts. Back up wallets and configuration before upgrading.

The v0.33.2 source freeze sets the v4, BMX4C, and Resident Curriculum heights
to 185000, installs the reviewed RC ASERT policy coefficient, and sets both
ratification constants in the same tuple. This is a live consensus instruction,
not an inert placeholder. The sealed build-relevant fingerprint is
`26d8be9eff7307928f70a7c13d88ba57cef222a6f77dfcfa3c12d14c618dcd10`;
changing the height, coefficient, gate flags, or fingerprinted source requires
a new CUDA+Metal corpus and startup-canary manifest. Testnet and signet heights
remain disabled. See `doc/btx-matmul-v4.7-transition-roadmap.md` for the
activation contract.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+. Mainnet remains on
MatMul v3 below height 185000; Epoch-A Profile 1 ExactReplay applies at and
above height 185000.

Production Profile 1 ExactReplay is designed for a qualified accelerator.
CPU ExactReplay remains an explicit pre-activation or diagnostic path, not an
automatic production fallback. The sanitized CUDA+Metal corpus and strict
startup-canary policy record the supported launch classes; each deployed
binary still self-qualifies its live provider and runtime before advertising
readiness.

The release assets include a mainnet AssumeUTXO snapshot at height 190507
(file version 9), after Epoch A / Profile-1 activation. Verify the published
checksums, then load `snapshot.dat` with
`btx-cli -rpcclienttimeout=0 loadtxoutset /path/to/snapshot.dat` to reduce
foreground catch-up to the remaining blocks after that height. Strict
consensus nodes must use this `loadtxoutset` pin rather than attested
snapshots. The node keeps validating the historical chain in the background.
The previous 190467, 189307, and 179000 pins remain in `m_assumeutxo_data`
for older binaries.

# Notable Changes

## Bitcoin Core and Knots catch-up

- Audits the complete Core-divergent and post-fork Knots commit sets, plus all
  open Core and Knots pull requests at the integration cutoff. Compatible
  correctness, storage, wallet, networking, privacy, platform, and performance
  fixes are adapted to BTX rather than blindly cherry-picked across the
  snapshot boundary.
- Hardens AssumeUTXO candidate handling, index and chainstate durability, BDB
  wallet recovery/migration, proxy and I2P credential logging, wallet secret
  memory, compact-block parsing, block-file I/O, and shutdown behavior.
- Fixes CoinStats lifetime-volume overflow, UTXO cursor/tip races, failed-cache
  accounting, invalid-descendant persistence, wildcard-bind discovery, local
  address score overflow, exact ban expiry, RPC credential parsing, and bounded
  integer option handling.
- Preserves BTX consensus, MatMul/Freivalds headers, shielded state, PQ wallet,
  and financial-only/P2MR policy. Bitcoin-only deployment assumptions and
  incompatible descriptor policies remain deliberately excluded.
- The source boundary, included work, measured results, and explicit deferrals
  are recorded in `doc/upstream-backport-audit-0.33.2.md`.

## Parallel block-input prevout fetching

- Block connection can prefetch UTXO prevouts concurrently from the chainstate
  database while preserving ordered validation and the consensus result.
- Two workers are used by default, capped at 16. Operators can use
  `-prevoutfetchthreads=<n>` to tune the pool or set it to `0` for serial
  lookups.
- A persisted-UTXO benchmark measured a 1.32x connect-time speedup with two
  workers on scattered prevouts. Higher worker counts can regress contiguous
  reads, so the setting remains bounded and tunable.

## CoinStats index rebuild

- The corrected CoinStats index uses 256-bit lifetime-volume counters and is
  rebuilt in `indexes/coinstatsindex`. The former `indexes/coinstats` directory
  is left untouched for downgrade safety. The first indexed startup therefore
  needs time and temporary disk headroom while both trees are present.

## Financial-only content-elimination fork

- Integrates the accepted work from PR #88. The production activation tuple is
  set only by the final reviewed 0.33.2 freeze; regtest retains explicit
  rehearsal overrides.
- At and above the fork, non-coinbase OP_RETURN outputs are invalid, coinbase
  OP_RETURN is restricted to the witness commitment, non-financial P2MR witness
  leaves are rejected, and coinbase scriptSig content is bounded.
- Relay defaults reject data-carrier and token-style transactions immediately;
  raw-transaction and PSBT RPCs no longer create `{"data": ...}` outputs.
- Existing historical data remains in the chain. The fork closes the covered
  explicit storage channels for newly mined transactions.

## Bonded OTC offers and transaction-bound HTLC claims

- Integrates the accepted work from PR #87. `contrib/otc/btx_otc.py` creates,
  verifies, and watches P2MR bonded offers and provides settlement/refund
  wrappers.
- Offer terms are committed through an unspendable `commit(<terms-hash>)` leaf
  inside the vault's P2MR root. Verification checks the strict vault shape,
  exact terms commitment, UTXO address, amount, confirmations, expiry, and
  optional seller attestation.
- Newly created atomic-swap claims use the transaction-bound `HTLC_TX` leaf,
  require exactly one claim and one refund path with no hidden extra leaves,
  and reject the legacy reusable CSFS-only claim shape at wallet/RPC boundaries.
  Existing funded legacy contracts remain governed by their committed scripts
  and should be claimed, refunded, or rolled forward operationally.

## MatMul v4.7 Profile 1 implementation and Epoch-A activation

- Epoch A uses the full deterministic Profile 1 episode as ExactReplay
  authority while retaining the fixed, digest-only block header.
- The intended mainnet change is atomic:
  `nMatMulV4Height = nMatMulBMX4CHeight = nMatMulRCHeight = H_A`, with both
  ratification constants true only after every required gate closes. Testnet
  and signet heights remain `INT32_MAX`. Unfinished Stage-3 proof machinery
  cannot become authority: Epoch A is ExactReplay-only.
- The one-time RC ASERT rescale and realized `k` must be derived from
  revision-bound raw CUDA+Metal measurements on the exact final implementation.
  The earlier two-rig corpus is retained as historical, non-authorizing
  evidence; its coefficient is not a release constant.

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
  episode parameters. Historical sealed CUDA+Metal cohorts remain under
  `doc/evidence/`, but build-relevant changes intentionally invalidate them;
  the committed manifest must be resealed from the exact final code freeze.
  Any optional HIP entry remains fail-closed until it reproduces that corpus.
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
  height, block hash, MatMul version, profile, and versioned replay-authority
  context. The V2 context binds the consensus schedule and derived replay
  predicate, so an attestation from a different authority context is rejected
  even when its chain, height, and block hash match.
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
- Repository Metal and sanitized CUDA measurements are retained as historical
  engineering evidence. The hardened comparator requires an exact code-freeze
  revision, source-tree fingerprint, harness-binary identity, and coherent raw
  provider metadata. The final CUDA+Metal nonce 1-8 cohort was generated from
  exact clean freeze `540ce328776e24dc4cf97592e239a125ab8b2c0f`, fingerprint
  `26d8be9eff7307928f70a7c13d88ba57cef222a6f77dfcfa3c12d14c618dcd10`.
  Both providers produced byte-identical headers and digests with zero CPU
  fallback; the evidence-only seal is the direct descendant of that freeze.
  Cross-revision equality remains non-evidence.

## Cumulative wallet and notification support

- Browser-compatible `.btxwallet` recovery/import support from the v0.33 line
  remains available. Browser key custody and the public gateway remain
  separately deployed components; never expose node RPC credentials to a
  browser or the public internet.
- The codebase retains the v0.33 ZMQ notification support, including block,
  transaction, wallet-transaction, raw, and sequence publishers when built
  and enabled. Operators should bind notification endpoints deliberately and
  protect them according to their deployment policy.
- The browser PQ module exposes ML-DSA-44 and SLH-DSA-SHAKE-128s
  keygen/sign/verify with caller-supplied entropy. Wallet-bundle import validates
  format, network, coin type, account, descriptors, and first receive address
  before installing key material.

# Activation State and Residual Risk

This release authorizes the reviewed Epoch-A tuple at height 185000. Historical
corpora under `doc/evidence/` remain diagnostic; only the exact-final sealed
CUDA+Metal cohort is production-authorizing. The installed 6931159304/1 ASERT
value is a reviewed conservative policy floor, not a claim that it is reproduced
by the retained schema-derived 4007014530/1 measurement.

The CUDA slot-reuse adversarial probe is not release evidence: on the launch
CUDA 13 host it did not distinguish the sealed build from either mutation.
Current production cohorts showed no CUDA/Metal divergence and the current
pageable-buffer path showed no generation/read overlap. Replacing that probe
is required before enabling pinned-buffer or device-Merkle optimizations.

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
- Some historical lifecycle lane samples are explicitly uncorrelated and
  remain diagnostic rather than release-authorizing evidence.
- Trusted RPC/archive mirrors inherit the safety of their configured signer
  set. They should not be described or exposed as independent consensus
  validators.
- Mainnet Epoch A activates at height 185000. The release decision explicitly
  accepts the documented operational residuals; it does not reinterpret
  historical diagnostic artifacts as exact-final evidence.
- Content elimination is structural, not absolute: monetary values, public
  keys, valid signatures, and permitted financial operands retain unavoidable
  steganographic capacity. The fork removes the covered cheap explicit storage
  channels; it cannot prove every remaining financial byte lacks an off-chain
  interpretation.
- The OTC tooling and its end-to-end post-fork lifecycle require independent
  review before use with meaningful value. Counterparties must verify the
  settlement transaction outputs rather than relying only on a declared CTV
  hash.
- `.btxwallet` exports contain plaintext PQ master-seed material. Keep them
  offline, delete temporary copies after import, and prefer encrypted native
  bundle archives for routine backups.

# Credits

Thanks to the contributors and reviewers of the MatMul v4.7 implementation,
GPU lifecycle and admission hardening, trusted-mirror design, upstream
backports, financial-only and bonded-OTC work, transaction-bound HTLCs, browser
wallet interoperability, ZMQ integration, testing, documentation, and release
engineering.
