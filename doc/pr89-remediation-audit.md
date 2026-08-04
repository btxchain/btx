# PR #89 integration audit and remediation plan

> **Historical release-state notice.** Release observations in the body below
> are preserved as of this audit's 2026-07-16 status date. The public
> `btxchain/btx` v0.33.2 tag and GitHub release were subsequently published from
> the earlier `H=185000` source tree with binaries, checksums, and snapshot
> assets. The later untagged corrective source disables Epoch A; publishing it
> requires an explicit public release/tag/version disposition.

Status date: 2026-07-16
Upstream PR: `btxchain/btx#89`
Audited upstream head: `c324361bedc801607a133269109b22901a121d93`
Target release line: BTX node `0.33.2`
Current integration-branch mainnet v4/BMX4-C posture: disabled (`INT32_MAX`)

## Executive verdict

**NO-GO for mainnet activation.** The MatMul v4/v4.2 body-verification code has
substantial tests and the CPU reference is internally consistent, but the
overall protocol is not safe to activate. The primary blocker is architectural:
v4 headers do not contain an authentic, header-verifiable proof of their claimed
chainwork. An unauthenticated header can be assigned full `nChainWork` before the
body sketch proves that any MatMul work occurred.

The staged `nBits`-relative header spam throttle in the latest PR is useful
experimental scaffolding, but it does not solve claimed-chainwork authenticity.
It is disabled, uses a nonce that is absent from wire serialization and block
identity, is not ground by miners, and substitutes far-cheaper SHA work for the
MatMul work credited from `nBits`.

There are also unresolved activation, hardware qualification, storage, presync
memory, testnet, CI, review, and adoption blockers. Code may be merged for
continued development because production-network activation is now disabled.
The withdrawn height `166,171` must not be restored or reused without completing
every gate.

## Severity and status legend

- **CRITICAL**: blocks safe activation or permits a network-wide liveness failure.
- **HIGH**: material security, mining, relay, resource, or qualification defect.
- **MEDIUM**: interoperability, configuration, observability, or hardening gap.
- **OPEN**: not fixed.
- **PARTIAL**: local mitigation exists, but required proof or testing is incomplete.
- **FIXED-LOCAL**: fixed on this integration branch; still needs review and CI.
- **UPSTREAM-FIXED**: present in the audited PR head.

## What the latest PR delta added

The integration includes all thirteen commits after upstream head `57c10919`:

1. `b5a5c6e8` — enforcing BMX4-C mine-to-validate round-trip test.
2. `48356e2d` — BMX4-C service-RPC dispatch, tighter payload cap, and construction invariants.
3. `3b88848a` — disabled experimental fixed-target header spam gate.
4. `85c5d0f4` — explicit `ENC-S8` / `ENC-BMX4C` RPC profile advertisement.
5. `3df071e2` — upstream consolidated adversarial-audit document.
6. `dcad75bd` — v4/BMX4-C single-height support and fail-closed header-gate
   enablement invariant.
7. `56044aa2` — ASERT half-life-upgrade ordering checks now include v4 and
   BMX4-C rescale anchors.
8. `f65be2b2` — wave-3 adversarial-audit findings.
9. `d4f55287` — expose the consensus-relevant 64-bit nonce through
   `getblockheader`.
10. `0ea77969` — document the pre-existing v4 unit-test mining-helper gap.
11. `1733b44a` — bind the header throttle to `nBits`, correct ASERT anchor/
    collision handling, reserve the mandatory proof in block assembly, and pin
    the compile-time transcript tile invariant.
12. `1edd3c66` — harden CUDA/Metal backend qualification and allocation paths
    (CUDA remains compile-unverified on this host).
13. `c324361b` — external-audit remediation status map.

The local integration preserves stricter exact payload sizing and accelerated
BMX4-C service solving while adopting the upstream hyphenated RPC profile names.

## Critical blockers

### C1. Headers do not authenticate claimed MatMul work

Status: **OPEN — CRITICAL**

Relevant code:

- `CheckMatMulProofOfWork_Phase1` in `src/pow.cpp`
- `ContextualCheckBlockHeader` in `src/validation.cpp`
- `BlockManager::AddToBlockIndex` in `src/node/blockstorage.cpp`
- best-header, headers-sync, IBD, and peer-protection consumers of `nChainWork`

At v4 heights, Phase1 checks the shape, target, and the header-carried
`matmul_digest`. It cannot recompute the digest without the block's sketch body.
An attacker can set `matmul_digest = 0`, construct schedule-valid headers, and
receive full claimed chainwork credit before supplying a valid body.

Impact:

- forged best-header towers;
- IBD and block-download stalls;
- manipulation of peer protection/eviction decisions that trust chainwork;
- `MinimumChainWork` bypass in the header-first path;
- ASERT timestamp/difficulty steering on an unauthenticated branch;
- cheap repeated resource/liveness attacks even though full-body validation
  eventually rejects each forged block.

Required fix:

1. Define a compact proof that is verifiable from the header alone and whose
   verified work is quantitatively bound to the chainwork credited from `nBits`;
   **or** redesign header-first chain selection so unauthenticated MatMul work is
   never credited to best-header, IBD, download, or peer-protection decisions.
2. Specify block identity, serialization, replay, duplicate-header, reindex, and
   reorg semantics for the new proof.
3. Add adversarial tests for forged high-work towers, ASERT manipulation, best-
   header poisoning, missing/invalid bodies, duplicate headers, restart/reindex,
   deep reorgs, and recovery to the honest chain.
4. Obtain independent protocol/security review before assigning an activation height.

Acceptance criterion: no header can increase trusted chainwork beyond the work
that a node verifies using header-available data.

### C2. The staged header spam gate is not an activation fix

Status: **OPEN — CRITICAL**

Relevant code and design:

- `CheckMatMulHeaderSpamGate` in `src/pow.cpp`
- `nMatMulHeaderPoWDiscountBits` in `src/consensus/params.h`
- `doc/btx-matmul-v4.2-header-pow-gate.md`

Problems:

1. The throttle rides the v4 flag day but `nMatMulHeaderPoWDiscountBits` is
   disabled by default. The startup invariant correctly prevents enabling it
   while its nonce is absent from the wire.
2. `nNonce` is not serialized in `CBlockHeader::SERIALIZE_METHODS`, so an honest
   grinder nonce is lost in transit.
3. `nNonce` is not part of `GetHash()`/block identity. Different nonce values can
   represent the same block hash, making duplicate-header early returns, disk
   persistence, reindex, and full-block arrival order-sensitive unless the
   protocol is redesigned.
4. Mining does not yet grind this nonce after sealing a MatMul winner.
5. The discount has no measured spam-cost calibration.
6. Binding the throttle to `nBits` makes its cost proportional to claimed work,
   fixing the constant-cost defect, but SHA remains far cheaper than MatMul; it
   therefore still does not authenticate the chainwork credited by `GetBlockProof`.
7. Mainnet v4 is now correctly unset on this integration branch; the former
   unified `166,171` assignment has been withdrawn.

Local hardening now enforces an enabled gate in headers presync/redownload before
chainwork credit, as well as in normal contextual validation. That closes a
wiring omission but does not solve items 1–7.

Required disposition: keep this mechanism disabled and treat it only as a
possible auxiliary throttle after C1 is solved.

### C3. Mainnet activation must remain disabled until release readiness

Status: **OPEN — CRITICAL OPERATIONAL**

At the 2026-07-16 10:44 UTC planning snapshot, btxprice reported:

- chain tip `161,371`;
- then-candidate activation height `166,171` (now withdrawn);
- exactly `4,800` blocks remaining at the snapshot, five nominal days at
  90-second spacing;
- v0.33.1: `28/213` observed peers (`13.15%`);
- v0.32.12: `152/213` observed peers (`71.36%`);
- v0.33.2: no observed peers.

At this audit's 2026-07-16 snapshot there was no published v0.33.2 GitHub
release/tag. A flag-day fork on that schedule would have split the overwhelming
majority of the observed network even if the implementation were otherwise
safe. The later public release state is recorded in the historical notice
above.

Required fix:

1. Keep production v4 activation disabled while engineering continues. **Done
   locally; must remain pinned by tests.**
2. Publish reviewed release candidates and reproducible artifacts.
3. Run a sustained public testnet rehearsal.
4. Define measurable signaling/readiness criteria for nodes, miners, pools,
   explorers, wallets, exchanges, and infrastructure.
5. Choose a new height only after every activation gate is green and adoption is
   demonstrably sufficient.

### C4. The unified flag day combines unresolved v4 and BMX4-C risks

Status: **OPEN — CRITICAL OPERATIONAL/CONSENSUS**

The latest upstream code correctly permits `nMatMulBMX4CHeight ==
nMatMulV4Height`, routes the activation block directly to ENC-BMX4C, prevents
the v4 rescale branch from shadowing the BMX4-C rescale, and makes a conflicting
half-life-upgrade anchor fail closed. The integration branch now keeps both
mainnet heights disabled.

That consistency fix expands rather than closes the activation burden:

- the intermediate ENC-S8 phase is skipped, so every BMX4-C backend and
  encoding-profile blocker applies on the first v4 block;
- native M-t24 device qualification is incomplete on every vendor and has not
  passed on two independent hardware families;
- the complete v3→BMX4-C ASERT rescale remains the uncalibrated default 1/1;
- the header spam throttle necessarily remains disabled
  (`nMatMulHeaderPoWDiscountBits == UINT32_MAX`) because its nonce is not on the
  wire and miners do not grind it;
- there is no release, signaling, rollback, or public-testnet evidence for the
  combined transition.

Required fix: keep production activation disabled while all unified gates are
completed. Do not treat equality support or its unit tests as evidence that the
combined fork is ready.

## High-priority protocol and node issues

### H1. Headers-sync ASERT replay can consume unbounded per-peer memory

Status: **OPEN — HIGH**

Relevant code: `MatMulRequiredSyntheticFloor` and
`HeadersSyncState::AdvanceSyntheticIndexWindow` in `src/headerssync.cpp`.

The integration fixed a correctness bug where presync retained only the base and
retune anchors but omitted half-life, v4, and BMX4-C ASERT re-anchors. It now uses
the same selector as `MatMulAsert`, and regression tests cross all new anchors.

However, `CBlockIndex::GetAncestor()` assumes every `pprev` hop decreases height
by exactly one. The synthetic chain therefore cannot prune intermediate entries
while retaining an anchor. Once the active anchor is reached, the per-peer list
grows for the rest of that ASERT epoch.

A tested attempt to use sparse `pprev` links failed deterministically and was
reverted. The correct fix is not another pointer shortcut.

Required fix:

- add an ASERT calculation API that accepts an explicit retained anchor snapshot
  (`height`, `time`, `nBits`/target) instead of calling `GetAncestor()` through a
  fully materialized synthetic chain;
- cap both presync and redownload state per peer;
- test multi-million-header streams, anchor transitions, restarts, redownload,
  invalid schedules, and memory bounds.

### H2. Mandatory proof capacity was not reserved during template selection

Status: **FIXED-LOCAL, NEEDS BOUNDARY REVIEW — HIGH**

Original defect:

- `BlockAssembler` selected transactions while `matrix_c_data` was empty;
- the ~8 MiB v4 sketch was attached only after solving;
- a busy mempool could produce solved blocks above the 24 MB consensus cap;
- blocks between the 16 MB P2P message cap and 24 MB consensus cap could be
  consensus-valid but unrelayable.

Local fix:

- reserve the exact serialized v4 sketch size before package selection;
- count its exact weight contribution;
- cap v4 template serialization at
  `min(policy/consensus limit, MAX_PROTOCOL_MESSAGE_LENGTH)`;
- advertise relay limit and proof reservation in GBT;
- add a v4 template reservation/RPC regression test.

Still required:

- dense-mempool boundary tests at production `n=4096` immediately below/above
  the relay, serialized-size, and weight limits;
- solved-block serialization and actual P2P relay tests;
- external-pool tests that add transactions to GBT;
- a decision whether 16 MB is the intended long-term network limit or should be
  raised in a separately reviewed protocol change.

### H3. Advertised proof pruning is not implemented

Status: **OPEN — HIGH OPERATIONAL/RESOURCE**

`nMatMulProofPruneDepth = 10,000` is assigned in parameters but has no pruning
consumer. The design's rolling-storage claim is therefore incorrect for archival
nodes. At about 8 MiB per 90-second block, proof payloads add roughly 7.5 GiB/day
or 2.7 TiB/year unless whole-block pruning is enabled.

Required fix:

- either implement proof-only pruning with explicit reindex, reorg, serving,
  snapshot, assumeutxo, and archival semantics;
- or remove the dead parameter and publish honest archival storage requirements;
- add long-run disk-growth and prune/reindex tests.

### H4. Compact-block and relay handling for the proof needs end-to-end review

Status: **OPEN — HIGH**

The mandatory sketch is a large trailing block payload and is not naturally
covered by Bitcoin-style compact-block transaction reconstruction. Required work:

- specify how compact-block relay requests/serves the proof;
- ensure missing, truncated, mutated, or delayed proofs cannot poison a valid
  header/block identity;
- measure propagation at realistic peer counts and bandwidth;
- test blocksonly, pruning, compact-block fallback, reorg, and peer disconnect paths.

### H5. ASERT v3-to-v4 work-unit rescale is uncalibrated

Status: **OPEN — HIGH**

Production still uses `nMatMulV4AsertRescaleNum/Den = 1/1`. The v3 and v4 nonce
units are materially different. Although ASERT eventually self-corrects, a bad
initial anchor can cause severe transient block-time and difficulty disruption
at a hard fork.

Required fix:

- benchmark the actual v3/v4 marginal nonce rate on the hardware miners will use;
- derive a price-independent rescale from measured throughput;
- replay historical timestamp/difficulty distributions;
- rehearse the transition on public testnet and document tolerances.

## Hardware and backend blockers

### G1. CUDA accumulator qualification previously allowed a false PASS

Status: **FIXED-LOCAL, UNCOMPILED/UNTESTED ON CUDA — HIGH**

The original native MXFP4 probe expected `16,777,152 = 2^24 - 64`. That value
has only 18 significant binary bits, so a balanced reduction could produce it
exactly even with an accumulator narrower than t=24. The sequential-partial-sum
argument was not valid for cuBLASLt's unspecified reduction tree.

Local fix: the probe now replaces one `3×3` term with `1×2`, producing the odd
final value `16,777,145`. This is exactly representable with t=24 and
unrepresentable with every t<=23 regardless of reduction order.

Required evidence: compile with CUDA 12.8+ and run on supported Blackwell
hardware, a deliberately ineligible/narrow path, and multiple driver/toolkit
versions.

### G2. CUDA device selection and qualification scope were inconsistent

Status: **FIXED-LOCAL, UNCOMPILED/UNTESTED ON CUDA — HIGH**

Eligibility honored `BTX_MATMUL_CUDA_DEVICES`, while v4/v4.2 execution used the
thread's ambient/default CUDA device. Native qualification was cached once for
the process, allowing one GPU's result to authorize another GPU.

Local fix:

- both CUDA v4 entry points call `ProbeCudaRuntime()` and `cudaSetDevice()`
  before streams, allocations, handles, or work;
- MXFP4 qualification is cached per CUDA device index.

Required evidence: mixed-capability multi-GPU tests, invalid selection tests,
threaded calls, device reset, driver failure, and per-device report output.

### G3. Metal MPP tensor template mismatch blocked runtime compilation

Status: **FIXED-LOCAL; M5 EXECUTION STILL OPEN — HIGH**

The Metal4 kernels originally declared `device const char*` inputs. Changing only
the scalar type to `int8_t` was insufficient because MPP template matching still
saw `const int8_t` and reached its unsupported-type assertion. The local fix uses
MPP's required mutable `device int8_t*` tensor-view declarations with `int32_t`
output for both v4.1 and BMX4-C. An isolated macOS 26 SDK runtime compiler probe
confirmed the distinction: the const form fails and the corrected form compiles.

This proves source compatibility with the current SDK, not native correctness.
Required evidence: execute the tensor path on real M5-class hardware, compare
every result with the CPU reference, and prove that a skip or ALU fallback cannot
be reported as native tensor success.

### G4. Existing backend verification falsely claimed device high-magnitude coverage

Status: **FIXED-LOCAL FAIL-CLOSED; REAL TEST STILL OPEN — HIGH**

`verify-backend.sh` previously grepped for `high_magnitude` test names, but those
tests execute CPU reference helpers rather than the selected device entry point.
A backend could therefore receive a false hardware PASS. The first marker-based
revision then had three fail-closed reporting defects: its generic
`CONSENSUS|SPLIT` grep matched the unrelated `pq_consensus_tests` suite name,
skips from unselected backends made a selected-backend run inconclusive, and a
missing-marker `grep` exited early under `set -euo pipefail` before printing the
intended diagnosis.

Local fix: Boost's exit status is authoritative for a test failure, skip
detection is scoped to the selected backend, missing-marker extraction is safe
under `pipefail`, and the script refuses to certify a backend unless a future
device-executed test emits an explicit backend-and-device-specific
`DEVICE_HIGH_MAGNITUDE_PASS:<backend>:<device-id>` marker. On this Apple host the
Metal suite passes but the verifier correctly returns FAIL because no such
device marker exists; it no longer misreports a digest divergence.

Required fix: implement those device tests for CUDA, Metal, and HIP using exact
vectors spanning the required accumulator regimes and make the marker impossible
to emit on skip/fallback/CPU execution.

### G5. Native BMX4-C hardware qualification is incomplete on every vendor

Status: **OPEN — HIGH**

- `matmul-v4-report` correctly reports non-CPU BMX4-C native M-t24 as unqualified.
- HIP's native MXFP4 path remains a false-return scaffold.
- CUDA native behavior is not tested on available hardware in this audit.
- M5 Metal tensor behavior is not tested on available hardware.
- HIP MFMA lane mapping and the complete BMX pipeline lack real-device evidence.

Activation requires bit-exact, device-executed results on at least two target
vendor families, with exact device/driver/toolchain identifiers and reproducible
logs.

### G6. CUDA working-set allocation is rigid

Status: **OPEN — MEDIUM/HIGH**

The CUDA backend preallocates a fixed maximum batched window (Q=32). At production
dimensions this can require several gigabytes. Allocation failure discards the
device window and falls back to CPU rather than retrying a smaller chunk.

Required fix: adaptive chunk sizing, overflow-safe memory estimates, retry on
allocation pressure, telemetry, and tests under constrained VRAM/concurrent load.

## Configuration and interoperability issues

### I1. Configurable v4 tile size was not actually configurable

Status: **FIXED-LOCAL FOR CURRENT PROFILE — MEDIUM/HIGH**

The parameter allowed a value such as future `n=8192,b=8`, while miner and
verifier compiled `kTileB=4`. Payload sizing and proof computation would disagree,
causing a reject-all activation.

Local fix: construction now asserts that the consensus parameter equals the
compiled tile until the implementation is genuinely parameterized.

Follow-up: documentation that proposes `b=8` at `n=8192` must be treated as a
future hard-fork design, not a currently supported parameter change.

### I2. Mining RPCs advertised legacy bounds and work semantics at v4

Status: **FIXED-LOCAL/PARTIAL — MEDIUM/HIGH**

Original defects:

- v4 could advertise `n=4096` with legacy `max_dimension=2048`;
- work profiles used legacy b/r values and reported the retired sigma lottery;
- fixed template reuse was hidden;
- GBT did not expose relay-safe proof reservation.

Local fixes:

- height-select v4 min/max bounds in challenge, service, GBT, and top-level fields;
- use v4 b/r values;
- label v3 versus v4 profile kind;
- report v4 sketch size and template/per-nonce tensor-MAC estimates;
- mark the v4 sigma lottery disabled and template-fixed work reusable;
- advertise encoding profile, proof reservation, and relay ceiling.

Still required: production-height JSON golden tests for every RPC/help schema and
external miner/pool conformance tests across v3 -> ENC-S8 -> ENC-BMX4C.

### I3. Encoding-profile domain separation remains a fork-time decision

Status: **OPEN — MEDIUM**

ENC-S8 and ENC-BMX4C are height-separated and derive different operands, but
some digest/domain-tag design is shared. Before BMX4-C activation, obtain an
independent cryptographic review of profile separation and decide whether a
profile-specific digest tag is required. Any change must update single-nonce,
batch, accelerator, RPC, and golden-vector paths in lockstep.

## Testing, CI, and review gaps

### T1. GitHub CI provides no code evidence

Status: **OPEN — HIGH PROCESS**

At the audited head, PR #89 is draft, merge state is `UNSTABLE`, and the current
BTX Readiness CI run fails before executing steps; the matrix is skipped. There
are no submitted GitHub reviews.

Required fix:

- repair runner/workflow startup;
- require Linux/macOS/Windows CPU builds and tests;
- add sanitizer, fuzz, serialization, functional activation, and upgrade tests;
- add real CUDA/HIP/Metal hardware jobs or signed reproducible qualification runs;
- require independent reviewer approvals for consensus, P2P, mining, and GPU code.

### T2. Required adversarial test matrix

Status: **OPEN/PARTIAL**

Before activation, add and pass:

1. forged-header towers with zero/random digests and hard claimed `nBits`;
2. best-header/IBD/download/peer-protection recovery tests;
3. duplicate header, mutated non-identity fields, restart, reindex, and disk replay;
4. multi-million-header presync/redownload memory-bound tests;
5. ASERT base/retune/half-life/v4/BMX4-C collision and reorg tests;
6. production `n=4096` dense-mempool proof-capacity boundary tests;
7. actual P2P full-block and compact-block relay at size boundaries;
8. proof pruning, archival, prune/reindex, snapshot, and deep-reorg tests;
9. external GBT/pool miner conformance across both profile forks;
10. CUDA/HIP/Metal exactness, fallback, device selection, OOM, and mixed-device tests;
11. long public testnet burn-in with realistic propagation and storage telemetry;
12. release-upgrade and rollback/recovery rehearsals.

### T3. Current positive evidence

The exact local integration has passed:

- CPU builds of `test_btx`, `btxd`, and `matmul-v4-report`;
- full CPU `ctest` on the prior PR head (268/268);
- the complete `pow_tests` suite on the prior PR head;
- focused v4/BMX4-C/mining/DGW/service suites;
- strict v4 and BMX4-C functional activation tests;
- Metal ALU-path bit-exact execution on Apple M4 Max;
- latest targeted tests for headers sync, parameters, mining RPCs, BMX4-C
  service flow, header spam gate, and template proof reservation.

This evidence supports continued development. It does not override any open
critical/high activation gate or substitute for unavailable target hardware.

## Activation checklist

All items below are mandatory:

- [ ] C1 authenticated header chainwork solved and independently reviewed.
- [ ] Production v4 activation disabled until the complete checklist is green.
- [ ] Headers presync/redownload memory strictly bounded.
- [ ] Production proof/template/P2P/compact-block capacity tested at boundaries.
- [ ] Proof storage/pruning semantics implemented or honest archival requirements published.
- [ ] v3->v4 ASERT rescale calibrated from real miner hardware.
- [ ] CUDA qualification passes on selected devices with per-device evidence.
- [ ] HIP qualification passes on supported AMD hardware.
- [ ] Metal tensor qualification passes on real M5-class hardware.
- [ ] Device-executed high-magnitude/M-t24 vectors pass on at least two vendors.
- [ ] RPC/GBT/pool interoperability tests pass across all profile transitions.
- [ ] Public testnet burn-in meets documented block-time, relay, CPU, RAM, and disk targets.
- [ ] Independent consensus, P2P, mining, and backend reviews are complete.
- [ ] CI is green and actually executes the required matrix.
- [ ] v0.33.2 release candidates are published and reproducible.
- [ ] Ecosystem signaling demonstrates a safe supermajority.
- [ ] A new activation height is selected with adequate safety margin.
- [ ] Rollback/recovery communications and procedures are rehearsed.

## Recommended sequencing

1. **Immediately disable the production activation height.** Keep v4/BMX4-C and
   header-gate code inert on production networks.
2. **Solve C1 first.** Do not spend activation effort on performance tuning while
   claimed header chainwork remains unauthenticated.
3. **Bound headers-sync memory and finish relay/storage semantics.** These are node
   safety prerequisites independent of GPU performance.
4. **Complete mining/RPC capacity and conformance tests.** Ensure internal and
   external miners cannot create invalid or unrelayable solved blocks.
5. **Complete real-device backend qualification.** Treat fallback as safety, not
   evidence that a native path is activation-ready.
6. **Calibrate ASERT and run public testnet burn-in.** Freeze consensus parameters
   only after measurements.
7. **Obtain independent review, green CI, release candidates, and adoption data.**
8. **Choose a new height last.** Never use a preselected date to waive a gate.

## Merge recommendation

**Do not merge this branch as an activation-capable production release.** It is
reasonable to merge the work for continued review only if production activation
is disabled and release notes clearly label MatMul v4/v4.2 and the header gate as
experimental. No hardware report, local test pass, or fixed spam throttle should
be interpreted as approval to activate until every checklist item is complete.
