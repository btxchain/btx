# BTX MatMul v4.2 — Preliminary Release-Blocker Assessment → Current State

A preliminary release-blocker list was raised for review. Each item is mapped
below to the CURRENT branch HEAD, because most predate the segregated-proof
solver-evolution work (Stages 1/2a) and the round-1..3 remediation. Posture is
unchanged: the whole MatMul upgrade is **activation-disabled** on mainnet and
every public testnet (`nMatMulV4Height == nMatMulBMX4CHeight == INT32_MAX`;
`nMatMulBMX4CDHeight == INT32_MAX`), so nothing here is live — NO-GO stands.

## 1. Authenticated chainwork only fixes part of the forged-header vulnerability

**Status: PARTIALLY ADDRESSED — the security-*relaxing* decisions are fixed; the
enumerated networking follow-ups are defended-by-design and get a rigorous
adversarial pass in Stage 2c.**

The C1/P0-1 core (`843aabd`, `nAuthenticatedChainWork`) authenticates a v4+
block's work only once its body + MatMul proof verify (`BLOCK_VALID_TRANSACTIONS`,
checked in `ContextualCheckBlock` before `ReceivedBlockTransactions`), and wires
it into the two decisions where forged work would *relax* a security guarantee:
the assumevalid script-verification skip (`ConnectBlock`) and presync reporting.
The remaining networking paths the audit flags — peer selection, download
scheduling, anti-DoS work thresholds, direct fetch, peer eviction — operate on
HEADERS whose bodies do not yet exist, so they *must* use provisional
`nChainWork` (a node decides what to download from claimed work); they are
defended instead by (a) the header-PoW spam gate binding forged-header cost to
`nBits`, and (b) the fact that the active chain can never be forged onto —
`ActivateBestChain`/`FindMostWorkChain` only consider candidates with received,
verified bodies, so a body-less forged chain never becomes the tip. Whether any
of these paths nonetheless benefits from authenticated work (or needs explicit
documentation of its provisional-by-necessity safety) is the subject of the
Stage 2c adversarial review of the data-availability / header-forgery surface.
This remains a pre-activation item.

## 2. Staged BMX4D 32 MiB proof exceeds the 24 MB block transport allowance

**Status: RESOLVED.** Two independent guards:
- The segregated-proof design (Stages 2a/2b) carries the ~32 MiB sketch
  OUT-OF-BAND; the block commits only the 32-byte header `matmul_digest`, so the
  sketch never counts against `MAX_BLOCK_SERIALIZED_SIZE` (24 MB) — the ceiling
  breach is removed by construction (`validation.cpp` segregated branch;
  `primitives/block.h` empty-`matrix_c_data` wire invariant).
- A hard activation guard exists regardless: `AssertBMX4CConstructionInvariants`
  asserts `BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY || fPowNoRetargeting`, so
  configuring ENC-BMX4C-D non-`INT32_MAX` on any PUBLIC network (all set
  `fPowNoRetargeting=false`) aborts the node at startup until the relay lands.
  The narrow regtest/dev exemption (single-process, local store stands in for the
  relay) cannot loosen a public network.

## 3. Mining/pool template capacity + exact proof-payload reservation

**Status: RESOLVED.** `BlockAssembler` (`node/miner.cpp:996-1012`) reserves the
EXACT sketch size `words = 2·m·m` (m = `nMatMulV4Dimension / kTileB`; 8·m² bytes
= 8 MiB at production) at in-block v4 heights, so transaction selection cannot
build an oversized solved block; at segregated heights it reserves NOTHING (the
sketch is off-body). `getblocktemplate` builds its template through the same
`BlockAssembler`, so the pool path inherits the identical reservation and its
`block_capacity` reporting reflects it.

## 4. Solver submission must fail closed if an accelerated backend returns no proof payload

**Status: RESOLVED.** The dispatch layer never accepts a device result without
verification. `ComputeDigestDispatched` (v4.1, `matmul/accel_v4.cpp` — the solo
GPU mining path) has a HARD REQUIREMENT: it runs `matmul_v4::VerifySketch`
(regenerate operands, recompute digest from the payload, O(n²) Freivalds) and
accepts only iff the payload commits to the true product AND the device digest ==
`H(σ‖payload)`. An empty/missing device payload fails `VerifySketch` and the code
falls back to the byte-exact CPU reference `matmul_v4::ComputeDigest`, which
always produces a valid committed payload. The BMX4C batched path
(`ComputeDigestsBMX4CDispatched`) has the identical `VerifySketchBMX4C`-then-CPU-
fallback contract. A winner therefore can never be submitted without a valid
committed proof — the accelerator can only lose throughput, never correctness.

## 5. Runtime consensus-parameter checks, Windows portability, block-bearing message limits

**Status: ADDRESSED.**
- **Block-bearing message limits (P1-1):** `MAX_PROTOCOL_MESSAGE_LENGTH` restored
  to 16 MB for ordinary messages; a separate `MAX_BLOCK_MESSAGE_LENGTH` (24 MB)
  applies ONLY to `block`/`blocktxn` (`net.cpp` `readHeader`), with a
  `static_assert(MAX_BLOCK_SERIALIZED_SIZE <= MAX_BLOCK_MESSAGE_LENGTH)` and a
  unit test pinning the exact boundary.
- **Runtime consensus-parameter checks:** every network's
  `consensus.nMaxBlockSerializedSize <= MAX_BLOCK_SERIALIZED_SIZE` is asserted at
  chain-parameter construction; the immutable MatMul-ASERT schedule is validated
  fatally at construction for all 6 MatMul networks; the per-profile §0.3
  dimension/payload pin runs at construction.
- **Windows portability:** the new Stage-2a proof store uses only portable
  primitives (`<sync.h>` = Bitcoin's cross-platform mutex wrapper, `<map>`,
  `<vector>`, `<uint256.h>`); no POSIX/pthread/filesystem. A broader Windows-build
  sweep of the new code is folded into the Stage 2c review.

## 6. Native CUDA / HIP / Metal hardware not independently tested here

**Status: STANDING MEASUREMENT GATE (cannot be closed in this environment).**
No GPU toolchain exists in CI, so the device kernels are written bit-exact-by-
construction behind their toolchain guards and validated only against the CPU
reference. The recent v4.1 `Q=B·V` GEMM-dim determinism bug (`0d1d8a1`) was found
and verified byte-exact-green on real NVIDIA silicon by an external tester; that
is the model — on-hardware determinism PASS (the activation GO gate) and the
per-card ordering must both be confirmed on real B200/B300/5090/MI355/M5 before
any activation. Not closable here.

---

**Net:** blockers 2, 3, 4, and 5 are addressed on-branch; blocker 1's core is
fixed with a defined Stage-2c adversarial follow-up; blocker 6 is a standing
hardware gate. All activation remains disabled.

---

# Segregated-proof relay audit (post Stage 2a/2b) → status

A second audit reviewed the segregated-proof RELAY specifically and found it not
production-ready for ENC-BMX4C-D activation. D stays disabled on all public
networks (`nMatMulBMX4CDHeight == INT32_MAX`), so none of this is live; the PR
remains fail-closed until every item lands. Mapping:

1. **BIP324 / v2 transport cannot carry the ~32 MiB proof.** CRITICAL / NEW /
   OPEN. BIP324's packet-length field is 24-bit (~16 MiB max), but the D proof is
   ~32 MiB (8·m², m=2048), so a single `matmulproof` truncates and the v2 peer
   disconnects. Needs application-layer CHUNKING + bounded reassembly. Designed in
   `doc/btx-matmul-v4.2-relay-hardening-design.md`; implemented in Stage 2d. Until
   then the relay is v1-only / small-proof-only, so `RELAY_READY` must go back to
   FALSE (item 6).
2. **Proof storage process-local + unbounded.** Being fixed in Stage 2c
   (persistent on-disk store, `nMatMulProofPruneDepth` window, `-matmulproofarchive`,
   IBD fetch, byte limits). In progress.
3. **Pending-proof queue unbounded in bytes / never expires.** OPEN. The 64-entry
   `m_matmul_proofs_pending` bounds count but each entry holds a full CBlock with
   no byte budget or expiry → memory/availability exhaustion. Stage 2d adds a byte
   budget + per-entry expiry + eviction that releases the held block.
4. **getmatmulproof has no serving limits.** OPEN. A tiny request triggers a
   ~32 MiB response repeatedly (outbound amplification). Stage 2d adds per-peer +
   global serving rate limits and an outbound bandwidth budget.
5. **Functional test is not production-size.** OPEN. The relay test uses n=128
   (tiny proof); it never exercises v2 encrypted transport at the real 32 MiB size.
   A production-size (m=2048) encrypted-transport test is added after Stage 2d
   chunking lands.
6. **CI has not run — repository billing lock.** OPEN (needs admin). Confirmed:
   the "BTX Readiness CI" job fails in ~3 s with `runner_id=0` (no runner ever
   assigned) on every recent commit including HEAD — a repository/org GitHub
   Actions billing lock, NOT a test failure. A repo/org admin must resolve Actions
   billing; then CI must be re-run green on the exact release commit. Not fixable
   from the agent side.

**Fail-closed posture (item 6 of the relay audit).** Because item 1 means the
relay is not production-ready, `BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY` returns
to FALSE in Stage 2d, and the regtest activation exemption in
`AssertBMX4CConstructionInvariants` is re-keyed from `fPowNoRetargeting` (which
`-test=matmuldgw` clears) to the chain being regtest, so regtest tests still run
while every PUBLIC network hard-aborts on any D activation. D remains INT32_MAX
everywhere regardless.
