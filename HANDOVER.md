# HANDOVER — changes required for 0.33.3

Scope: everything that had to be hot-patched or worked around operationally on
mainnet during the Epoch-A (MatMul v4.7) activation day, 2026-08-10, so that
0.33.3 runs stably with **no watchdogs, no manual peer surgery, and no restarts**.

Baseline: `v0.33.2`, tag commit `b4671ec28bb24e2fcbdd8252576119d54fd95238`.

Priority order below is the order these should be implemented. Items 1–3 are the
ones that actually cost the network hours of convergence.

---

## 1. Block download can stall forever — no per-block timeout  ★ CRITICAL

**Symptom.** A node holds headers far ahead of its tip and never advances. One
requested block never arrives; every block behind it is blocked. Observed on all
four of our nodes repeatedly, for 10–40 minutes at a time, and independently
reported by another operator ("cost us ~6 hours of network convergence").

**Root cause.** `src/net_processing.cpp`:

- `struct QueuedBlock` (~line 279) has **no timestamp**. There is no record of
  when an individual block was requested.
- The head-of-queue timeout keys off `CNodeState::m_downloading_since`, which is
  **peer-wide** and is only advanced when the *front* of the queue is received
  (`RemoveBlockRequest`, ~line 1693-1696).
- Therefore a peer that keeps delivering *later* blocks while one block never
  arrives holds the queue head indefinitely.

**Fix — already implemented and deployed, adopt as-is.**
Branch `hotfix/block-download-timeout` in the 0.33.2 source checkout
(`/home/administrator/v0332-src`), commit `1fb1bc29`:

1. Add `std::chrono::microseconds requested_at{0us};` to `QueuedBlock`.
2. Stamp it in `BlockRequested()` at insert time.
3. In the timeout check, time the head from `queuedBlock.requested_at` (falling
   back to `m_downloading_since` when unset) instead of the peer-wide clock.
4. On timeout, call `RemoveBlockRequest(hash, peer)` **before** `fDisconnect`, so
   the block is immediately re-requestable from another peer rather than staying
   owned by a peer being dropped.
5. Log the actual in-flight duration.

**Verified:** deployed to all three CPU mirrors; nyc1 went 185083 → 185162
(tip) immediately on restart. Compiles clean; no consensus/validation/wire change.

---

## 2. Download timeout is far too long, and scales the wrong way  ★ CRITICAL

Even with item 1, the timeout frequently does not fire in useful time.

```
src/net_processing.cpp
  BLOCK_DOWNLOAD_TIMEOUT_BASE     = 1
  BLOCK_DOWNLOAD_TIMEOUT_PER_PEER = 0.5
  BLOCK_DOWNLOAD_TIMEOUT_MIN      = 10s

download_timeout = max(spacing * (1 + 0.5 * peers_downloading_from), 10s)
```

With mainnet `nPowTargetSpacing = 90` and only 4 peers downloading, that is
**225 s**. With ~20 peers downloading it becomes **~15 minutes**, i.e. the more
peers you have the longer a dead peer can stall you — backwards.

**Required changes:**
- Add an absolute cap, e.g. `BLOCK_DOWNLOAD_TIMEOUT_MAX` of 2–3 × spacing
  (~3–5 min), independent of peer count.
- Consider counting only peers that have actually *delivered* a block recently,
  rather than every peer with something in flight.
- On timeout, prefer **re-requesting from a different peer** over disconnecting;
  disconnection is a blunt instrument that also discards the peer's other useful
  in-flight blocks.

---

## 3. Residual stall: node stops requesting entirely  ★ CRITICAL — NOT DIAGNOSED

Distinct from items 1–2 and **still unsolved**.

**Symptom.** A node sits with `blocks == headers` on its active chain, a
headers-only branch 40–80 blocks ahead in `getchaintips`, peers that advertise
those headers — and `vBlocksInFlight` empty or static, with no timeout possible
because nothing is in flight. Only a `btxd` restart clears it, after which the
node immediately connects tens of blocks.

**Evidence.** fra1 frozen at 185191 for >20 min with 115 peers and 24 in-flight
that never completed; then frozen at 185197 for >1 hour. Each restart jumped it
forward (185026→185035, 185083→185162, +26, +44, +79). Restart is currently the
only known remedy — we automate it (see "Operational workarounds" below), which
is not acceptable long term.

**Suspects to investigate:** block-download window/`MAX_BLOCKS_IN_TRANSIT_PER_PEER`
accounting not being released on some path; `mapBlocksInFlight` entries orphaned
so the block is considered "already requested" forever; peer selection refusing
all candidates for a branch it can't attribute.

**Repro:** put a trusted mirror ~50 blocks behind a single well-connected source
during a period of frequent short reorgs.

---

## 4. `getblockheader` fails for headers-only blocks  ★ HIGH

`getblockheader <hash>` returns `error -1: Block not available` for a block whose
**header we have** but whose data we do not. Upstream Bitcoin Core returns the
header. This makes the stall in items 1/3 undiagnosable from RPC and forced our
watchdog into blind peer rotation, because it is impossible to walk a
headers-only branch back to the first missing height.

**Fix:** return the header when the `CBlockIndex` exists, regardless of whether
block data is present. Only `getblock` should require data.

---

## 5. Linux miners silently default to CPU  ★ HIGH (adoption blocker)

`src/matmul/accelerated_solver.cpp` ~line 68:

```cpp
std::string DefaultBackendRequest() {
#if defined(__APPLE__)
    return "metal";
#else
    return "cpu";      // ← every Linux miner, including CUDA hosts
#endif
}
```

Any operator who upgrades on Linux and mines gets **CPU** solving even on a fully
qualified CUDA host. macpro2 (RTX 5060 Ti, sm_120) did exactly this until
`BTX_MATMUL_BACKEND=cuda` was set by hand — the log shows
`MatMul mining backend: cpu (requested=cpu, requested_backend_available)` while
the same host had previously auto-selected
`auto_selected_cuda:imma_s8s8s32_tensor_path:sm_120`.

This plausibly contributed to pools (`btxpool.org`, `ninjaraider.com/hk1`) not
returning after activation: they stop at exactly height 185000.

**Fix:** return `"auto"` on non-Apple. `ResolveBackend()` already falls back to
CPU safely and fails closed for devices without a bit-exact INT8 path, so this
cannot make an inadmissible device mine. Local mining policy only — no fork risk.

---

## 6. RC mining pipeline runs fully serial  ★ MEDIUM

`getmatmulchallengeprofile` on a mining node reports:

```
solve_pipeline: batch_size=1  async_prepare_enabled=false
                async_prepare_worker_threads=0  prefetch_depth=1
                prepared_inputs=0  batched_nonce_attempts=0
solve_runtime : attempts=331  solved=0  mean_elapsed=18.9s
```

Causes, both in `src/pow.cpp`:

- ~line 8035: `g_matmul_async_prepare_enabled.store(false, ...)` is
  **unconditional** on this path. `BTX_MATMUL_PIPELINE_ASYNC`,
  `BTX_MATMUL_PREPARE_WORKERS`, `BTX_MATMUL_PREPARE_PREFETCH_DEPTH` therefore
  have no effect — verified: setting all three changed nothing.
- ~line 8015: nonce-seed batching only applies when `gpu_nonce_seed_scan_enabled`,
  which requires `pre_hash_epsilon_bits > 0`. At Epoch-A heights it is 0, so
  `batch_size` collapses to 1 and `gpu_prehash_scan_attempts` stays 0.

Net effect: one full tensor episode per nonce, serial, GPU idle ~60–65% of the
time (measured 35% mean utilisation, 66 W of a 180 W limit, 4 of 24 cores).

**Ask:** decide whether Epoch-A is *intended* to have epsilon 0 (and therefore no
GPU prehash scan). If not, that is a live mining-throughput bug. Either way the
unconditional async-prepare disable should become configurable.

---

## 7. Mining is preempted by validation on a combined node  ★ MEDIUM

On a node that is both attestation authority and miner, `SolveMatMulV4RC` logs
`candidate accelerator wait cancelled at nonce=3..15` repeatedly: mining acquires
an `RCAcceleratorScheduler` lease at `Priority::CandidateMining` and is preempted
after a handful of nonces. Result: 331 attempts, **0 solved**, all "failed" via
aborted lease rather than exhausted search.

Prioritising validation over mining is correct. But the current behaviour makes a
combined node a *non-functional* miner while appearing to mine. Either document
that combined operation is unsupported, or give candidate mining a minimum lease
quantum so it can make measurable progress between validation bursts.

---

## 8. `coinstatsindex` crash-loops  ★ MEDIUM

```
index/coinstatsindex.cpp:233: CoinStatsIndex::CustomAppend(...):
Assertion `unclaimed_rewards <= arith_uint256(numeric_limits<CAmount>::max())' failed.
```

Disabled fleet-wide as a workaround. `txindex` and `blockfilterindex` unaffected.
Needs a real fix or the option should be rejected at startup with a clear message.

---

## 9. Optional: peer protocol-version gate for legacy nodes  ★ LOW

Non-upgraded nodes extend a legacy chain whose headers sealed nodes reject
(`Disconnecting peer for invalid claimed header work transition`). Consensus is
unaffected, but they consume peer slots and make reported peer heights
misleading for pool operators.

Implemented (working tree, **not deployed**) mirroring the existing
`MIN_SMILE_V2_PROTOCOL_VERSION` / `SMILE_V2_ENFORCEMENT_HEIGHT` precedent:

- `PROTOCOL_VERSION` 800001 → 800002
- `MIN_MATMUL_RC_PROTOCOL_VERSION`, `MATMUL_RC_ENFORCEMENT_HEIGHT`
- disconnect in `net_processing.cpp` version handling, after the SMILE gate
- `-minmatmulrcversion`, `-matmulrcenforcementheight` args

**Danger:** every node on the network today advertises 800001. If enforcement
height passes while we are the only node on 800002, we partition ourselves.
Ship with enforcement **defaulted off** (height `INT32_MAX`) and let operators
coordinate activation.

---

## Operational workarounds currently in production — all should become unnecessary

These exist only because of items 1–3. Remove them once fixed.

| Workaround | Where | Why |
|---|---|---|
| `btx-sync-watchdog.py` + 60 s systemd timer | all 4 nodes | restarts `btxd` after 5 stalled minutes (mirrors only) |
| `connect=114.150.94.235:19335` | 3 mirrors | pin mirrors to macpro2 as sole block source |
| `BTX_MATMUL_BACKEND=cuda` env | macpro2 `btxd.service.d` | item 5 |
| `coinstatsindex` disabled | all | item 8 |

**Important:** the watchdog must **not** disconnect peers. Doing so at 2 min
cancelled in-flight requests and reset the item-1 timer (which needs ~3.8 min),
so the workaround actively prevented the real fix from working. It is now
restart-only.

---

## Release/build notes for whoever cuts 0.33.3

- **The production canary enforces build provenance.** A binary built from a
  dirty or non-git tree reports
  `ready=0 reason=...:canary=build_provenance_mismatch` and the node loses
  strict-device authority. `BUILD_GIT_COMMIT` must have **no `-dirty` suffix`**.
  Package with `git bundle` / clean clone — a `tar --exclude='build-*'` silently
  deletes `src/minisketch/build-aux/*` and `src/libbitcoinpqc/wasm/build-wasm.sh`
  and marks the tree dirty.
- The golden manifest
  (`src/matmul/matmul_v4_rc_production_golden_manifest.data`) carries
  `source_revision` + `source_tree_fingerprint` and is excluded from its own
  fingerprint. Fingerprint =
  `sha256(git ls-tree -r --full-tree HEAD -- CMakeLists.txt cmake src contrib/matmul-v4)`
  minus the manifest line.
- **Keep the recorded ExactReplay digests unchanged** across a P2P-only release.
  A passing canary against unchanged digests is then positive proof the release
  did not perturb replay. This was done for the 0.33.2 hotfix and the canary
  passed on macpro2 (`outcome=passed`, sm_120).
- CUDA build flags: `-DBTX_ENABLE_CUDA_EXPERIMENTAL=ON -DBTX_CUDA_ARCHITECTURES=120`,
  `-DBoost_INCLUDE_DIR=/usr/include` on macpro2.

---

## Field report — Wizard Partners (David Jordan), 2026-08-10

Independent operator evidence (~35 sm_120 nodes + RTX PRO 6000 archive).
Full text: `doc/btx-postfork-field-report-wizard-partners-2026-08-10.txt`
(also `.docx` in `Documents/btx/uploads/`).

**Confirmed by their control experiment:** v0.33.2 + sm_120 validates the
canonical chain correctly via `submitblock` (~5 s/block). The systemic failure
mode is **P2P delivery of v4 block bodies** (headers race ahead; bodies lag),
which is exactly items 1–3 above.

**Additional findings incorporated into 0.33.3:**

| Finding | Action |
|---|---|
| Async ExactReplay of a non-active/canonical competing branch is preempted (`ExactReplay: cancelled`, outcome=3) → zombie freeze; `matmulrcexecution=strict-device` was the operator workaround | Map `MatMulVerifyWorker::CompetingBranch` → `RCAcceleratorScheduler::TipValidation` so competing-branch replay is not starved by CandidateMining (see `src/node/matmul_verify_worker.cpp`) |
| Legitimate sm_120 canary needs **CUDA 13.2 / cuBLASLt 13.4**; 13.0/13.1 → `episode_digest_mismatch_backend_vs_cpu` | Document in GPU operator runbook |
| Public archive contributing block data: `194.247.183.68:19335` (PRO 6000, unpruned, txindex, strict-device consensus) | List for operators; `addnode` from fleet |

**Their ask (answered operationally):** tip-holding miner / archive peer is
macpro2 at **`114.150.94.235:19335`** (`externalip`, `MATMUL_CONSENSUS` +
`MATMUL_ATTESTATION_ARCHIVE`). Their archive was already inbound there on
2026-08-11; outbound `addnode=114.150.94.235:19335` still helps if their
synced tip lags.

---

## Acceptance criteria for 0.33.3

1. A node 50+ blocks behind a single source converges to the tip **without any
   restart** and without operator action.
2. No `btx-sync-watchdog` timer needed on any node; removing it does not cause
   lag to grow.
3. A stuck block request is re-requested from another peer within ~3 minutes
   regardless of peer count, and this is visible in the log.
4. `getblockheader` returns headers for headers-only blocks.
5. A Linux CUDA host mines on GPU with no environment variables set.
6. Trusted mirrors (`matmulvalidation=trusted`) never probe or attempt
   ExactReplay — currently correct (`provider=not-probed`,
   `reason=non-strict-mode`); add a regression test so it stays that way.
7. Competing-branch ExactReplay is not permanently cancelled by mining
   preemption (no zombie freeze requiring `strict-device` as a workaround).
