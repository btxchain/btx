> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX PR #89 (v4.4 ENC-DR MatMul PoW) — External Review Triage vs. Actual Code
Repo: `btx` @ branch `claude/matmul-v4-design-spec-af23sj`, HEAD `e665b5a`. Read-only review; all evidence is `file:line`.
Classes: **REAL-HERE** (reproducible in this repo) / **PARTIAL** (real but largely mitigated) / **NO** (btx-node-synthesis-only) / **DESIGN** (doc/normative decision, not a code bug) / **ALREADY-FIXED**.

---

## 1. Triage Table

| Finding | Class | Evidence (file:line) | Already-addressed? | Severity |
|---|---|---|---|---|
| **C1** raw work drives P2P security decisions | **REAL-HERE** | Auth work read at only 3 sites: `src/validation.cpp:6888,10282,10649`. Raw `nChainWork`/`m_best_header` drive: direct-fetch `src/net_processing.cpp:1519,1542-1543,1558-1560,1582`; outbound-peer protection `:3632`; header/tip work compare `:3495,3527,3601,5842,5864`; anti-DoS work thresholds `:3448,5721,6370`; chain-sync eviction `:6876,6883`; IBD/download gating `:5370,7173`; best-header assignment `:7323-7324` | Partial: only the ENC-DR assumevalid recompute-trust gate uses authenticated work (`validation.cpp:10282`). P2P selection/eviction/fetch remain raw | **Critical** |
| **C2** header throttle un-enableable / IBD budget | **REAL-HERE (mitigated)** | Nonce not on wire: `src/primitives/block.h:38` (`BTX_HEADER_NONCE_ON_WIRE=false`), serialization omits `nNonce` `:63`; gate grinds `nNonce` `src/pow.cpp:3184-3186`. IBD per-peer 200000/min `src/pow.cpp:4055`; fast-phase 200000 `:4080`. Fail-closed coupling assert `src/kernel/chainparams.cpp:86` | Yes: defer-not-disconnect (`net_processing.cpp:3838-3844,5774-5779,6423-6430`), skip-known (`:3736-3741,6398`), 4/2 re-pricing (`kernel/chainparams.cpp:773-780`), coupling assert present. **Residual:** per-peer throttle neutralized in IBD (200000 cap); global 4/min only defers | **Critical** |
| **C3** producers don't offload+clear sketch | **REAL-HERE (confirmed)** | ENC-DR reject `src/validation.cpp:10252-10254`. Central offloader `OffloadMatMulV4SketchToCache` `src/pow.cpp:3795-3811`. **Missing at:** `src/test/util/mining.cpp:104-144` (attaches sketch @132, never offloads — breaks unit suite), `src/node/interfaces.cpp:1085-1112` (submitSolution keeps `matrix_c_data`). Present at `src/rpc/mining.cpp:4940-4944`. `src/node/miner.cpp:1010-1018` only reserves size (no solve → OK) | Partial: only `generate` offloads. No central `FinalizeMatMulSolvedBlock` exists | **Critical (merge blocker)** |
| **C4** 24MB block vs V2/BIP324 16MB packet cap | **REAL-HERE** | Ceiling `src/consensus/consensus.h:16,19` (24MB). V2 3-byte length `src/bip324.cpp:125-129`, `src/bip324.h:25` (`LENGTH_LEN=3`). Send: no guard, silent truncation `src/net.cpp:1678-1712` → `bip324.cpp:126-128`. Recv cap ~16MB `src/net.cpp:1349-1359`. V1 has 24MB block exception `src/net.cpp:797,801-818`; **V2/PQ has none** | No | **Critical** |
| **C5** recompute holds `g_msgproc_mutex` | **REAL-HERE** | Chain: `ProcessMessages` (`g_msgproc_mutex`) `src/net_processing.cpp:6781` → `ProcessBlock` `:4223` → `ContextualCheckBlock` → recompute `src/validation.cpp:10310`. `CsMainScopedRelease` releases only cs_main `src/validation.cpp:10186-10191`, used `:10304`; `g_msgproc_mutex` still held | Partial: cs_main released, msgproc NOT. Hook point + slot machinery ready (`net_processing.cpp:4220-4234`, `ReserveMatMulVerificationSlot`) | **Critical** |
| **C6/C7/H8** scalar labeled native MXF4; report PASS on CPU; dispatch≠registry | **REAL-HERE** | Scalar-decode kernel certified native-mxf4: `src/cuda/matmul_v4_bmx4_accel.cu:679-698,853-859,1376-1427,1424`. Report exits 0 CPU-only: `src/matmul-v4-report.cpp:1256,1018,684,940-946`. Runtime dispatch (`accel_v4.cpp:334`, uses v3 caps `:100-122`) ≠ evidence registry (`backend_capabilities_v4.cpp:210-243`, used only by report/tests). `verify-backend.sh:111` bmx4c passes on exit-code only | Mitigated for consensus only: per-result `VerifySketch`+CPU fallback `accel_v4.cpp:495-537,582-639` | **Critical (cert integrity)** |
| **C8** tensor work not consensus-enforceable | **DESIGN** | Digest-commit only; PoW object is `H(sigma‖Chat)` `src/validation.cpp:10239-10244` | N/A — inherent to digest-only design | Doc |
| **H1** one block charged 2× (not 3×) | **REAL-HERE (order bug)** | cmpctblock charges at `src/net_processing.cpp:5766` **before** discovering the ENC-DR payload is required and bailing to GETDATA at `:5814-5821`; full BLOCK then charges again `:6415`. No third/recompute-layer charge (validation has no `ConsumeMatMul*`; `pow.cpp:3771` is advisory-only) | skip-known (`already_have_block_data :6398`) only blocks re-holding a known block; the sequential cmpctblock+full-block double-charge on a *fresh* block remains | High |
| **H2** authenticated work sparse/stale | **REAL-HERE** | Set only on connect: `src/chain.cpp:176-177` (`pprev->auth + GetBlockAuthenticatedProof`); forged/headers-only stay flat: `src/test/matmul_chainwork_auth_tests.cpp:114,119-120`; `src/node/blockstorage.cpp:361` | Coupled to C1: the few auth-work reads are conservative, but staleness is why raw-work reads (C1) are exposed | High |
| **H3** assumevalid burial uses equiv-time + raw work | **PARTIAL** | Recompute-trust gate DOES use authenticated work `src/validation.cpp:10282` + time-DoS `GetBlockProofEquivalentTime :10283`. Raw usage remains in relay policy `BlockRequestAllowed` `src/net_processing.cpp:2422-2424` | Mostly addressed for the recompute-trust path; raw equiv-time only in lower-severity relay policy | High→Med |
| **H4** cache-Freivalds (ε≤2⁻¹⁸⁰) vs exact (ε=0) predicates | **DESIGN** | `src/matmul/pow_v4.h:34`, `src/matmul/matmul_v4.h:262` (R=3→2⁻¹⁸⁰). Normative statement already in `src/validation.cpp:10241-10244` (exact = consensus definition; Freivalds = fast path) | Documented; needs the normative predicate pinned to exact-equivalence (2⁻¹⁸⁰ false-accept is astronomically safe) | High (doc) |
| **H5** no process-wide single-flight for recompute | **REAL-HERE (partial)** | Concurrency **cap** exists (`m_matmul_pending_verifications`, `ReserveMatMulVerificationSlot` `net_processing.cpp:3822,6408`; `CanStartMatMulVerification` `pow.cpp:4118-4121`) but it is a count bound, **not** a per-block-hash dedup | A-1 dedups the block WRITE, not the recompute; two peers → duplicate recomputes of same hash | High |
| **H6** v4 SolveMatMul ignores share_target_override | **REAL-HERE** (corrected — NOT fixed) | v4 heights dispatch early to `SolveMatMulV4` `src/pow.cpp:5046-5048`, whose signature `:4864-4870` has **no** `share_target_override` param; `SolveMatMulV4BMX4C :4772-4780` likewise. Override honored ONLY on the legacy path `:5080-5083`. Existing test `pow_tests.cpp:2992` + release note cover legacy solvers only | No — v4 pool shares silently dropped (solver only returns full-block solutions at v4 heights) | High |
| **H7** digest-only mining materializes every losing 8MiB sketch | **REAL-HERE (ENC-S8 CPU path only)** | ENC-S8 CPU `BatchedSketchMiner` fills a full 8·m² `payload` per candidate incl. losers: `src/matmul/matmul_v4_batch.h:53-57,79-89`, `src/pow.cpp:4939-4948`. No `ComputeDigestOnly` API exists. **BMX4C already mitigated** (passes target, host-verifies only winners `pow.cpp:4814-4820`) | Partial — BMX4C path already does the two-phase pattern; ENC-S8 CPU batch does not | High (memory) |
| **H9/H10** sketch cache/relay/prefetch amplification & poisoning | **REAL-HERE (partial)** | Cache 8-entry, entry-count (`src/matmul/matmul_sketch_cache.h:91`); prefetch ≤16/peer overshoots (`net_processing.cpp:3560,7774`, `MAX_BLOCKS_IN_TRANSIT_PER_PEER=16 :104`); no assumevalid-depth guard in `MaybeRequestMatMulSketch :1895-1909`; MMSKETCH receive hashes ≤8MiB with no per-peer rate limit `:6249` | Yes for serve side: E.1 serve-limit `:6043-6177`, symmetry `:6230-6240`, self-auth reject `:6244,6250`. **Unfixed:** prefetch↔cache coupling, assumevalid prefetch, MMSKETCH ingress rate-limit | High |
| **H11** RPC/GBT schema inconsistencies | **REAL-HERE** | `block_capacity` omits `max_protocol_message_length`/`relay_serialized_limit` `src/rpc/mining.cpp:8515-8538`; getmatmulchallenge work_profile schema `:5959`; `RPC_DOC_CHECK` exists `CMakeLists.txt:358`, `src/rpc/util.h:47-48`. No central `ResolveMatMulWorkProfile` (only `BuildMatMulWorkProfile`) | No | High (merge blocker on debug builds) |
| **H12** k2b-gate G2 always-true + cherry-pick + trusts JSON | **REAL-HERE (confirmed)** | `contrib/matmul-v4/k2b-gate.py:301` (`... or True`); G2 also excluded from verdict `:304` (`go = G1 and g3 and g4 and g5`); fastest-per-class `:266-272`; trusts operator JSON `:83-103` (no attestation) | No | High (limited blast radius — offline tool, activation height stays INT32_MAX) |
| **5 btx-node API fixes** (metal ns, win_target×2, all-ones target, is_regtest) | **NO (btx-node-only)** | Namespace `matmul_v4::bmx4::metal` correct here `src/metal/matmul_v4_bmx4_accel_stub.cpp:7`; win_target threaded `src/matmul/accel_v4.cpp:541`, `src/pow.cpp:4819`; is_regtest threaded `src/kernel/chainparams.cpp:65,206`; report never calls the dispatcher (`matmul-v4-report.cpp`); batch test uses miner API w/o win_target | All 5 already internally consistent here | — (not applicable) |

---

## 2. Prioritized Implementation Plan (non-overlapping by file ownership)

**Hot-file warning.** `src/net_processing.cpp` and `src/validation.cpp` are touched by C1, C5, H1, H3, H9/H10. These CANNOT be edited by parallel agents on the same file. They are designated **serialized lanes** (single owner each, ordered internal edits). All other files are freely parallelizable.

### A. Release-main-merge blockers (compile/API, C3, RPC schema, gate tool, broad unit suite)

**WP-1 — C3 test-helper fix (unblocks the broad unit suite).**
- Owns: `src/test/util/mining.cpp` (+ `src/test/util/mining.h` if signature note needed).
- Change: in `MineHeaderForConsensus(CBlock&)` (:104-144), after attaching `matrix_c_data` (:132), when the height is `IsMatMulV4Active && commitment==DIGEST_RECOMPUTE`, call `OffloadMatMulV4SketchToCache(block)` (already declared `pow.h:289`) to offload+clear; retain the inline sketch only under `FLAT_SKETCH_INBLOCK`. No dependency on WP-2 (uses existing offloader).
- Test: `validation_block_tests`, `mempool_locks_reorg` go green; add an assert that the mined ENC-DR block body is empty. Also re-run `setup_common.cpp:413`, `miner_tests`, `peerman_tests`, `blockencodings_tests`, `blockfilter_index_tests`, `headers_sync_chainwork_tests`, fuzz `p2p_headers_presync` (all call this helper).

**WP-2 — C3 central function + submitSolution.**
- Owns: `src/pow.cpp`, `src/pow.h`, `src/node/interfaces.cpp`.
- Change: add `bool FinalizeMatMulSolvedBlock(CBlock&, const Consensus::Params&, int height)` in `pow.cpp` wrapping the `IsMatMulV4Active && DIGEST_RECOMPUTE → OffloadMatMulV4SketchToCache` guard (the exact logic at `rpc/mining.cpp:4940-4944`). Call it in `submitSolution` (`interfaces.cpp:1085-1112`) so IPC-submitted ENC-DR blocks serialize digest-only.
- Note: do NOT touch `rpc/mining.cpp` here (owned by WP-3); its existing offload keeps working. Adopting the central fn there is optional cleanup for WP-3.
- Test: new unit test — submitSolution at ENC-DR height yields empty body + populated sketch cache.

**WP-3 — H11 RPC/GBT schema + central resolver.**
- Owns: `src/rpc/mining.cpp` (exclusive).
- Change: add `block_capacity.max_protocol_message_length` and `block_capacity.relay_serialized_limit` (:8515-8538) and declare them in the result schema (:7901+). Reconcile getmatmulchallenge `matmul.encoding_profile` + `work_profile.{b,n,profile_kind,r}` (result schema :5959) against what `BuildMatMulWorkProfile` emits. Introduce `ResolveMatMulWorkProfile(height)` as the single source consumed by getblocktemplate/getmatmulchallenge/getmatmulchallengeprofile (refactor `BuildMatMulWorkProfile`). Optionally adopt `FinalizeMatMulSolvedBlock` at :4943.
- Test: build with `-DRPC_DOC_CHECK`; `getblocktemplate`/`getmatmulchallenge` help must pass the doc check.

**WP-4 — H12 gate tool + C6 verify script.**
- Owns: `contrib/matmul-v4/k2b-gate.py`, `contrib/matmul-v4/verify-backend.sh`.
- Change: k2b-gate — delete `or True` (:301); include `G2_profile` in the `go` conjunction (:304); replace fastest-per-class (`class_best` max, :266-272) with worst-case or all-samples ordering so a slow datacenter sample isn't masked; add a loud "operator-supplied, unattested" banner for the trusted JSON fields (:83-103). verify-backend.sh — require the device marker in bmx4c mode too (mirror v41 :169-178), not just report exit code (:111).
- Test: add a fixture JSON set where G2 should fail and assert NO-GO; assert bmx4c mode rejects a CPU-only report.

### B. Activation-height blockers (C1/C2/C4/C5 + H-series security)

**WP-5 — C4 transport size guard (fully independent).**
- Owns: `src/net.cpp` (V2/PQ transport region), `src/bip324.cpp`, `src/bip324.h`.
- Change: send-side guard in `V2Transport::SetMessageToSend` (:1678-1712) rejecting any `contents.size() > 0xFFFFFF` (disconnect, no silent truncation); assert in `bip324.cpp:125-129` that length ≤ `0xFFFFFF`. Ensure block bodies over V2/PQ are never sent as a raw `block` message > 16MiB — force the compact-block / `blocktxn`-fragment path (each < 16MiB) or fall back to V1 framing. Keep recv `MAX_CONTENTS_LEN` ≤ `0xFFFFFF` (:1349).
- Test: functional test relaying a >16MiB block between two V2-only peers must succeed (via compact/fragmented path) and a raw oversize `block` must be refused, not truncated.

**WP-6 — C6/C7/H8 backend certification integrity (independent files).**
- Owns: `src/matmul/accel_v4.cpp`, `src/matmul/accel_v4.h`, `src/matmul-v4-report.cpp`, `src/cuda/matmul_v4_bmx4_accel.cu` (+ hip/metal mirrors).
- Change: (C7) make runtime `accel_v4.cpp:ResolveBackend` (:334) consult the v4 `admissible`/certification registry (`backend_capabilities_v4.h`), not just v3 `CapabilityFor` (:100-122). (C6) require an actual device/tensor path for a native-mxf4 marker — do not emit `native-mxf4` for the scalar-decode fallback (`matmul_v4_bmx4_accel.cu:679-698,1424`); or rename the scalar path marker. (H8) make `matmul-v4-report` bmx4c/v41 PASS require a real device (not CPU) — gate exit 0 on device execution (:1256,1018,684).
- Test: `matmul-v4-report --profile bmx4c` on a GPU-less host must exit non-zero; determinism test asserting registry-admissible == runtime-dispatched backend.

**WP-7 — C5 async bounded recompute worker (serialized lane: net_processing.cpp + validation.cpp).**
- Owns (coordinated with WP-8 — see sequencing): `src/net_processing.cpp` `ProcessBlock` region (:4220-4234) + a new worker-queue module; `src/validation.cpp` recompute offload seam (:10175-10310).
- Change: move the synchronous `ProcessNewBlock`/ENC-DR recompute off the `g_msgproc_mutex`-holding thread onto a bounded worker pool sized by `nMatMulMaxPendingVerifications`; keep cs_main-dependent classification (empty-body :10252, assumevalid-trust :10275-10286) on the caller before dispatch. Return the message handler immediately.
- Test: functional test — a peer delivering an expensive block does not stall processing of other peers' messages.

**WP-8 — C1/H2/H3 + H1 + H9/H10 P2P security routing (serialized lane: net_processing.cpp).**
- Owns: `src/net_processing.cpp` (all security-decision edits) + the C1 routing edits in `src/validation.cpp` non-recompute regions.
- Change:
  - **C1/H2:** route best-header/peer-chain selection, direct-fetch eligibility (:1519-1582), outbound-peer protection (:3632), chain-sync eviction (:6876-6883), IBD/download gating (:5370,7173), and anti-DoS work thresholds (:3448,5721,6370) to read `nAuthenticatedChainWork` (with graceful behavior while auth-work is stale during IBD).
  - **H3:** replace raw `m_best_header` + `GetBlockProofEquivalentTime` in `BlockRequestAllowed` (:2422-2424) with authenticated work where it is a security gate.
  - **H1:** move the `IsMatMulProductPayloadRequired`/ENC-DR check ahead of the cmpctblock budget charge (currently charge at :5766 precedes the payload-required bail-out at :5814-5821), so a fresh block is not charged once for the compact token that does no work and again for the full block (:6415).
  - **H9/H10:** couple prefetch (:3560,7774) to the 8-entry cache size (raise cache or cap in-flight prefetch); add an assumevalid-depth guard to `MaybeRequestMatMulSketch` (:1895-1909); add a per-peer ingress rate limit on MMSKETCH (:6179-6256).
- Test: extend `matmul_chainwork_auth_tests` to assert forged-header chains cannot trigger direct-fetch/eviction/protection; add a prefetch-vs-cache regression and an MMSKETCH ingress flood test.

**WP-9 — H5/H6/H7 solver dedup + override + two-phase API (pow.cpp; sequence after WP-2).**
- Owns: `src/pow.cpp` solver region, `src/matmul/matmul_v4_batch.h`/`.cpp`.
- Change:
  - **H6:** add `const uint256* share_target_override` to `SolveMatMulV4` (:4864-4870) and `SolveMatMulV4BMX4C` (:4772-4780), thread it from the v4 dispatch (:5046-5048), and relax the digest early-exit (BMX4C loser test :4828, ENC-S8 :4946/:5008) to `effective_target` exactly as the legacy path does at :5080.
  - **H5:** add a process-wide single-flight keyed by block hash around the ENC-DR recompute so duplicate concurrent recomputes of the same hash collapse (the dedup at `validation.cpp:10739` guards only the disk write).
  - **H7:** add a `ComputeDigestOnly`/two-phase digest-then-sketch API on the ENC-S8 CPU `BatchedSketchMiner` (mirror the BMX4C target-gated pattern) so losing nonces don't materialize 8MiB payloads.
  - Coordinate with WP-2 (both touch `pow.cpp`): WP-2 lands first (merge blocker), WP-9 follows.
- Test: **H6** add a v4-height `share_target_override` case (the existing `pow_tests.cpp:2992` covers legacy only — a v4 case is required or the regression stays green); H5 concurrency test (two threads, same hash → one recompute); H7 memory-ceiling test over a 32-nonce window.

**WP-10 — C2 residual throttle hardening (config/consensus; small surface).**
- Owns: `src/pow.cpp` budget functions (`EffectiveMatMulPeerVerifyBudgetPerMin` :4049-4056), `src/consensus/params.h` defaults.
- Change: reconsider the IBD per-peer 200000/min escalation (:4055) — bound it so per-peer throttling is not fully neutralized during catch-up; the on-wire nonce enablement (`BTX_HEADER_NONCE_ON_WIRE`) is a separate coordinated header-format change (out of scope for a hotfix, note only). Coordinate with WP-9/WP-2 on `pow.cpp` (disjoint functions; sequence to avoid conflicts).

**H4 / C8 — DESIGN items (no code WP).** Pin the normative predicate to exact-recompute-equivalence in the spec and add one clarifying sentence at `src/validation.cpp:10241-10244`; document C8 (tensor work is not consensus-enforceable by construction) in the spec. Assign to a docs owner (`doc/…`), no source collision.

**Sequencing summary for the two hot files:**
- `src/net_processing.cpp`: WP-7 (C5 async, structural) then WP-8 (C1/H1/H9-H10 routing) — or one owner does both sequentially. Do NOT parallelize.
- `src/validation.cpp`: WP-7 (recompute seam) vs WP-8 (C1 routing, non-recompute regions) touch different regions but same file — assign to one owner or land WP-7 first.
- `src/pow.cpp`: WP-2 (C3 central fn) → WP-9 (H5/H7) → WP-10 (C2 budget). Disjoint functions, sequence to avoid merge conflicts.
- Freely parallel from day 1: WP-1, WP-3, WP-4, WP-5, WP-6.

---

## 3. Already-fixed / False-positive-here (flag explicitly)

1. **H6 — CORRECTED to REAL-HERE (initially misread as fixed).** Only the *legacy* `SolveMatMul` path honors `share_target_override` (`pow.cpp:5080`); at v4 heights the early dispatch (`pow.cpp:5046-5048`) calls `SolveMatMulV4` which lacks the parameter entirely (`:4864-4870`). The existing test and release note cover legacy solvers only. Pool shares ARE broken at v4 heights. See WP-9.
2. **All 5 btx-node reviewer API fixes — NOT APPLICABLE HERE.** The C++ APIs are already internally consistent: BMX4 Metal probe is in `matmul_v4::bmx4::metal` (`metal/matmul_v4_bmx4_accel_stub.cpp:7`), `win_target` is threaded through the mining dispatcher (`accel_v4.cpp:541`, `pow.cpp:4819`) and correctly absent from the CPU batch-miner test API, `matmul-v4-report` never calls the win_target dispatcher, and `is_regtest` is threaded through the BMX4 construction invariant (`kernel/chainparams.cpp:65,206`). These were btx-node-synthesis reconciliations only.
3. **C2 mitigations largely landed.** Defer-not-disconnect, skip-known, 16/4→4/2 re-pricing, and the header-PoW coupling assert all exist (evidence above). What remains is the IBD per-peer 200000 escalation and the fundamentally-disabled (fail-closed) header throttle pending an on-wire nonce.
4. **C3 `generate` path — already correct.** `rpc/mining.cpp:4940-4944` already offloads; only the test helper and submitSolution are missing it.
5. **H3 recompute-trust — already authenticated.** The assumevalid recompute-skip gate already uses `nAuthenticatedChainWork` (`validation.cpp:10282`); the residual raw usage is lower-severity relay policy.
6. **H9/H10 serve side — already hardened.** E.1 serve token-bucket/dedup/egress-budget and mmsketch request/receive symmetry with self-authentication are in place; only ingress rate-limit + prefetch/assumevalid coupling remain.
7. **H4 normative predicate — already stated** in code comments (`validation.cpp:10241-10244`); needs formal pinning, not a code fix.

### Note on H12 blast radius
The `or True` bug is real (`k2b-gate.py:301`), but this is an **offline human decision-support tool** that does not wire into consensus (`nMatMulBMX4CHeight` stays `INT32_MAX`), and G2 is not even part of the final `go` verdict (:304). So H12 is a real quality/integrity defect in the activation-gate tooling, not a live consensus risk — merge-blocker class, not activation-height class.
