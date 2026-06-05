# BTX Comprehensive Hardening — Implementation Plan (two PRs)

> **UPDATE (final): the activation height for everything actually delivered in this branch is 123,000**,
> not the 126,400 figure used in the planning notes below. It is a single constant,
> `smile2::SmileCTProof::C002_ACTIVATION_HEIGHT = 123000`, which gates the entire shipped C-002/R5 +
> post-quantum bundle (shielded v3 proof, self-serve unshield, legacy-EC rejection, FIPS-205 SLH-DSA
> script flags + bridge attestor). The MatMul/PoW consensus tightenings discussed below under
> `nMatMulHardeningHeight=126400` were NOT implemented in this branch (those consensus params remain at
> their defaults), so the 126,400 references in this and the other redteam notes are historical planning
> records for a broader bundle, retained as-is. See `doc/shielded-c002-migration.md` and
> `RELEASE_NOTES_0.31.0_DRAFT.md` for the authoritative, user-facing activation height.

Directive: implement EVERYTHING at ONE activation height **126,400** (≈7,800 blocks from tip ~118.6k at 90s ≈ 8 days,
"1 week + 1 day"). Version bump 0.30.1 → 0.31.0 [DONE]. Posture: high-value chain, well-funded adversaries → defense-in-depth.

★★ FORK CLASSIFICATION (post-discovery — answer to "soft or hard?"): bundling EVERYTHING at 126,400 = **HARD FORK.**
Reasons (any ONE makes it hard):
- e1 PoW-amortization fix changes seed/PoW semantics ⇒ old↔new nodes MUTUALLY reject (e5: NO soft-fork alternative,
  amortized blocks indistinguishable). Definitive hard fork.
- f3 shielded-soundness fix (if monomial→polynomial challenge swap) changes which shielded proofs are valid ⇒ bilateral hard fork.
- a5 halt fix is a RELAXATION in its edge region (accepts a block pr-214 rejects) ⇒ also hard-fork-direction vs the deployed pr-214.
The timestamp/difficulty/DoS/UX items ALONE would be a SOFT fork (tightening).
⇒ A single 126,400 release requires UNIVERSAL node+miner upgrade by the flag day (NOT just majority hashrate; non-upgraded
nodes fork off permanently).
★ DECISION (maintainer): **(A) ONE FLAG DAY — everything activates at 126,400 as a coordinated HARD FORK.** Rationale: whole
chain resilient/updated within ~1 week; bounds the e1 exploit window to ≤1 week. ⇒ REQUIRES universal node+miner upgrade by
126,400 (coordinate exchanges/pools/explorers NOW; non-upgraded = permanent split). Code may still be organized as separate
review PRs (consensus / crypto / feature) but ALL co-activate at 126,400 in 0.31.0.
PUBLIC FRAMING: headline 0.31.0 = the self-service privacy-preserving SHIELDED→TRANSPARENT unshield feature (+ UX: rebuild
progress bars/ETA, easier build). Security/consensus changes described neutrally as "protocol + mining upgrade"; NO exploit
detail in public notes until post-upgrade (responsible disclosure). Do NOT affirmatively misrepresent if asked directly.

`nMatMulHardeningHeight = 126400` (mainnet) gates the changes; activate from genesis on test nets + regtest CLI override.

================================================================
## PR 1 — Consensus & Node Hardening  (branch: hardening/consensus, builds on pr-214)
Non-crypto-module changes. Consensus tightenings gated at height 126400.

[CONSENSUS, gated 126400]
1. **a5 activation-boundary chain-halt fix (HIGH).** Reconcile BIP94 lower bound with the drift upper bound so a
   block is never unmineable: effective cap = max(prev_mtp + drift, prev_blocktime − MAX_TIMEWARP). Apply IDENTICALLY
   in consensus (validation.cpp ContextualCheckBlockHeader) AND the miner clamp (miner.cpp UpdateTime/GetMaximumTime)
   AND submitSolution (interfaces.cpp) — c1: UpdateTime currently emits min_time and self-rejects. (Correctness fix;
   makes the rule safe at any (re)activation.)
2. **Tighten per-block drift → 1800 (MED, b7-CONFIRMED).** nMatMulMaxFutureMtpDrift 3600→1800. b7: zero honest impact
   (mainnet max block.time−prev_mtp=1143s < 1800; never down-stamps honest), halves the per-block difficulty lever
   (×1.87→×1.32). Realistic max difficulty-suppression is a BOUNDED ~×3.4 transient (NOT floor), self-correcting. Needs a5 fix first.
2b. **STACK: clamp the timestamp ASERT consumes to min(blocktime, prev_mtp+900) (b7).** ZERO honest/liveness impact;
   further floors the difficulty-manipulation lever. Consensus change (changes nBits) → gate at 126400. Good defense-in-depth that is SAFE (unlike the dropped cumulative cap).
3. ~~Cumulative windowed future-drift cap~~ — **DROPPED from 0.31.0 (maintainer decision).** See "DROPPED / FUTURE-REVISIT" below.
4. **Enable the future-drift cap on ALL networks (b4-1, MED)** + regtest CLI args (`-regtestmatmulmaxfuturemtpdriftheight`
   / `-regtestmatmulmaxfuturemtpdrift`, a4). Test nets activate from genesis (also sidesteps a5 there).
5. **Height-gate the mining/submitSolution future-time clamp (b6-F1, LOW)** to match consensus activation.
6. **Enable per-block difficulty slew guard `ApplyDgwSlewGuard` (c1, optional consensus — INCLUDED)** to cap
   difficulty-spike lock-out transients. Gated 126400; verify honest-mining safety.

[NON-CONSENSUS, immediate]
7. **Revert getblocktemplate-throw-on-chain-guard to bypass+return-template-with-warning (a7).** Keep submitblock/
   submitSolution refusing. Fixes BIP22/23 poller regression.
8. **Reorg wallet-confirmation desync (b5, LOW-MED).** Mark a payment "not in active chain and not in mempool" as
   conflicted instead of showing stale confirmations.
9. **PR-214 description correction** (still says height 120000 / tip 118222; reality 118482). Doc only.

================================================================
## PR 2 — Crypto & Shielded Hardening  (branch: hardening/crypto, separate per directive)
All changes to src/matmul, src/shielded, src/libbitcoinpqc + crypto-affecting. Consensus-affecting crypto params
share the 126400 activation height.

[CRYPTO]
10. **c3 fail-closed RNG (HIGH crypto-quality).** ml_dsa/utils.c custom_randombytes_impl: abort on /dev/urandom
    open-fail and short-read (NO zero-fill); error (no wrap/reuse) on insufficient injected entropy; prefer routing to
    a vetted CSPRNG. (Final form pending e4's deterministic-vs-randomized-signing analysis.)
11. **Freivalds rounds 2→3 (b1, defense-in-depth).** 2^-62 → 2^-93. Consensus param → gate at 126400.
12. **MatMul payload deserialization length bound (b2).** Bound matrix_c_data to nMatMulMaxDimension² words pre-decode.
13. **Cross-kernel determinism unit test (d2, LOW).** Compile ScalarDot + NeonDot unconditionally; assert equality over
    worst-case corpus (build-independent regression guard against future SIMD non-determinism).
14. **Shielded refactor-proofing (c4, LOW).** Locally guard variant std::get sites (get_if/holds_alternative);
    convert redundant size/bounds asserts in ct_proof/membership to real runtime checks (release-safe).
15. **c5 z_sendmany (z→z) prover SIGSEGV fix (MED).** Memory-safety bug in smile2 prover; characterize via ASan (e2/e3/e4
    building sanitizer images) then fix. Shielded sends currently broken.
16. **NeedsShieldedProofCheck explicit family check (c5, LOW).** Infer "needs proof" from value-bearing/bridge-mint
    family, not input count, so a future relaxation can't silently skip verification.
16b. **[MED, NEW e2] Bound smile2 CT output amounts to ≤ MAX_MONEY** (consensus tightening, gate 126400): add per-output amount-range check to the smile CT relation/validation — currently absent (a 2^60-sat note verifies); mirror matrict's 2^VALUE_BITS>MAX_MONEY. Latent (value_balance/pool checks stop realized over-value) but a missing invariant.
17. **[PENDING e-wave]** any MatMul-hardness / Fiat-Shamir / range-proof / nullifier / PQ-sig findings (e1–e4).

20. **c3 RNG fix re-rated HIGH→LOW (e4):** unreachable in production (callers pass fail-closed Core entropy; Dilithium hedged). Still implement fail-closed (abort, no zero-fill; error on insufficient entropy) as defense-in-depth. Delete fallbacks in ml_dsa/utils.c AND slh_dsa/utils.c.
21. **d3 shielded-rebuild DoS fix (MED→HIGH):** restrict RebuildShieldedState self-repair to block-connect/startup only (not mempool); bounded incremental re-sync from last checkpoint; drop "position absent" structural rejects from the mempool-path recoverable set. (Prevents one cheap mempool tx → ~25-min node stall, re-armable per shielded block.)

================================================================
## PR 3 — MatMul PoW amortization fix  (HARD FORK, separate coordinated flag-day)
22. **★ CRITICAL (e1): fold the nonce into the MatMul seeds** — `seed_a/b = SHA256(prev‖height‖nonce‖which)` (pow.cpp:47
    DeterministicMatMulSeed + the validation.cpp:8385 "bad-matmul-seeds" enforcement + miner seed-gen) so A·B changes
    every nonce attempt and cannot be amortized; restores genuine Θ(n³)/attempt at negligible honest cost. HARD FORK:
    amortized blocks are bit-identical-valid ⇒ undetectable ⇒ cannot soft-fork; requires universal upgrade at a flag-day
    height. e5 adversarially verifying the break + validating the fix (no perf regression / no new split) before implement.
    Decision needed from maintainer on flag-day timing (this is bigger than the soft-fork bundle).

[DOCS/OPS — accompany PR2]
18. Supply-chain hygiene (c3): bump depends/ sqlite ≥3.50.2; pin Dockerfile apk versions; checksum CI curl|tar;
    record kyber/sphincs upstream commit+hash; fix libbitcoinpqc provenance URL.
19. **Commission EXTERNAL audit of bespoke matmul + shielded lattice crypto** (c3/c5 — residual money risk is the
    primitive soundness; e1–e4 are our best-effort internal pass, not a substitute).

================================================================
## DROPPED / FUTURE-REVISIT (deliberate decisions, not omissions)
### Cumulative windowed future-drift cap — DROPPED from 0.31.0 (decided 2026-06-02)
- WHAT: a consensus rule bounding the SUM of per-block forward timestamp-drift over the last K blocks (vs the per-block
  cap), to stop a sustained MTP-ratchet from compounding.
- WHY DROPPED: (1) REDUNDANT — a2 proved the existing 2h MAX_FUTURE_BLOCK_TIME bound already caps the chain's lead over
  real time, and the per-block drift cap (1800s) + slow MTP advance already self-limit forward drift; the cumulative cap
  only adds protection in the corner where cumcap/window < per-block-drift. (2) FRAGILE/DANGEROUS — h2 found the naive
  implementation has fail-closed chain-halt bugs (rejected every block at activation, worse than a5); even done correctly
  it must measure excess inter-block GAP (not distance-above-MTP) and gate the look-back at the activation height, a subtle
  consensus rule with real halt risk. Net: it would make the chain LESS safe for ~no benefit — contradicting the hardening goal.
- REVISIT IF: (a) the 2h MAX_FUTURE_BLOCK_TIME wall-clock bound is ever weakened/removed, OR (b) the per-block drift cap is
  raised back toward/above the ASERT half-life, OR (c) a future attack demonstrates a cumulative-drift exploit the per-block
  cap + 2h bound don't stop. If revisited: implement EXACTLY per h2's spec (gap-based excess, activation-gated look-back),
  with dedicated chain-halt regression tests at the activation boundary. Reference: redteam/findings/h2.md, a2.md.

## Out-of-scope (document as known/operational, not code)
Selfish mining (consensus-unfixable), cross-version split (operational: majority-hashpower deploy + the now ~1-month
window), chain-guard eclipse + NTP (operational: peer diversity, trusted time).

================================================================
## UPDATES (newest findings + directives) — fold into the PRs above
- **PR1 (soft-fork 125k) += UX/build 0.31.0 items (non-consensus, worker u1/u2):**
  - u1 build-ease: fix GCC-15 consteval-uint256 test-compile failure repo-wide; clean static/portable Linux build (Dockerfile.static option); one-command build + regtest docker-compose.
  - u2 UX: shielded-rebuild + reindex/IBD PROGRESS (percent + bar + ETA + rate; the ~25-min silent shielded rebuild); verbose startup phase logging ON by default; expose rebuild progress in getblockchaininfo.
- **PR2 (crypto/shielded) +=:**
  - d4-1 service-challenge registry eviction-DoS (MED): never evict unredeemed/unexpired; rate-limit issuance. d4-2 verify-vs-redeem footgun (LOW).
  - e3/c5 z_sendmany prover SIGSEGV (MED, triply-confirmed): ASan root-cause + fix (shielded sends currently broken).
  - d3 shielded-rebuild DoS (MED→HIGH): restrict RebuildShieldedState to block-connect/startup, not mempool path.
  - s2/s3 hygiene: bump depends/ sqlite ≥3.50.2 (released binary IS vulnerable — Guix path, not Alpine); record ml-kem/ethash pins; restore leveldb stat loop; checksum CI curl|tar; pin Dockerfile apk.
- **PR3 (PoW HARD FORK) — e1 fix REFINED (e5+f1+maintainer design constraint):**
  - GOAL: make A·B nonce-dependent so it can't be amortized, WHILE keeping work PURE DENSE-GEMM, GPU-hard/brand-agnostic. MUST NOT add per-element SHA256 (ASIC-friendly REGRESSION, f1-A) or memory-hardness (REGRESSION).
  - PREFERRED: per-nonce O(n²) structured perturbation (e.g. diagonal scaling D_nonce from nNonce64 → honest computes A·(D·B), full-rank-different per nonce, not low-rank-amortizable, ~no extra hashing). Use nNonce64 directly (NOT sigma — circular). Two-site (consensus validation.cpp:8385 + miner) must match. Extend to getmatmulservicechallenge (f1-B). Remove dead g_from_seed_cache / CUDA base cache. e5 recalibrated severity HIGH (not CRIT). h1 validating.
  - **f3 (HIGH, candidate-CRIT) likely a 2nd hard-fork item:** if external audit can't close the SMILE2 monomial-FS-challenge soundness (C-002), height-gated swap monomial→Hamming-weight polynomial challenge (legacy SampleChallenge pattern). NEEDS external crypto audit decision.

## IMPLEMENTATION & VERIFICATION STATUS (live)
- ✅ i3 DONE+VERIFIED (findings/i3.md): z_sendmany SIGSEGV = STACK OVERFLOW (TryProveCT ~128KB frame on musl 128KB worker thread), MED wallet-local, NOT remote (VerifyCT ~64KB fits => no poison block). FIX: prover on dedicated 8MB-stack thread (wallet_bridge.cpp); verified z->z send+mine, ASan-clean, verifychain ok. Unblocks v1/x1/x2/x3.
- ✅ i2 DONE+VERIFIED (findings/i2.md, 20-file diff applies clean to pr-214, daemon+wallet image builds green): (1) RNG fail-closed (ml_dsa+slh_dsa abort, no zero-fill/reuse); (2) Freivalds 2→3 gated @126400 (regtest CLI override; verified across boundary); (3) payload deser bound 2048² words; (4) CheckedGet<T> replaces family-keyed std::get + asserts→runtime throws; (5) NeedsShieldedProofCheck value-family-keyed (unknown families FAIL CLOSED); (6) d3: BOTH O(chain) self-repairs removed from MemPoolAccept (only PoW-gated ConnectBlock/startup); (7) d4: prune never evicts unredeemed/unexpired + token-bucket issuance + verify-footgun fixed. Only Fix2 consensus; rest immediate.
- ✅ u2 DONE+VERIFIED (findings/u2.md): src/util/progress.h ProgressReporter (throttled %/bar/rate/ETA); wired into RebuildShieldedState (the ~25-min silent replay), reindex, IBD/UpdateTip; verbose phase logging (init.cpp); getblockchaininfo.rebuild_progress field. 6 files, non-consensus, build OK, patch applies clean to pr-214. (minor cosmetic: dup 100% line when a phase finishes within one throttle window — harmless.)
- ✅ u1 DONE+VERIFIED (findings/u1.md): GCC14/15 consteval-uint256 test-compile fix = ONE header change (src/uint256.h: consteval hex ctor takes const char(&)[W*2+1] instead of string_view) zero call-site edits, full BUILD_TESTS=ON passes; -DBUILD_STATIC=ON option (clean static build, no manual .so removal); Dockerfile.static/tests + docker-compose.regtest.yml. Diff +281/6 files, git apply --check clean vs pr-214. (supersedes the ad-hoc Dockerfile.static prior agents made.)
- ⛔ i5 STOP: f3 challenge-swap NOT safe in-house (verifier inverts challenge) → external audit only (scope: F3_AUDIT_SCOPE.md).
- ★ FEATURE DECISION (maintainer): **SHIP self-service unshield FULLY enabled in 0.31.0.** ⇒ f3 becomes permissionless. COMPENSATING CONTROLS (mandatory): (1) max-effort adversarial wave w1(impl)/x1(forge f3→inflate)/x2(double-spend/value)/x3(privacy/DoS/memory) MUST come back CLEAN; if x1 forges ANY false-value proof = CRITICAL = do not ship feature; (2) commission external f3 audit IN PARALLEL (F3_AUDIT_SCOPE.md); (3) ship a turnstile/value-pool imbalance MONITOR (inflation canary) with the release. Honest caveat: testing finds exploits, can't PROVE soundness — audit still required.
Agents producing built+tested diffs: h2 (soft-fork bundle: a5/drift/cumulative/slew/height-gate @126400),
i1 (refined e1 PoW fix — regression-minimized), i2 (RNG/Freivalds-rounds/payload-bound/c4-guards/NeedsShieldedProofCheck/
d3-rebuild-DoS/d4-eviction-DoS), i3 (z_sendmany segfault root-cause+fix), u1 (build-ease), u2 (UX progress/ETA),
v1 (self-service unshield feature design→impl). h1 already CONFIRMED the e1 fix concept works.
Plus i5 (f3 conservative monomial→polynomial challenge swap, gated 126400 — delivers "verified" OR "needs audit").
INTEGRATION (decided): apply verified diffs onto the redteam branch (keeps redteam/ docs available to running agents;
strip redteam/ when cutting the public PR branches). Overlap-prone files needing careful conflict-resolution:
chainparams.cpp (nMatMulHardeningHeight=126400 + per-net activation), validation.cpp (a5/drift/cumulative/slew + e1 seed
+ f3 + d3), node/miner.cpp, rpc/mining.cpp (e1 service-challenge + d4 + UX), src/shielded/* (i3 segfault + i5 f3 + v1 feature).
Then: full 0.31.0 build → run test suite (after u1's GCC-15 test-compile fix) → RE-RUN every confirmed attack vs the patched
binary (proof obligation). NOTE: integration executes once all impl diffs land (agents mid-flight); it is a careful manual
merge, not an auto-apply, because of the file overlaps above.

## HONEST RESIDUAL-RISK LEDGER (what "as secure as we can make it at this time" means)
- FIXED+VERIFIED (after integration): a5 halt, drift/cumulative/slew difficulty hardening, e1 PoW amortization (HARD FORK),
  d3/d4 DoS, RNG fail-closed, Freivalds rounds, payload bound, c4 guards, z_sendmany segfault, UX/build, version 0.31.0.
- ROBUST BY AUDIT (no fix needed): PoW forgery (b1), verification DoS (b2), relay DoS (a3), MTP-ratchet/timelock (a2),
  ASERT math (b4), split model (a4), backward-drift (a6), P2P/RCE (c2), poison-block (c1/c4), monetary impl (c5),
  PQ sigs (e4), supply-chain incl. secp256k1 unmodified (s1/s2/s3), no NTT/structure matmul break (f2).
- ★ RESIDUAL NEEDS EXTERNAL CRYPTO AUDIT (cannot be "proven secure" by us): **f3 SMILE2 monomial-FS-challenge soundness**
  (their own deferred C-002). MITIGATION OPTIONS: (a) external audit completes the tight extractor proof, OR (b) conservative
  height-gated HARD-FORK swap monomial→Hamming-weight polynomial challenge (legacy SampleChallenge pattern — they already did
  this class of fix once). RECOMMEND (b) for THIS release if audit can't complete in the window (don't ship an unproven
  soundness assumption on the active value-bearing path). DECISION NEEDED.
- DESIGN PROPERTIES (not flaws, by maintainer intent): GPU-hard/brand-agnostic mining (NOT ASIC-resistant-via-memory);
  soft-fork-style minority-enforcement stranding (operational: universal upgrade by 126400).

## Proof obligation before opening either PR
Re-run EVERY confirmed attack (a5 halt, drift grind, difficulty lock-out, RNG, etc.) against the PATCHED build and
show it's closed; full build + existing tests green. Bring diffs + evidence for sign-off before push.
