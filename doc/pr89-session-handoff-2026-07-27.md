# PR-89 Stage-3 Recursion — Session Handoff (2026-07-27)

> **MatMul v4.7 transition status:** historical Stage-3 handoff for possible
> Epochs B–D. It has no authority in Epoch A. A mandatory proof must be
> canonical and durable; Epoch B still requires Profile-1 ExactReplay, Epoch C
> retains Profile 1 under proof authority, and Profile 2 is Epoch D only. See
> `doc/btx-matmul-v4.7-transition-roadmap.md`.
>
Single-file resume guide. Everything below is MEASURED unless marked COMPUTED/INFERRED.
Nothing is activated: **`certified_bits` is a computed 0** and every `*_ready` /
`k*Executable` constant is still false. No constant was flipped to make anything pass.

---

## 1. THE HEADLINE RESULTS

- **A real block's role sections collapse into ONE root proof that FITS** (`c897501`).
  Arity-N narrow node; the exact arity ceiling is measured. **NOT independently
  re-verified** — the lane committed and then died on an API limit before reporting
  measured bytes or a tamper-reject. **Verify this first (see §4.1).**
- **`transcript_bound` 1/8 -> 8/8** (`e6083a7`), earned by 8 built companion CSs.
- **The >=52*W Fiat-Shamir wall is gone**: 5.37e8 -> 1.64e4 rows per challenge
  (~32,800x); whole transcript ~1.09e11 -> 3.27e6 rows.
- **Real-width aggregate-root self-prove COMPLETES**: 16.66 GiB, ~76 min,
  prove + verify + 3 tamper rejects. Was 303 GiB dense, then OOM at 24 GiB.
- **Recursion fixed point EXISTS in the narrow layout**: expansion **0 columns per
  child column** (526 cols at both W=2 and W=544), level 2 verified by re-entering a
  parent's own real FRI proof. Dense layout proven to have **no** fixed point
  (slope ~597; contraction needs <1; no arity/Q/cap/field change closes it).
- **Verify root cause found**: `Reduce128` compiled to a libgcc software divide
  (`__umodti3` undefined in 21 TUs). Fast-reduce port: `Permute` 30.93us -> 3.61us,
  confirmed at real width (`trace_ntt+roots` 21,896s @8t -> 1,695s @16t).
- **Poseidon2 is ~78% of a prove pass** (1,040s of 1,325s, x2 passes ~= 2,080s) —
  and it is exactly what the existing GPU splice accelerates (~90x, 10/10
  bit-identical audits on real structured data).

## 2. WHAT IS STILL BLOCKED

| item | state |
|---|---|
| Full block proof end-to-end | assembly was 35,363,636 B vs 16,777,216 cap; `c897501` claims this is solved — VERIFY |
| `certified_bits` | computed **0**. g3 closed; g0/g5/g6 pure downstream; **only g1 and g2 have independent work** |
| g2 | verify **5.006 s vs 900 ms** at the *smallest* aggregate shape; two-level root not representable (crossover 2,048 cols vs 2^20 cap) |
| g4 endpoint conjuncts | floor **58.6 s**, of which 57.3 s is the parent's in-AIR SHA replay. Needs a **Poseidon2 companion CS** in `recursive_parent_air.cpp` |
| Endpoint provenance | 26/3/4/0 episode-side (was 26/3/2/21). CompositionLink 3 roots = 2 anchored, 1 not |
| Program registry | **14-role bytecode migration 0/14**, 50/52 endpoint families residual, no `universal_parent_verifier` ProgramTable. LARGEST remaining work |

## 3. TRAPS — READ BEFORE TOUCHING ANYTHING

1. **`ValidateProductionProgramRegistryV1` is purely structural.** A registry built
   from 1-column stubs satisfies every automated check with **zero soundness**. Only
   the `false` readiness constants prevent it.
2. **Goldilocks `B = x + p` aliasing defeated four constructions this session.**
   Canonicity is load-bearing at every decomposition, mask, or absorb.
   `FromU64(x) = x mod p`, so absorb u64 as **two 32-bit lanes**.
3. **Do NOT absorb `v1,v2` as an FS shortcut.** `E -> (v1,v2)` is linear, kernel
   dim 2W-2, constructible with two field inversions. 2^128 vs 2^0.
   See `fri_ext3_alg_order_audit.h:16-35`.
4. **A vacuous CTL bus shipped in this tree once** (`bp_col` was a free witness
   column with no link to the parent). Assume the same shape elsewhere.
5. **`git commit <paths>` DIRECTLY — never `git add` first, never `--amend`.**
   The shared index is racy; one lane's explicit pathspecs still produced an 8-file
   commit, and another rewrote a different lane's commit.
6. **Verdicts ONLY from exit codes + artifact checks.** ~15 false-signal incidents:
   stale objects, shared log collisions, env-gated tests reporting PASS in 0s, a
   `grep -c` masking a build failure, notifications reporting exit 0 for SIGTERM'd
   runs and for builds that produced no binary.
7. **A third W-proportional FS term exists**: `ProtocolBatchCoefficients` under
   `independent_batching_coefficients = true` absorbs 24W bytes. False on Q192 today.

## 4. NEXT STEPS, IN PRIORITY ORDER

**4.1 VERIFY THE BLOCK PROOF (`c897501`).** Highest priority. Run the arity-N narrow
node path on a real block from a local RC regtest datadir (RPC 19335,
u/p, height 106, RC live from 101). Report: measured artifact bytes vs the
16,777,216 cap, ACCEPT by the real unmodified verifier, and a **proof-level**
tamper reject. Until that exists the headline is a commit message, not a result.

**4.2 Poseidon2 companion CS in `recursive_parent_air.cpp`** to replace
`BuildChildAirChallengeShaReplayV1`. Row cost 4096 -> 5 measured for the primitive;
projected endpoint floor 24.6 s upper bound, ~8.4 s if the CS build collapses too.
Unblocks both g4 endpoint conjuncts.

**4.3 GPU-accelerate the Poseidon2 sponge at real width.** It is ~2,080 s of the
prove and the splice already exists (`BTX_GPU_ROWLEAF=1`, hard-aborts on GPU
failure, `BTX_GPU_ROWLEAF_AUDIT=1` for parity). Consumer Blackwell test host,
sm_120, CUDA 13.3.
**Keep verify CPU-viable** — it runs on every relaying node and does not parallelise
(444 serial 205-permutation chains).

**4.4 g2.** Needs a >5.6x verify reduction at the smallest shape AND >2x the column
cap in width before a two-level root exists to time. Likely requires the narrow path,
not the dense one.

**4.5 Program registry.** Largest body of work; nothing this session touched it.

**4.6 Main-repo port.** The then-current main-repo checkout is
**two protocol generations behind** — version 1, Q=148, zero `Fri3AlgProtocolConfig`.
A generation port, not a diff port.

## 5. ENVIRONMENT

- Build in a **private dir** (`build-<lane>`); `build-omp` is STALE and made a
  passing harness appear to fail.
- The shared tree periodically does not compile while lanes are mid-edit; use an
  isolated worktree (precedent: `stage3-prov-wt`, `stage3-airq-wt`, `stage3-blk-wt` —
  all now redundant and safe to remove).
- Cap every heavy job: `systemd-run --user --scope -p MemoryMax=NNG -p MemorySwapMax=0`.
  An uncapped 60 GB process destroyed a whole session; capped ones die cleanly.
- **Disk is at 94% (29 GB free).** Build dirs and worktrees are most of it.
- `sshd` binds **only** to a private overlay-network address on port 2022. If that
  route drops, SSH is unreachable even though sshd is healthy.
