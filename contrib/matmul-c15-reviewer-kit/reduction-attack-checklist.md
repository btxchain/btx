# C-15 reduction-attack checklist (firm oracles → §0.1 FAIL)

**Status: C-15 OPEN.** This is a step-by-step attack menu for independent
cryptanalysts. Completing it with only negative evidence is **not** a theorem
and does **not** authorize raising `nMatMulDRLTHeight` (`INT32_MAX` remains).

Normative game: [`doc/btx-matmul-v4.4-lt-external-c15-packet.md`](../../doc/btx-matmul-v4.4-lt-external-c15-packet.md) **§0.1**.
Named assumption: **§0.2** `BTX-C15-NonCollapse-v1` (unreduced).
Kit smoke: `toy_attack_harness.py`, `reference_extract.py`, `test-vectors.json`.

## How to use this checklist

For each attack below:

1. Attempt the construction at toy `n` (kit) then at review sizes `n ∈ {64,256,4096}`.
2. Measure exact-int MAC cost against `HonestMAC(n)` (§0.1).
3. Record vectors / R² / Freivalds residuals / equivalence-class sizes.
4. Map the outcome to the §0.1 return table.

| §0.1 verdict | When (reminder) |
|---|---|
| **FAIL** | `Adv ≥ ε` at `≤ (1−δ)·HonestMAC`, **or** affine/low-degree (deg ≤ 2 primary) surrogate on ≥ `N=10⁶` realistic `B32` samples with Freivalds-usable rewrite through `G,W,H` |
| **PASS** | No such adversary for the stated class; residual risks bounded — **still no height raise** |
| **INCONCLUSIVE** | Unrestricted class open; bias without shortcut; missing oracles |

Review defaults: `δ = 1/2`, `ε = 2⁻⁴⁰`. Do not silently retune.

---

## A1 — Affine entrywise surrogate (C15-A → §0.1 FAIL)

**Goal.** Fit `f(raw) = α·raw + β` (or panel-linear) so `f(B32[i,j]) ≈ Extract(...)`.

**Steps.**

1. Sample dense realistic `B32` from synthetic `(G·W)·H` (`rank ≤ w`) and/or honest MatExpand traces.
2. Fit affine OLS; record R² (`toy_attack_harness.py --degree 1` or in-tree `matexpand_extract_r2_nonapproximability`).
3. If R² is non-negligible, build Freivalds probes on `Ĉ` and attempt rewrite through `G,W,H` (L1 thin-panel class).
4. Count MACs of the shortcut vs `HonestMAC`.

**Oracle / FAIL.** Surrogate matches on ≥ `N=10⁶` samples **and** Freivalds-usable rewrite at half-cost (or R² near-perfect with accepting forged sketches). Kit smoke: unexpectedly high affine R² — escalate; do not close on smoke alone.

---

## A2 — Degree-2 / degree-3 polynomial surrogate (C15-A extended → §0.1 FAIL)

**Goal.** Entrywise poly of deg ≤ 2 (primary FAIL class) or deg ≤ 3 (§0.2 checklist).

**Steps.**

1. Same samples as A1.
2. Fit deg 1..3; print all R²: `python3 toy_attack_harness.py --n 16 --w 4 --degree 3`.
3. Firm bar (in-tree witness): R² < 0.05 expected on dense regimes; R² ≳ 0.05 demands rewrite attempt.
4. If any degree yields a Freivalds-linearizable `B̂'`, cost it against §0.1.

**Oracle / FAIL.** Deg ≤ 2 surrogate with rewrite + `Adv ≥ ε` at `≤ (1−δ)·HonestMAC`. Deg-3 alone with rewrite is a strong reportable finding / FAIL under the §0.2 checklist even if primary table emphasizes deg ≤ 2.

---

## A3 — Zero Freivalds residual on surrogate `B̂'` (C15-B → §0.1 FAIL)

**Goal.** Produce `B̂'` cheaper than MatExpand+Extract such that Freivalds probes cannot distinguish `B̂` from `B̂'` (residual `rᵀ(B̂−B̂')s = 0` systematically, or within soundness).

**Steps.**

1. Build any candidate surrogate (affine, poly, spectral fold, cached Expand).
2. Run multi-probe Freivalds residuals (kit prints one probe; firm should use many + EncDr round count).
3. Feed forged sketch into `VerifySketchBMX4CLT` / kit-equivalent accept check.
4. Account MAC cost of producing `B̂'` + sketch.

**Oracle / FAIL.** Systematic zero / soundness-bounded residual with accepting digest at half-cost. Single zero on tiny `n` = WARN only (`toy_attack_harness` behavior).

---

## A4 — Truncated `(i,j)` salt equivalence class (§0.2 #6 → §0.1 FAIL)

**Goal.** Show that collapsing position salts to low bits / tiles creates a large shared-keystream equivalence class and reopens ~`n/w ≈ 32×` thin-panel amortization.

**Steps.**

1. Confirm normative Nonce96: `nonce_second = (uint64(i)<<32) | uint64(j)` full-width (see `test-vectors.json` / packet §1.4).
2. Diff Extract under `(i,j)` vs `(i⊕2³²k, j)` / high-half flips — kit/C++ `matexpand_position_salt_differential`.
3. Hypothesize a truncated implementation or adversary-forced tile reuse; measure collision / equivalence-class size vs IdealExtract baseline (~1/23).
4. If class is large, attempt shared-φ / panel-reuse Freivalds rewrite; cost vs `HonestMAC`.

**Oracle / FAIL.** Concrete truncation (in a consensus twin) **or** adversary-forced equivalence class yielding `Adv ≥ ε` at `≤ (1−δ)·HonestMAC`. Goldens alone ≠ PASS.

---

## A5 — Spectral / low-rank residue after Extract (§0.2 #3)

**Goal.** Recover usable `rank(B̂) ≪ n` structure for reassociation (`U`/`V` are rank-transparent).

**Steps.**

1. Form `B̂` via normative Extract on rank-`≤w` `B32`.
2. Estimate numerical / modular rank; search shared-φ / Fourier residue across rows/tiles.
3. If residue exists, attempt Freivalds rewrite cheaper than Expand+BV+combine.

**Oracle / FAIL.** Only if residue yields §0.1 win. Documented alphabet concentration without shortcut → **INCONCLUSIVE** / non-finding (see `test-vectors.json` `non_findings`). Empirics from `spectral_approx_probe.py` (`n∈{8,16,32}` SVD/CCA) alone ≠ FAIL — see `spectral_approx_probe.md`.

---

## A6 — TMTO / cross-nonce Expand reuse (§0.2 #4, I1′)

**Goal.** Hellman / panel tables or partial Expand reuse across nonces/templates cheaper than marginal MatExpand-B.

**Steps.**

1. Bound state space `|M11|^{n·w}` and differential reuse under position-salted Extract.
2. Test cross-template reuse of one MatExpand-B under shared `P` (I1-A).
3. Cost any surviving table against `HonestMAC`.

**Oracle / FAIL.** Concrete TMTO / reuse with §0.1 thresholds. Speculative infeasible tables → not FAIL.

---

## A7 — Mant/Scale related-nonce XOR (§0.2 #5)

**Goal.** Exploit `MANT`/`SCLE` lane packing or `Mant(raw)↔Scale(raw⊕Δ)` structure to amortize beyond per-cell ChaCha.

**Steps.**

1. Reproduce related-nonce observations from pre-review notes.
2. Ask whether any identity skips GEMM or collapses Freivalds probes across cells.
3. If only distinguisher / μ′↔e lock without MAC savings → document as C15-C residue, not FAIL.

**Oracle / FAIL.** Amortization that wins §0.1. Distinguisher-only → **INCONCLUSIVE**.

---

## LFR — Linear Freivalds rewrite taxonomy (GAP-B1)

**Scope.** Packet C15-B / Sketch B: Freivalds (or sketch) probes that are
**linear in `B̂`** rewrite as probes on `G,W,H` alone (or a cheap fold of
panels), yielding accepting digests at `≤ (1−δ)·HonestMAC`. The classical
write-ups cover only **affine entrywise** and **shared-φ** residues; this
table classifies the wider linear-rewrite surface firms must probe.

**Status labels (per subclass).**

| Label | Meaning |
|---|---|
| **theorem** | Normative / algebraic fact under stated hypotheses (consensus pin, exact identity, or IdealExtract/PRF fragment). Still **not** a C-15 close. |
| **heuristic** | Plausible obstruction or attack shape; empirics / witnesses only; Sketch B full-rank claim remains unproven (`PositionSalted-FullRank-Heuristic-v1`). |

Completing every row with **negative** evidence is **PASS for that subclass
only**, not a theorem for unrestricted adversaries, and **does not** authorize
raising `nMatMulDRLTHeight`.

| ID | Subclass (beyond / including affine·shared-φ) | Status | Oracle / FAIL surface | Checklist link |
|---|---|---|---|---|
| **LFR-0** | Legacy thin-panel L1: Extract omitted or replaced by linear `Fold` of `B32=GWH` | **theorem** | Probes reassociate through `G,W,H`; ~`n/w≈32×` vs dense ExactGemm. Extract is **necessary** vs this class; sufficiency unproven. | packet §1.1 |
| **LFR-1** | Affine entrywise `B̂[i,j]≈α·B32[i,j]+β` (global or per-panel) | **heuristic** empirics; IdealExtract/PRF ⇒ no dense match is a **theorem fragment** only | R² / match on ≥`N=10⁶` **and** Freivalds-usable rewrite at half-cost | A1 |
| **LFR-2** | Shared-φ / Simon-style `φ∘(GWH)` spectral residue, effective rank `≲w` | **heuristic** (`PositionSalted-FullRank-Heuristic-v1`; GAP-B2) | Numerical/modular rank ≪`n` correlated with panels; rewrite cheaper than Expand+BV | A5 |
| **LFR-3** | Separable / panel-linear bias `α·raw + β_i + γ_j` (or tile-constant offsets) | **heuristic** (same primary FAIL family as LFR-1; not separately reduced) | OLS with row/col dummies; nonzero structure ⇒ attempt L1-style rewrite | A1 |
| **LFR-4** | Degree-≤2 entrywise polynomial surrogate | **heuristic** empirics; IdealExtract/PRF fragment as in LFR-1 | Deg≤2 R² bar + rewrite; **primary** §0.1 FAIL class | A2 |
| **LFR-5** | Degree-3 entrywise polynomial surrogate | **heuristic** (§0.2 checklist extension; out of Sketch A arrow) | Deg-3 R² ≳0.05 ⇒ rewrite attempt; reportable even if primary table emphasizes deg≤2 | A2 |
| **LFR-6** | Truncated `(i,j)` salt / tile keystream equivalence class | **theorem** that normative full-width is required (truncation = consensus-split); collapse under truncation is **heuristic** attack shape | Equivalence-class size vs IdealExtract ~1/23; shared-φ / panel-reuse rewrite | A4 |
| **LFR-7** | Sketch-projector–induced fold (`U`/`V` create usable structure; rank-transparent projectors) | **heuristic** (GAP-B4: no lemma that projectors cannot *create* structure) | Cheap algebraic form in `(U,V,G,W,H)` matching probes without full Expand | A3, A5 |
| **LFR-8** | Approx-`B̂` / high-rank but Freivalds-forgery-friendly residual | **heuristic** (GAP-B3) | Multi-probe residuals within soundness at half-cost; systematic accept of forged sketches | A3 |
| **LFR-9** | Batch-algebra / associativity “past Extract” into `GWH` | **theorem** that exact int associativity *after* Extract does **not** pull panels through Extract (`matexpand_batch_algebra_optimal_equals_full`); any *new* linear fold past Extract remains **heuristic** | BA-A/B witnesses; search for accidental linearization (Q* windows, BA-C) | packet §4 |
| **LFR-10** | Cached Expand / TMTO / cross-nonce panel reuse feeding linear probes | **heuristic** (state-space / differential cost bounds) | Concrete table or reuse with §0.1 MAC win; speculative infeasible TMTO ≠ FAIL | A6 |
| **LFR-11** | Related-nonce Mant/Scale XOR as *linear* amortization across cells | Lane identity `Mant(raw)=Scale(raw⊕Δ)` is **theorem** (PRF encoding); GEMM/Freivalds skip is **heuristic** / non-finding to date | Identity tuples + ask whether probes collapse across Δ-mates with MAC savings | A7 |

### How to run the taxonomy

1. For each LFR row, attempt the linked A-attack (or packet BA) at toy `n` then
   `n∈{64,256,4096}` where feasible.
2. Record: surrogate agreement / rank / equivalence-class size / Freivalds
   residuals / exact-int MAC vs `HonestMAC`.
3. Map to §0.1: only **rewrite + cost win** (or primary surrogate+rewrite) is
   **FAIL**; distinguisher-only / alphabet concentration without shortcut →
   **INCONCLUSIVE**.
4. Do **not** treat LFR-0 necessity of Extract as sufficiency (Sketch B remains
   open; GAP-B2/B3/B6 untouched by this taxonomy alone).

**Cross-links.** Sketch B / GAP-B1:
[`doc/btx-matmul-v4.4-lt-c15-reduction-drafts-2026-07-19.md`](../../doc/btx-matmul-v4.4-lt-c15-reduction-drafts-2026-07-19.md);
Wave-1 gap rank #3:
[`doc/btx-matmul-v4.4-lt-c15-reduction-research-synthesis-2026-07-19.md`](../../doc/btx-matmul-v4.4-lt-c15-reduction-research-synthesis-2026-07-19.md).

---

## Kit commands (build-free)

```bash
cd contrib/matmul-c15-reviewer-kit
python3 reference_extract.py
python3 toy_attack_harness.py --n 8 --w 4
python3 toy_attack_harness.py --n 16 --w 4 --seed 7 --degree 3
python3 spectral_approx_probe.py   # SVD/CCA n∈{8,16,32}; empirics ≠ §0.1 FAIL
```

Reduction-relevant finding signals (also in `test-vectors.json`):
**high R²**, **zero Freivalds residual** (systematic), **truncated salt equivalence class**.
Spectral/CCA toy residuals → see `spectral_approx_probe.md` (need §0.1 win to claim FAIL).

## Explicit non-claims

- Running this checklist without a FAIL does **not** close C-15.
- ChaCha20-PRF security alone does **not** imply `BTX-C15-NonCollapse-v1`.
- No silicon nonce/s; no height raise; public activation stays `INT32_MAX`.
