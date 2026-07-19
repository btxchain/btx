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

**Oracle / FAIL.** Only if residue yields §0.1 win. Documented alphabet concentration without shortcut → **INCONCLUSIVE** / non-finding (see `test-vectors.json` `non_findings`).

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

## Kit commands (build-free)

```bash
cd contrib/matmul-c15-reviewer-kit
python3 reference_extract.py
python3 toy_attack_harness.py --n 8 --w 4
python3 toy_attack_harness.py --n 16 --w 4 --seed 7 --degree 3
```

Reduction-relevant finding signals (also in `test-vectors.json`):
**high R²**, **zero Freivalds residual** (systematic), **truncated salt equivalence class**.

## Explicit non-claims

- Running this checklist without a FAIL does **not** close C-15.
- ChaCha20-PRF security alone does **not** imply `BTX-C15-NonCollapse-v1`.
- No silicon nonce/s; no height raise; public activation stays `INT32_MAX`.
