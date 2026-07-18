# ENC-SC — Consolidated Adversarial Review & Required Fixes

Three independent Opus red-team lenses attacked the ENC-SC committed object
(`doc/btx-matmul-deterministic-nextgen-design.md`, §7). As with the Option-4
review, the lenses **disagreed**, and the disagreements were where the real
defects hid: one lens declared a layer "sound by construction," another broke
exactly that layer. This memo adjudicates all three and states the corrected
construction the v4.4 spec must be built on. **Nothing here is implemented; no
`matmul_v4_sc` code exists. This is a pre-spec design gate.**

**Bottom line:** ENC-SC is a viable direction with a genuinely sound *core*, but
the §7 draft is **NOT ready to spec** — it contains two identified breaks and one
open hardware-gated risk. All three are fixable with specific changes; the fixes
tighten (do not resolve) the GEMM-dominance question, which only silicon can
settle.

---

## 1. What is SOUND (cross-validated, keep)

- **Field / Circle-FRI transplant to q = 2⁶¹−1 — SOUND.** q ≡ 3 (mod 4) ⇒ the
  circle group C(F_q) is cyclic of order q+1 = 2⁶¹ (2-adicity 61), so the
  circle-FFT halving map is well-defined for a 2²¹ codeword; F_{q²} = F_q[i]
  is the correct CM61 folding field (Circle-STARKs, eprint 2024/278). Vanilla
  radix-2 FRI is correctly rejected (2-adicity of q−1 is 1). The decisive
  claim — *the existing L0 consensus field survives* — holds. Caveat: circle
  codes need special-case handling (self-conjugate point / last layer); that is
  audit surface, not a break.
- **Sum-check + Schwartz–Zippel — SOUND, proven.** ε_sc ≈ 2⁻¹¹⁷ (12 degree-2
  rounds), ε_SZ ≈ 2⁻¹¹⁷ (20-var multilinear). The challenge point is drawn
  *after* the commitment and the verifier computes the end-points P̃, Q̃ itself
  from header seeds, so a wrong Ĉ′ cannot be tailored to the sampled line. These
  terms are ~2⁻¹¹⁷ — NOT the bottleneck.
- **The work-enforcement PRINCIPLE — sound conditionally.** Enforcement lives in
  *the commitment being the lottery preimage* (not in the sum-check, which a
  prover can answer for the true value in O(n²+nm) ≪ W). There is no f^k gap and
  no "compute a fraction f" shortcut: the LDE is a global transform, so omitting
  any part of Ĉ changes the whole polynomial and the seed-derived end-point
  rejects it. This is a real improvement over Option 4 — **but only if the
  commitment is rigid and FRI is correctly sized**, which the draft gets wrong
  (§2, §3).
- **Determinism (D1) achievable; DoS bounded.** Integer circle-FFT is
  deterministic in principle; the verify cascade is fail-fast and forcing
  max-verify ≈ honest work. Determinism's cost is a large unbuilt
  consensus-normative surface (circle-FFT ordering, F_{q²}, FS transcript
  serialization), not a math obstruction.

---

## 2. BREAK #1 — Lottery keyed on the evaluation codeword (Option-4 reincarnated)

**As drafted (§7.1):** `matmul_digest = H(σ ‖ R_LDE)` where `R_LDE` is the Merkle
root over the **evaluation codeword** (~2m² leaves).

**The attack:** FRI is a *proximity* test — it proves the committed word is
*close* to a low-degree polynomial, not that it *is* one. A miner pays the full
GEMM W **once**, builds the honest codeword, then **corrupts one redundancy
leaf** → recomputes ~20 hashes → new root → fresh `H(σ‖R′)` lottery draw, **no
GEMM**. The corruption sits at Hamming distance ~2⁻²¹, well inside FRI's radius,
so FRI still accepts and the sum-check still binds the honest underlying
polynomial; it is caught only if one of the queries opens that leaf (~0.004%).
Cost ratio ~10⁹× vs honest. **This is the §2.4 commitment-grinding collapse
verbatim.**

**The memo's precise error (§4.B / §7.6-D3):** FRI binds a unique *polynomial*
but a δ-*ball* of *roots*; the lottery is keyed on the *root*. "Zero prover
degrees of freedom" is false — the unqueried codeword leaves are Option 4's free
positions, reintroduced by proximity slack. (Lens #3 declared this layer "sound
by construction" *assuming* commitment rigidity; lens #1 checked the assumption
and it fails.)

**REQUIRED FIX (F1):** key the lottery on the **message** commitment —
`M = Merkle(canonical m² residues of Ĉ)`, i.e. the actual sketch bytes (today's
`SerializeSketch`) — **not** the evaluation codeword. Then corrupting any
lottery-preimage leaf changes Ĉ itself, which the seed-derived end-point rejects;
the FRI codeword (with its redundancy) lives **only** in the post-win proof.
Rigidity restored: *fresh ticket ⟺ fresh Ĉ ⟺ fresh nonce ⟺ fresh B ⟺ fresh W.*
Add an explicit consistency argument binding `M` to the FRI-committed polynomial
(systematic encoding + open the message positions, or a batched evaluation
argument). Bonus: only the 1× message tree is per-nonce; the 2× codeword tree
moves to win-time, *lowering* the per-nonce hash floor.

The corrected object is coherent: **"commit to the true sketch as the lottery +
sum-check/FRI as the *whole-object* proof (replacing f^k spot-checks)."**

---

## 3. BREAK #2 — FRI soundness parameters under-sized; PoW-grinding unaccounted

**As drafted (§7.6/§7.7):** "ρ = 1/2, ~80 queries + 20-bit grind ⇒ ε_FRI ≈ 2⁻⁸⁰
under the proven Johnson regime."

**Error A — the number is the disproved conjecture, mislabeled as proven.**
Proven Johnson per-query soundness is ½·log₂(1/ρ) = **0.5 bits/query** at ρ=1/2,
so 80 queries → **2⁻⁴⁰**, not 2⁻⁸⁰. The 2⁻⁸⁰ figure is the **capacity
conjecture** (1 bit/query) — which the memo disclaims in prose yet uses in
arithmetic, and which was **disproved in late 2025** (Diamond–Gruen 2025/2010;
SoK 2026/1367). Corrected proven accounting at the stated params: **ε_FRI ≈
2⁻⁶⁰** (query term), before a separate commit-phase/folding proximity term that
alone is ~2⁻⁵⁵…2⁻⁷⁰ at N=2²¹ and needs post-2024 analyses (2024/1512) to clear
2⁻⁸⁰. If the multilinear opening uses BaseFold at unique-decoding, per-query
drops to ~0.42 and 80 queries → 2⁻³³.

**Error B — single-shot accounting in a PoW.** The draft adds ε terms once
(SNARK model). In a PoW every nonce is a fresh Fiat–Shamir instance and the
adversary's budget is hashing, so effective forge cost ≈ **2^grind / ε_FRI**
(non-interactive FRI concrete security, 2024/1161). The FS grind nonce sits in
the query phase and does not change `R_LDE`, so an adversary can (1) find a
lottery-winning garbage root, (2) answer the sum-check for the true value in
O(n²+nm) ≪ W, (3) grind the query-index nonce until the garbage codeword's
openings pass. With grind=20 and proven ε_FRI≈2⁻⁶⁰ this is a false-proof path
whose margin over honest per-block work is **thin-to-negative on early /
low-difficulty / under-attack networks** — the exact "cheaper than work"
failure the design exists to exclude. The sum-check/end-point path is NOT the
weak link (grinding it costs ~2¹³⁷); **only the FRI query term — the smallest ε
— is grindable, and it is the one mis-sized.**

**REQUIRED FIX (F2):** size against the PoW-grinding model, proven regime only:
`grind_bits + proven λ_FRI ≥ ~120`, and separately discharge the commit-phase
term (≤ 2⁻¹²⁰ at N=2²¹) with the improved bounds. Quote proven per-query =
½·log₂(1/ρ); **never** cite an up-to-capacity number. Make `grind_bits` an
explicit consensus parameter tuned jointly with difficulty. Treat
**(proof-size cap, rate ρ, per-nonce hash floor, proven λ_FRI) as a FOUR-WAY
constraint** — the memo treats them as independent, and they are not:

| ρ | proven bits/query | queries for λ_FRI=100 | proof-size | hash-floor |
|---|---|---|---|---|
| 1/2 (draft) | 0.5 | ~200 | **likely blows 256 KB** | ×1.4 |
| 1/4 | 1.0 | ~100 | ~150–250 KB | **~×1.9** |
| 1/8 | 1.5 | ~67 | bigger codeword | **~×2.4** |

At ρ=1/2 the proven-sound query count (~200) very likely **exceeds the 256 KB
cap**; lowering ρ to fit raises the per-nonce hash floor to **×1.9–×2.4**, worse
than the ×1.4 the draft assumed.

---

## 4. OPEN RISK — GEMM-dominance under the (now larger) hash floor

This is the one that cannot be settled here, and the fixes make it harder:

- The per-nonce commitment hash scales **∝ m²** while the GEMM marginal scales
  **∝ m**. So "grow m storage-free" (the marquee §7.4 knob) does **NOT** give
  free GEMM-scaling: large m makes the miner **hash-bound** and erodes the
  frontier-GEMM thesis. Compute must scale via **n** (bounded by the verify
  budget) and throughput/difficulty, not freely via m.
- The memo already concedes the baseline is "SHA/XOF-bound in practice" on H100
  at today's floor; F2's re-sizing raises the floor to ×1.9–2.4, pushing further
  into the SHA-bound regime and increasing the value a SHA-ASIC/high-clock hybrid
  can extract.
- **Verdict: GEMM-dominance is NOT provable from first principles and the
  correction moves it adversely.** It is a measurement question — the design's
  own blocking gate — that requires H100/B200 `matmul_v4_stage_bench` under the
  *corrected* floor. Two prior model-based estimates were wrong (PR #89); do not
  certify from theory. Fallback if it fails: Candidate A (digest-only full
  recompute) — zero prover overhead, GPU-class tip verify, still deterministic +
  flat.

---

## 5. Corrected construction (what the v4.4 spec must adopt)

1. **F1 — message-commitment lottery.** `matmul_digest = H(σ ‖ M)`,
   `M = Merkle(canonical m² Ĉ residues)`. Evaluation codeword + FRI live only in
   the post-win proof. Bind `M` ↔ FRI polynomial by a consistency argument.
2. **F2 — PoW-grinding-aware FRI params.** `grind_bits + proven λ_FRI ≥ ~120`
   (e.g. ρ=1/4, ~100 queries, grind_bits ≥ 30); commit-phase term ≤ 2⁻¹²⁰;
   proven per-query = ½·log₂(1/ρ) only; `grind_bits` a consensus parameter
   calibrated with difficulty; (cap, ρ, floor, λ_FRI) co-designed.
3. **Merkle + domain hygiene:** domain-separated leaf/node tags, leaf-index
   binding, power-of-two layout, canonical LE residue serialization.
4. **Determinism pins:** circle-domain coset offset, twiddle sign, interpolation
   basis, evaluation ordering, F_{q²} modulus — all byte-canonical, cross-vendor.
5. **Silicon gate (blocking):** H100/B200 measurement of per-nonce GEMM wall-time
   share under the corrected ×1.9–2.4 floor, against the PR#89 datacenter
   threshold; Candidate A as fallback.

With F1+F2 the scheme attains the property Option 4 lacked — a rigid
(header,nonce)→ticket function bound to full compute, with cryptographically
negligible (not f^k) soundness. **Do not begin §7.7 spec work until F1 and F2
are folded in and the silicon gate is scheduled.**

---

## 6. Meta-note

The three-lens split earned its keep twice (Option 4 and now ENC-SC): a single
"sound" verdict on a novel PoW commitment cannot be trusted. Every future
committed-object change should get ≥2 independent adversarial lenses plus an
external cryptographic review of the *combined* (commitment ∘ sum-check ∘
Circle-FRI ∘ Fiat–Shamir) protocol in the PoW-grinding model — component-wise
literature soundness is necessary but not sufficient.
