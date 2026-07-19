# C-15 reduction survey — cryptographic / PoW-theory named assumptions (2026-07-19)

*Wave 1 — SURVEY (crypto / PoW-theory lens).*  
*Scope: named assumptions closest to LT-C15 MatExpand Extract; map formal sketches → BTX applicability → obstructions → residual useful lemmas.*  
*Sources: `doc/btx-matmul-v4.4-lt-external-c15-packet.md`, `/tmp/c15_audit_prior_art.md`, `/tmp/c15_audit_shortcut_tmto.md`, `contrib/matmul-c15-reviewer-kit/README.md`, companions in prior-art citation list.*  
*Hard rules honored: **no C-15 closed claim**; **no height raise**; doc-only.*

---

## 0. Executive verdict

**LT-C15 does not cleanly reduce to any single named standard assumption.** Closest analogues are:

1. a **ChaCha-as-PRF / ideal-RO fragment** (necessary, insufficient for work-binding);
2. **Pearl / cuPOW transcript unpredictability** (same *meta-class*, different encoding);
3. **Ball et al. fine-grained PoW non-amortization** (I1′ spirit only; wrong task family);
4. **KW / cuPOW secret low-rank** (explicitly **uninhabitable** for public deterministic BTX).

SIS / LWE / low-rank recovery / Freivalds soundness are **components**, not full reductions. Primecoin / Equihash / RandomX are **analogous posture** (heuristic PoW hardness), not transferable theorems.

**Verdict for activation / closure:** survey-only **OPEN**. Packet §0.1 game remains the review target. Do not treat this note as PASS.

---

## 1. What would constitute a reduction (reminder)

Packet §0.1 game (fixed): adversary outputs accepting Phase-A digest (or seal if SB annex) with `Adv ≥ ε` over Freivalds false-accept while paying `≤ (1−δ)·HonestMAC(n)` exact-int MAC for MatExpand-B + `B̂·V` + combine.

A *named* reduction would bound:

```
Adv_LT-C15(A)  ≤  Adv_NamedGame(B)  +  negl(Freivalds)  +  (optional structural Adv)
```

with `NamedGame` a standard or published conjecture. **No such complete chain exists today.** Prior-art sketch:

```
Adv_LT-C15 ≤ Adv_PRF^ChaCha + Adv_ExtractStruct + Adv_Shortcut_MBv + negl(Freivalds)
```

— where `Adv_Shortcut_MBv` is currently as ad-hoc as cuPOW’s algebraic conjecture.

---

## 2. Ideal PRF / random-oracle work lower bounds

### 2.1 Formal statement sketch

**Ideal PRF.** Let `F_k : {0,1}^{in} → {0,1}^{out}` be a keyed family. Security: every PPT distinguisher with oracle access to either `F_k` (secret `k`) or a uniform random function has negligible advantage.

**Ideal / programmable RO.** Hash `H` modeled as a random oracle; query complexity `q` yields collision / preimage bounds `≈ q²/2^n` (birthday) or `q/2^n`.

**Work lower bound folklore (RO mining).** Finding `x` with `H(x) ≤ T` requires `Θ(2^λ / T)` RO queries in the classical RO model (with parallel variants under PRM / parallel RO). This is a **query** lower bound for unstructured search, not an algebraic-MAC lower bound.

**AEAD precedent (Procter ePrint 2014/613).** ChaCha20-Poly1305 reduces to “ChaCha block ≈ PRF” + Poly1305 ε-AΔU under nonce-respecting use — **not** a PoW theorem.

### 2.2 Applicability to BTX

| Fragment | Fits? |
|---|---|
| `prf_key = SHA256("BTX_MATEXPAND_PRF_V44LT" ‖ seed_W)` as CRHF / ROM domain sep | Yes (Bitcoin-family practice) |
| ChaCha20 block as PRF on distinct `(key, Nonce96, counter=remix)` | Plausible working assumption (packet F1) |
| IdealExtract ⇒ outputs look like independent M11×`{0..3}` draws | Motivates non-affinity / spectral flatten arguments |
| RO query lower bound ⇒ MatExpand MAC floor | **No** |

### 2.3 Obstruction — why PRF security ≠ PoW lower bound

1. **Wrong metric.** PRF games bound *distinguishers*; HonestMAC bounds *exact-int multiply-accumulates* of `G·W`, `Y·H`, `B̂·V`, `P·Q`. A perfect PRF still allows an adversary who never distinguishes keystreams but **rewrites Freivalds probes** through panels if Extract is affine / low-degree.
2. **Composition gap.** BTX Extract is non-AEAD: `(raw ⊕ lane, pack(i,j))` nonce packing, M11 rejection, discrete scale, remix walk — outside Procter / RFC 8439 proof scope.
3. **Ideal Extract still leaves work-binding open.** Even a random table `B̂[i,j]` kills homomorphism; producing accepting sketches cheaper than MatExpand+BV+combine is a **separate** fine-grained / no-shortcut claim (packet F2).
4. **Public seeds.** `seed_W` is consensus-derived; `prf_key` is public once `W` is fixed. PRF security is still meaningful against *forging without evaluating Extract*, but miners *legally* know the key — hardness is computational work, not key secrecy.

### 2.4 Residual useful lemma

**Lemma-shape (ideal model, not a proof of C-15):** If Extract were replaced by an ideal random function of `(key, raw, i, j)` (or ChaCha were an ideal PRF on the normative encoding), then there is no efficient *entrywise affine / degree-≤2* surrogate `f(B32)` matching Extract on dense samples with advantage ≫ Freivalds ε — matching in-tree C15-A witnesses and the kit’s expected low R². **This kills the linear reassociation class under the ideal model; it does not prove HonestMAC lower bounds.**

---

## 3. Ball–Rosen–Segev / Ball et al. PoW non-amortization

### 3.1 Formal statement sketch

**Citation pin (load-bearing):** Ball, Rosen, Sabin, Vasudevan — *Proofs of Useful Work* / fine-grained PoWs (ePrint **2017/203** → CRYPTO’18 / ePrint **2018/559** “*Proofs of Work From Worst-Case Assumptions*”). Colloquial “Ball–Rosen–…” / “Ball et al.” in PoW literature usually means this line; **Segev** co-authors related Ball–Rosen work but the PoW non-amortization theorems cited for OV/3SUM/APSP PoWs are **BRSV**.

**Sketch.** Under fine-grained hypotheses (OV, 3SUM, APSP), evaluate certain low-degree polynomials as PoW challenges. CRYPTO’18 proves an **average-case direct-sum** theorem: producing `t` accepting proofs costs roughly `t` times one proof (non-amortization), plus faster verify / ZK variants.

### 3.2 Applicability to BTX

| Aspect | Transfer |
|---|---|
| Conceptual need: many nonces ⇏ sublinear total work | **High** (I1′, Q*, batch algebra) |
| Task family: OV/3SUM/APSP polynomial evaluation | **None** — BTX prices MatExpand GEMM + sketch |
| Direct-sum theorem for `MineSlot` marginal units | **Not proved** |
| Worst-case → average-case fine-grained bridge | Not available for ChaCha∘GWH |

### 3.3 Obstruction

BRSV hardness is **problem-specific**. MatExpand Extract + Freivalds sketches are not instances of their polynomials. Importing “non-amortization” as a slogan without a direct-sum statement for `(W_B ↦ digest)` is assumption laundering.

I1′ *intentionally* amortizes template A / `U`/`V`/`P`; the priced object is nonce-fresh MatExpand-B. That is an **engineering non-amortization boundary**, not a BRSV theorem.

### 3.4 Residual useful lemma

**Design hygiene only:** treat multi-instance mining (Q* Phase A skinny grind vs Phase B seal) with an explicit amortization game — packet I1-A/B/D, SB-*, shortcut audit S9/S10. Use BRSV as **vocabulary** (“prove direct-sum or admit heuristic”), not as a cited hardness assumption for MatExpand.

**Wave 3 Gap #9 deliverable:** explicit game statement (heuristic / unproved) in
`doc/btx-matmul-v4.4-lt-c15-qstar-i1-amortization-game-2026-07-19.md`
(`BTX-I1p-QStar-DirectSum-Heuristic-v1`). Does **not** close C-15; Gap #10 KW
redesign skipped.

---

## 4. Pearl / cuPOW transcript unpredictability

### 4.1 Formal statement sketch

**Komargodski–Weinstein cuPOW** (ePrint **2025/685**, arXiv 2504.09971); Pearl NoisyGEMM instantiation.

**Shortcut class (shared with C-15 meta-class):** given clean product `AB`, compute `(A+E)(B+F)` via low-rank correction identities cheaper than full MatMul.

**Mitigation:** force miners to hash a **block MatMul transcript** (tile-level RO / Blake3 jackpot in Pearl) so outputs are unpredictable without paying for the noisy product path.

**Hardness conjecture (cuPOW):** roughly, solving / predicting under **batch low-rank random linear equations** on transcript structure is hard — **ad-hoc**, not a standard PRF.

### 4.2 Applicability to BTX

| | Pearl / cuPOW | BTX LT MatExpand |
|---|---|---|
| Priced object | Noisy dense MatMul + transcript | Thin `G·W·H` then nonlinear Extract + sketch |
| Work-binding mechanism | Transcript RO unpredictability | Extract non-homomorphism + digest lottery |
| Verifier | Product / transcript checks (+ optional ZK) | Freivalds on sketches + digest |
| Miner-chosen mats | Yes (usefulness gap) | No — seeded panels |

**Transfer strength:** **High (attack taxonomy)** / **Low–Med (protocol)**. Same reason Freivalds-alone is insufficient; different encoding.

### 4.3 Obstruction

No reduction from “break MatExpand Extract” to “break cuPOW transcript unpredictability” (or converse). Pearl’s noise is **additive low-rank secret structure**; BTX’s rank-≤`w` is **public deterministic factorization** then PRF Extract. Usefulness-gap critiques (arXiv 2606.04819) are narrative hygiene, not C-15 algebra.

### 4.4 Residual useful lemma

**Pitfall lemma (shared):** Freivalds / output-only checks prove **correctness**, not **work**. Any closing C-15 write-up should keep verify-soundness and miner-MAC lower bounds in separate games (packet already does). Transcript-unpredictability is the closest *published* “work-binding conjecture” peer — useful as a **template for stating** BTX’s `Adv_Shortcut_MBv`, not as a reduction target.

---

## 5. Komargodski–Weinstein secret low-rank (KW) — why public deterministic BTX cannot invoke it

### 5.1 Formal statement sketch

In cuPOW / Pearl, low-rank noise `(E,F)` (or equivalent secret structure) is derived so that:

- the *honest* path pays for noisy MatMul / transcript;
- an adversary who tries correction shortcuts must solve for secret low-rank factors / batch low-rank equations.

Hardness relies on the noise (or equivalent) being **unpredictable / secret relative to the clean product** in the sense of the paper’s conjecture — miners cannot freely choose structured `A,B` that collapse work without failing the transcript RO.

### 5.2 Applicability to BTX

**Direct invocation: blocked.**

BTX v4.4-LT MatExpand:

- `G,H` template-scoped, `W` nonce-seeded — **public deterministic** from consensus seeds;
- `rank(B32) ≤ w = 128` is an **unconditional public algebraic fact**, not a secret;
- Extract keys are `SHA256(tag ‖ seed_W)` — public given `seed_W`;
- design explicitly **removed** v3-style low-rank noise amortization (`nMatMulNoiseRank` retired).

### 5.3 Obstruction (hard)

You cannot claim “C-15 reduces to KW secret low-rank hardness” because the KW secret is **not present**. Publishing `G,W,H` and requiring Extract is a **different** design point: destroy usable low-rank *residue after a public factorization*, rather than hide a secret low-rank correction.

Attempting to “add KW noise” would re-open v3 amortization classes and contradict LT’s public ExactGemm + Extract posture.

### 5.4 Residual useful lemma

**Negative lemma (important for reviewers):** any argument of the form “Pearl is hard ⇒ MatExpand is hard” is invalid. Conversely, breaks of Pearl’s usefulness or ASIC story do **not** imply MatExpand shortcuts. Keep KW citations in the **taxonomy** column only.

---

## 6. SIS / LWE / low-rank recovery / Freivalds as components

### 6.1 Freivalds soundness

**Statement sketch.** For matrices over a field / ring `𝔽_q`, random probes detect `A·B ≠ C` except with probability `≤ O(1/q)` per round (classical Freivalds; SZ-style analyses). BTX: `q = 2⁶¹−1`, mainnet pin **R = 3** ⇒ soundness `~ q^{-R}` (order-of-magnitude).

**Role in C-15:** sets the **ε floor** in packet §0.1 (`ε = 2⁻⁴⁰` default above false-accept). **Never** a work lower bound.

**Residual lemma:** separate `Adv_forge_Freivalds` from `Adv_shortcut_MAC` in any reduction write-up.

### 6.2 SIS / LWE / Module-SIS/LWE

**Statement sketch.** Short integer solutions / learning with errors (and module variants) underpin lattice signatures, commitments, ZK — **in-repo** for shielded / PQ spend paths, **not** for MatExpand Extract.

**Applicability:** none as a C-15 assumption. Extract is symmetric PRF + small alphabet, not a lattice relation.

**Obstruction:** no SIS/LWE instance is posed by `B̂` or `Ĉ`.

**Residual lemma:** do not cite Dilithium/MLWE parameters as MatExpand hardness.

### 6.3 Low-rank recovery / entrywise-transform LRA

**Statement sketch.** Recovering factors of a low-rank matrix, or approximating entrywise `f(UV)`, often requires near-quadratic work for many `f` (e.g. NeurIPS 2023 entrywise-transform LRA hardness line; Simon-type warnings that shared φ preserves effective rank).

**Applicability:** **motivational** for rejecting Fold / shared-φ Extract; supports “subquadratic spectral shortcut unlikely under strong `f`.”

**Obstruction:** ChaCha+M11 is not in the polynomial / `|x|^p` class those theorems study; position salts change the model; no theorem says “ChaCha∘GWH needs `HonestMAC` MACs.”

**Residual lemma:** use as **heuristic support** for C15-A/B under ideal Extract; schedule empirical SVD / CCA probes (lattice audit follow-ups) rather than claiming a reduction.

### 6.4 Kikuchi-style spectral sparse-LWE

**Sketch.** Spectral norms distinguish planted sparse linear equations.

**Applicability:** **no direct instance** after ChaCha Extract (not a sparse LIN oracle). Residual: related-`raw` differentials along low-rank `ΔW` are a research question, not Kikuchi.

---

## 7. Other named PoW hardness frameworks (analogous posture)

| Framework | Hardness posture | Analogy to LT-C15 | Obstruction | Residual lemma |
|---|---|---|---|---|
| **Primecoin** (King 2013) | Cunningham chains / prime-form number theory; heuristic | “Useful-looking” math as PoW | Different domain; no Freivalds/Extract | Taxonomy only — usefulness ≠ work-binding |
| **Equihash** (Biryukov–Khovratovich) | Memory-hard generalized birthday / Wagner | Bind work to a structured search | Not matmul; ASIC story differs | Inspiration for **explicit cost metric** (BTX uses MAC + ExactGemm) |
| **RandomX** (Monero) | CPU/VM interpreter hardness; Trail of Bits review posture | Heuristic “no known shortcut” + empirical review | Not algebraic GEMM | Closest **process** analogue: external review + residual risk list, not a theorem |
| **scrypt / Argon2 / memory-hard RO** | Parallel RO / pebbling lower bounds | Query/memory lower bounds | BTX bottleneck is tensor MAC, not RAM-fill | Do not import pebbling bounds as MatExpand MAC bounds |
| **Bitcoin SHA256d** | RO preimage / partial inversion folklore | Lottery `H(σ‖Ĉ) ≤ target` is the **outer** lottery | Outer lottery ≠ MatExpand floor | Keep header digest lottery separate from C-15 algebra |
| **Ofelimos / Coin.AI / PAI AI-PoW** | Local search / training / NAS as mining | AI-PoW branding | Low algebraic transfer | SoK framing (ePrint 2025/1814): BTX is AI-*native* PoW, not Pearl useful-work |
| **Bitansky et al. cryptographic PoW** | Strong crypto assumptions → PoW | Existence of provable PoWs | Assumptions too strong / wrong shape for ExactGemm | Shows “provable PoW” is possible *in principle* — not a MatExpand reduction |
| **zkMatrix / zkMaP / sumcheck matmul** | PCS / IP soundness for matmul | Alternate verify stack | BTX deliberately uses Freivalds sketches | Design fork marker — changing to ZK would change assumption surface entirely |

---

## 8. Per-assumption summary table

| Named assumption / framework | Formal role vs C-15 | Applicability | Obstruction | Residual useful lemma |
|---|---|---|---|---|
| Ideal PRF / ChaCha-PRF | Fragment F1 | High for non-affinity | ≠ work lower bound; custom encoding | Ideal-model kill of affine/deg≤2 surrogates |
| Random-oracle mining bounds | Outer lottery only | Low for MatExpand MAC | Wrong metric | Separate digest lottery from GEMM floor |
| Ball et al. / BRSV non-amortization | I1′ vocabulary | Conceptual only | Wrong task family | Explicit game: `…-qstar-i1-amortization-game-…` (heuristic) |
| Pearl / cuPOW transcript unpredictability | Closest published peer conjecture | High taxonomy | Different encoding; no reduction | Template for stating `Adv_Shortcut_MBv` |
| KW secret low-rank | **Cannot invoke** | None (direct) | Public deterministic panels | Negative lemma: no Pearl⇒BTX transfer |
| Freivalds soundness | ε floor | High (verify) | Correctness ≠ work | Split forge vs shortcut advantages |
| SIS / LWE | Unrelated | None | No lattice instance | Avoid citation drift from shielded stack |
| Low-rank recovery / entrywise LRA | Heuristic support | Med | Wrong `f` class | Motivates salts; empirical SVD/CCA |
| Primecoin / Equihash / RandomX / memory-hard | Posture analogues | Low–Med process | Domain mismatch | External-review + residual-risk culture |
| Ofelimos / AI-PoW SoK | Framing | Low algebra | Different tasks | “Useful” vs “AI-native” hygiene |
| ZK matmul IPs | Alternate design | Low for current LT | Not deployed path | Documents non-goal |

---

## 9. Implications for packet / firm review (non-claiming)

1. Reviewers should **reject** “ChaCha is a PRF ⇒ C-15 PASS.”
2. Reviewers should **reject** “cuPOW/KW hard ⇒ MatExpand hard.”
3. A credible closure needs **explicit games** for Extract-structure + no-shortcut (prior-art §6), with FAIL/PASS/INCONCLUSIVE per packet §0.1 — still not a height raise.
4. BRSV-style non-amortization language belongs in **I1′ / Q*** write-ups as a *desired theorem shape*, not a cited assumption.
5. In-tree witnesses + reviewer kit remain **witnesses**.

---

## 10. Explicit non-claims

- C-15 is **not** cryptographically closed.
- This survey does **not** authorize `nMatMulDRLTHeight` changes.
- No silicon nonce/s invented or implied.
- Mapping named assumptions shows **proximity and gaps**, not a completed reduction.

---

## 11. Sources

- `doc/btx-matmul-v4.4-lt-external-c15-packet.md` (§0.1, §1–§2, §8)
- `/tmp/c15_audit_prior_art.md`, `/tmp/c15_audit_shortcut_tmto.md`, `/tmp/c15_audit_lattice_spectral.md`
- `contrib/matmul-c15-reviewer-kit/README.md`
- Procter ePrint 2014/613; RFC 8439
- Ball et al. ePrint 2017/203, 2018/559
- Komargodski–Weinstein ePrint 2025/685; Pearl whitepaper; usefulness-gap arXiv 2606.04819
- Freivalds 1979; entrywise-transform LRA (NeurIPS 2023 line); Kikuchi ePrint 2026/614
- Primecoin; Equihash; RandomX; Ofelimos ePrint 2021/1379; PoUW SoK ePrint 2025/1814

*End of Wave-1 crypto/PoW reduction survey. C-15 remains OPEN.*
