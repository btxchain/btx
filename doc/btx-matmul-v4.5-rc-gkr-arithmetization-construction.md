# ENC_RC winner-GKR arithmetization — complete construction and soundness (WS2) — 2026-07-21

*Companion soundness table: `doc/btx-matmul-v4.5-rc-gkr-soundness-table-2026-07-21.md`.
Supersedes the gap table in `doc/btx-matmul-v4.5-rc-arithmetization-completeness-2026-07-20.md`
(whose "CLOSED (scaffold)" entries are reverted to honest status by this document).*

**Consensus posture (unchanged).** The int64 reference
(`RecomputeResidentCurriculumReference`, `RecomputeCoupledPuzzleReference`) remains the sole
consensus authority. `kRCGkrFormalSoundnessReady=false` hard-disables the arbiter
(`EnvRCGkrArbiterEnabled` ignores `BTX_RC_GKR_ARBITER`); all activation heights stay
`INT32_MAX`. G1–G5 remain OPEN/PARKED until succinct bindings + external audit.
Composed bound writeup: `doc/btx-matmul-v4.5-v7-composed-soundness-bound-2026-07-22.md`.
This document is the mathematics that must be implemented before any audited cutover can even
be discussed. Nothing here weakens or replaces exact replay.

---

## 0. Headline findings (read first)

> **UPDATE (2026-07-22, margin restoration — supersedes the parameter numbers
> below and in §2/§8/§9):** the fold now ships **Q = 128** (`kRCFriNumQueries`;
> `FriSoundnessBoundBits() = 76`, real 76.80) and the separation bounds are
> re-derived over the **F_{p^3} challenge field** (|K| ≈ 2^192; Fp3 =
> Fp[x]/(x³−7) per item 3, implementation pending — see INTEGRATION_REPORT.md
> "Fp2 → Fp3 challenge sites"). Composed bound: **≈ 2^-76.8, margin ≈ 12.8 bits
> over 2^-64** (was ≈ 2^-65.7 / 1.8 bits). Full old-vs-new table: Appendix INT.
> The body text below retains the historical Q=116/Fp2 numbers.

1. **The current `VerifyWinnerProof` (proof v6) is, against a Byzantine prover, a plain
   SHA256d PoW with extra steps.** A cheating prover who grinds arbitrary 32-byte strings as
   `round_roots` until `SHA256d(kRCEpisodeTag ‖ roots) ≤ target` can fabricate *all* layer
   wires (any self-consistent `A', B', Y' = A'·B'`), run the honest prover code on the
   fabricated wires, and pass every check in `VerifyWinnerProof` **with probability 1**,
   having done zero episode work. Proof: §9, Forgery F0. Every "CLOSED (scaffold)" claim of
   G1–G3 in the M7+ audit is therefore reverted; the scaffold is *format*-complete, not
   *soundness*-complete. The five relations below are what actually closes it.
2. **Nothing is fundamentally unconstrainable.** All five relations are soundly
   constrainable inside the existing sumcheck + LogUp + FRI system. Shipped
   **G1–G5 status remains OPEN/PARKED** until those bindings land and independent
   malicious constructors are rejected under PCS/AIR (not merely under native
   grounding). The honest cost is that relation (3) (Extract) and the trace
   boundary of relation (2) require **in-circuit AIRs for ChaCha20 and SHA-256
   compression** (≈ 2^42–2^43 lookup rows at consensus dims). That is laborious,
   not impossible; no obstruction theorem exists (§11).
3. **Three quantified corrections to the shipped parameter story:**
   - **Seven separate FRI instances do not clear 2^-64.** Each instance is 2^-65 after
     grinding (`FriSoundnessBoundBits()=65`); the union over the 7 instances in
     `RCGkrProof` is ≥ 7·2^-65 ≈ **2^-62.2**. Fix: one *batched* FRI over a random linear
     combination of all columns (§2.3), or Q ≥ 128 per instance.
   - **A single LogUp α over Fp2 fails.** With grinding budget 2^40 and target 2^-64, a
     single α tolerates only N ≤ 2^(128-40-64) = **2^24** summands. The Extract relation
     has ≥ 2^28.4 tiles bare-minimum and ≈ 2^43 rows with the full PRF AIR. Hence over Fp2
     the α-challenge **must be amplified to two independent challenges** (soundness
     (N/|F|)² = 2^-170), or the protocol must move to Fp3 (§5.6). Fp2+dual-α is the
     recommended path; Fp3 = Fp[x]/(x³−7) is well-defined (7 is a cubic non-residue mod p,
     verified: 7^((p−1)/3) ≠ 1 mod p) but unbuilt.
   - **A single DEEP/OOD point over Fp2 fails for large columns.** deg ≤ 2^24 is the
     single-point ceiling by the same 128−40−64 arithmetic; consensus columns reach 2^28.
     Fix: two OOD points per DEEP claim (§2.2), giving (2^30/2^128)² ≈ 2^-196.
4. **Goldilocks two-adicity caps FRI columns at 2^28 coefficients** (LDE = 16·2^28 = 2^32 =
   the largest power-of-two subgroup of F_p^×). The concatenated trace is 2^33.4 cells at
   consensus dims, and a single QKt output alone is 2^28.6. The commitment layer is
   therefore necessarily **multi-column** (§2.1); the current single-vector
   `FriCommitAndFold(trace_evals…)` cannot even run at consensus dims.
5. Composed bound of the full construction (§8): **ε_total ≤ 2^-65 + 2^-74 ≈ 2^-64.9**,
   dominated by the single batched-FRI query term. It clears 2^-64 with ≈ 0.9 bits of
   margin; raising Q from 116 to 128 buys ~11 bits of margin at +10% query cost and is
   recommended before cutover.

---

## 1. Preliminaries

### 1.1 Fields

- Base field **F_p**, p = 2^64 − 2^32 + 1 (Goldilocks), log2 p = 63.99999999966.
  F_p^× has 2-adicity 32: max power-of-two subgroup order 2^32.
- **Fp2** = F_p[x]/(x²−7), |Fp2| = p² ≈ 2^128 (7 is a QNR; `matmul_v4_rc_gkr_field_ext.h`).
- **Fp3** = F_p[x]/(x³−7), |Fp3| = p³ ≈ 2^192 (7 is a cubic non-residue and 3 | p−1, so
  x³−7 is irreducible). *Unbuilt*; needed only if the dual-α amplification of §5.6 is
  rejected.
- All Fiat–Shamir challenges live in Fp2 (or Fp3 if chosen). Wire values are int64/int8
  embedded via `FromSigned2` (injective: |values| < 2^62 ≪ p).

### 1.2 MLE and eq-kernel conventions

For v ∈ F^(2^ν) indexed by x ∈ {0,1}^ν (little-endian bits, matching `EqFactor`),
the multilinear extension is ṽ(r) = Σ_x v_x·eq(r,x), eq(r,x) = Π_b (r_b x_b + (1−r_b)(1−x_b)).
A matrix M ∈ F^(m×n) padded to 2^(ν_i)×2^(ν_j) row-major has M̃(r_i, r_j) as in
`MleEvalMatrix`. **Transpose is free:** M̃ᵀ(r,s) = M̃(s,r). **Single-coordinate index-XOR
is free:** if w_x = v_(x⊕e_b) then w̃(r) = ṽ(r₁,…,1−r_b,…,r_ν). **Bit-rotation of the
index is free:** a rotation permutes the coordinates of the evaluation point. These three
facts make transposed operands (Kᵀ, Wᵀ, Gᵀ) and the coupled butterfly stages (§7.4)
evaluable against a *single* commitment with no extra committed data.

### 1.3 Coefficient-basis commitment and the eq-kernel univariate

Commit v as the univariate P_v(X) = Σ_{i<2^ν} v_i X^i (this is exactly what
`FriCommitAndFold(coeffs…)` does today: coeffs = wire values). Define the **eq-kernel**

  q_r(X) := Π_{b=0}^{ν−1} ((1−r_b) + r_b·X^(2^b)),  deg q_r = 2^ν − 1.

Its coefficient at X^i is eq(r, bits(i)), hence ṽ(r) = ⟨coeffs(P_v), coeffs(q_r)⟩.
The verifier can evaluate q_r at any point in O(ν) multiplications.

**Lemma 1.1 (inner product over a subgroup).** Let D ⊂ F^× be a multiplicative subgroup,
|D| = N = 2^ν·B' ≥ 2^ν. For deg P, deg q < N:
Σ_{x∈D} P(x)·q(x^{-1}) = N·⟨coeffs(P), coeffs(q)⟩.
*Proof.* Σ_{x∈D} x^(i−j) = N iff i ≡ j (mod N), else 0; with both degrees < N, i ≡ j ⇒
i = j. ∎

**Lemma 1.2 (univariate sumcheck; Aurora, Ben-Sasson–Chiesa–Riabzev–Spooner–Virza–Ward,
EUROCRYPT 2019, §5 / Lemma 5.4 as used there).** For h ∈ F[X], deg h < 2N, and subgroup D
of order N: Σ_{x∈D} h(x) = σ iff there exist g (deg g < N) and f (deg f < N−1) with
h(X) = g(X)·Z_D(X) + X·f(X) + σ/N, Z_D(X) = X^N − 1. ∎

### 1.4 Standard soundness results used (exact statements)

- **S1 — Multilinear sumcheck** (Lund–Fortnow–Karloff–Nisan, JACM 1992): for a ν-round
  sumcheck on a degree-≤d-per-variable claim, a false claim survives with probability
  ≤ ν·d/|F| over the verifier's challenges. Here d = 2 (product of two multilinears in
  the bound variable), so ε_sc = 2ν/|F|; per-round (round-by-round) error 2/|F|.
- **S2 — Schwartz–Zippel**: a nonzero ℓ-variate polynomial of total degree d vanishes at a
  uniform point of S^ℓ with probability ≤ d/|S|.
- **S3 — LogUp / log-derivative lookup** (U. Haböck, ePrint 2022/1530, Lemma 5): for
  sequences (w_i)_{i<N_w}, table (t_j)_{j<N_t} with multiplicities m_j ∈ F, char(F) > N_w:
  {w_i} ⊆ {t_j} as multisets with the claimed multiplicities **iff**
  Σ_i 1/(α−w_i) = Σ_j m_j/(α−t_j) as rational functions of α. If the multiset relation
  fails, the equality holds at uniform α ∈ F for at most (N_w + N_t)/|F| of the α's
  (numerator of the difference is a nonzero polynomial of degree < N_w + N_t).
  Note char(F) = p ≈ 2^64 > N ≈ 2^43 — multiplicity wraparound is impossible. ✔
- **S4 — FRI, unique-decoding regime** (Ben-Sasson–Bentov–Horesh–Riabzev, ICALP 2018, as
  parameterized in `matmul_v4_rc_fri.h`): rate ρ = 1/16, unique-decoding proximity
  parameter α = 17/32 (θ = 15/32 < (1−ρ)/2). A word δ-far (δ ≥ 15/32) from RS[N, ρ]
  passes Q i.i.d. queries with probability ≤ (17/32)^Q; Q = 116 ⇒ 2^-105.85; the shipped
  accounting subtracts the g = 40 grinding budget: `FriSoundnessBoundBits() = 65`. The
  fold-commit phase error (per fold challenge) is ≤ N_lde/|F| per round, absorbed into the
  FS sum in §8. We use FRI **strictly as shipped** — no redesign.
- **S5 — DEEP/OOD** (Ben-Sasson–Goldberg–Kopparty–Saraf, "DEEP-FRI", ePrint 2019/336;
  DEEP-ALI composition as in StarkWare's ethSTARK documentation v1.2): after committing P
  and sampling z outside the LDE domain D, the claim v = P(z) backed by the quotient
  Q_z = (P−v)/(X−z), FRI-tested and opened at the query sites with the identity
  P(x) = Q_z(x)(x−z)+v, binds v to the unique codeword within the unique-decoding radius,
  except with probability ≤ d_max/(|F|−|D|) over z (the bad-z set where two distinct
  degree-<d_max candidates agree). s independent OOD points give (d_max/(|F|−|D|))^s.
- **S6 — Fiat–Shamir of round-by-round-sound protocols in the ROM**
  (Ben-Sasson–Chiesa–Spooner, TCC 2016 (BCS); Canetti et al., STOC 2019;
  Chiesa–Manohar–Spooner, and the grinding convention of ethSTARK): an adversary making
  q_H random-oracle queries breaks FS-compiled soundness with probability
  ≤ q_H·ε_rbr + q_H²/2^256 (hash collisions). **Repo convention adopted throughout:**
  q_H = 2^g = 2^40, and every FS term must therefore carry ≥ 104 pre-grinding bits to
  net 2^-64. This matches how `FriSoundnessBoundBits()` already subtracts 40.
- **S7 — Thaler's matmul sumcheck** (J. Thaler, "Time-optimal interactive proofs for
  circuit evaluation", CRYPTO 2013, §4): the claim Ỹ(r_i,r_j) = Σ_{k∈{0,1}^{ν_k}}
  Ã(r_i,k)·B̃(k,r_j) is a ν_k-round degree-2 sumcheck; this is exactly `ProveProductK` /
  `VerifyProductK`.

### 1.5 The ground-truth function f (immutable)

f is the int64 episode of `matmul_v4_rc.cpp`: per round r ∈ [0, R): seeds
σ_r = SHA256("BTX_RC_ROUND_V1" ‖ (r=0 ? sigma : root_{r−1}) ‖ le32(r)); operands
Q,K,V,X₀,W_l,G_L expanded by `ExpandMxDequantInt8` (ChaCha-keyed MX rejection sampling);
layers in the canonical order

  **QKt → SV → Fwd(0..L−1) → [Bwd(l), Wgrad(l)] for l = L−1..0**

each layer = exact int64 GEMM (+ residual add X_l for Fwd), then
`ExtractMXMatrixInt64(prf, ·)`; the round stream (Z ‖ per-layer X_{l+1} ‖ G_l ‖ D_l int8
bytes, `kRCSegmentLeavesEnabled=false` layout) is Merkle-ized by the tagged SHA256d
tile-tree (`RoundMerkleStream`, T_leaf = 1024, leaf tag 0x00, node 0x01, pad 0x02) into
root_r; digest = SHA256d("BTX_RC_EPISODE_V1" ‖ root_0 ‖ … ‖ root_{R−1}).
Consensus dims: R=4, d_head=128, n_q=512, n_ctx=786432, L=16, d_model=4096, b_seq=16384.
Layer count 4·(2+3·16) = 200. Trace cells N_Y = 11,274,551,296 ≈ 2^33.39; Extract tiles
N_T = N_Y/32 ≈ 2^28.39; PRF-expanded operand cells ≈ 2^31.17.

---

## 2. The commitment layer (used by every relation)

### 2.1 Column decomposition (forced by 2-adicity)

Fix κ = 2^28 (max coefficients per column: LDE 16·2^28 = 2^32 = max 2-adic subgroup).
The **global witness** is a list of columns C_1,…,C_W, each C_i ∈ F_p-embedded Fp2 vectors
of length ≤ κ, comprising, in the canonical layout Λ(params) (§4):

- T-columns: per (round, kind, layer) the GEMM output Y (int64), split into ≥⌈|Y|/κ⌉
  chunks (QKt Y = 2^28.58 → 2 chunks; all others fit in one);
- E-columns: extract_in (= Y or Y+residual for Fwd) where distinct from Y — for Fwd only
  the residual is already a committed operand (X_l), so extract_in is *not separately
  committed*: the linear constraint acc = Y + X_l is enforced at evaluation points (G5);
- O-columns: extract_out / operand tensors (int8) — one committed copy per *distinct*
  tensor (X_l, S, Z, G_l, D_l, W_l, Q, K, V), **never duplicated per use**; transposed uses
  read the same column via §1.2;
- A-columns: the Extract/expansion AIR trace (§5) and hash AIR trace (§6.3);
- L-columns: LogUp inverse and multiplicity columns (§5.5).

Fixed lookup tables (mantissa-16, xor-256, range-2^16, SHA/ChaCha helper tables) are
**preprocessed**: their commitment roots are consensus constants recomputed once by any
verifier build (they are tiny), not prover data.

### 2.2 Batched FRI with dual-OOD

One FRI instance for the whole proof:

1. Prover Merkle-commits each column's LDE (roots ρ_1..ρ_W absorbed).
2. FS challenge λ ∈ Fp2; define P* = Σ_i λ^{i−1}·P_{C_i} (degrees aligned by chunk;
   shorter columns are degree-shifted by multiplying by X^{κ−len} — the standard
   maximal-degree-enforcement trick, so every column is simultaneously degree-checked).
3. FS challenges z_1, z_2 ∈ Fp2 \ D (dual OOD). Prover sends claimed evaluations of
   *every column* at z_1, z_2 (these double as the openings all relations consume, via
   the evaluation argument of §2.4) and commits the DEEP quotients
   (P* − P*(z_s))/(X − z_s), s = 1,2 (batched into P* with fresh FS weights).
4. Run the shipped FRI fold/query machinery (`FriCommitAndFold` internals) once on the
   batched word, Q = 116, g = 40. Query-site openings check the DEEP identities for both
   z_1, z_2 and the per-column consistency P*(x) = Σ λ^{i−1} P_{C_i}(x) against the
   column Merkle paths at the queried indices.

**Theorem 2.1 (batched commitment binding).** Except with probability
ε_commit ≤ ε_FRI + 2^40·[ (W+2)/|Fp2| + (2κ/(|Fp2|−2^32))² ] + ε_hash, after step 4 every
committed column is within the unique-decoding radius of a unique polynomial of degree
< κ, and every claimed pair (C_i(z_1), C_i(z_2)) equals that polynomial's true values.
Here ε_FRI = 2^-65.85 (S4, post-grinding), the (W+2)/|Fp2| term is the RLC batching
collision (S2 applied to the λ- and quotient-weight polynomials), and the squared term is
the dual-OOD bad-point set (S5). With W ≤ 2^11: ε_commit ≤ 2^-65.85 + 2^-76 + ε_hash.
*Proof sketch.* If some column is outside the radius, the RLC is outside except for ≤
(W−1) bad λ per distinct far column (S2 on the λ-polynomial of degree W−1 whose values
are distances); FRI then rejects except 2^-105.85 (S4). If all are close, decode to unique
polynomials; a wrong claimed evaluation at z_s makes the DEEP identity fail on > θ of D
unless z_s falls in the agreement set of two distinct low-degree polynomials, density
≤ 2κ/(|F|−|D|) per point, squared for both points. ∎

**Why dual OOD:** single-point gives 2κ/|Fp2| ≈ 2^-99 pre-grinding → 59 bits net < 64.

### 2.3 Why batching is mandatory, not cosmetic

The shipped proof carries 7 independent FRI instances (a, b, trace, lookup, table, inv, r).
Each contributes 2^-65 after grinding; the adversary attacks the weakest one of its
choice, so the union bound is ≥ 7·2^-65 ≈ 2^-62.2, **missing the 2^-64 target**. A single
batched instance restores the 2^-65 floor (and shrinks proof bytes ~7×). Alternative:
keep 7 instances at Q = 128 (76.8 bits each, union 2^-74) — strictly worse on bytes.

### 2.4 Evaluation argument (MLE opening against the batched commitment)

All relations reduce to claims "ṽ(r) = c" for committed columns v and FS-derived points r.
Batch all such claims (there are ≤ a few thousand) as follows. For each claim, by §1.3 it
is ⟨coeffs(P_v), coeffs(q_r)⟩ = c. Take FS weights μ_1..μ_M and prove the single aggregated
inner product Σ_m μ_m ⟨P_{v_m}, q_{r_m}⟩ = Σ_m μ_m c_m via Lemma 1.1 + Lemma 1.2:

- h(X) := X · (Σ_m μ_m P_{v_m}(X)·q*_{r_m}(X)) with q*_r(X) = X^{κ−1} q_r(1/X)
  (coefficient-reversed kernel; verifier evaluates q_r(x^{-1}) directly in O(ν)),
- prover commits f, g of Lemma 1.2 as two more columns *inside the same batched FRI*
  (second commitment epoch: commit-then-challenge order is λ, z after f,g roots),
- verifier checks the Lemma 1.2 identity at z_1, z_2 and at every FRI query site, using
  the already-opened column values and its own O(ν) evaluations of q*_{r_m}.

**Theorem 2.2 (evaluation binding).** Conditioned on Theorem 2.1, a set of claims
containing at least one false ṽ(r) ≠ c passes with probability
ε_eval ≤ 2^40·[ (M−1)/|Fp2| + (2κ/(|Fp2|−2^32))² ] ≤ 2^-76 for M ≤ 2^12.
*Proof.* If some claim is false, the aggregated inner product is wrong except for ≤ M−1
bad μ (S2). A wrong σ in Lemma 1.2 makes h − g·Z_D − X·f − σ/N a nonzero polynomial of
degree < 2κ; the dual-OOD check catches it as in Theorem 2.1. Query-site checks bind the
identity to the committed words per S5. ∎

(Alternative with identical interface: BaseFold (Zeilberger–Chen–Fisch, CRYPTO 2024)
multilinear-PCS mode of FRI. The Aurora-style argument above is chosen because it reuses
`FriCommitAndFold` unmodified.)

### 2.5 Padding constraint (anti-smuggling)

Committed columns are zero-padded to powers of two, but MLE claims range over the full
padded cube, so **unconstrained pad cells are attack surface** (Forgery F-pad, §9). For
each column with logical length ℓ < 2^ν: verifier draws ρ, computes natively the O(ν)
closed form of the MLE of the suffix indicator 1_{[ℓ,2^ν)}, and the prover proves
Σ_x 1_{≥ℓ}(x)·eq(ρ,x)·v(x) = 0 by a ν-round degree-3 sumcheck ending in one v-opening
(folded into §2.4). A nonzero pad cell makes the masked multilinear nonzero, caught except
with 3ν/|Fp2| + ε(opening).

---

## 3. Relation (1): A/B commitment + opening bound to `final_eval`

### 3.1 Construction

Per layer ℓ (dims m,n,k), with Ã, B̃ the MLEs of the *operand columns designated by the
layout Λ* (transposes handled per §1.2 — e.g. for QKt, B̃(k̂,ĵ) := K̃(ĵ,k̂)):

1. Verifier derives r_i ∈ Fp2^{ν_i}, r_j ∈ Fp2^{ν_j} from FS **after** all column roots
   (already the case: `fri_precommit` precedes the per-layer loop).
2. The layer claim c_ℓ is **not prover-supplied**: it is bound to the trace by relation
   (2): c_ℓ = Ỹ_ℓ(r_i,r_j) as an opening claim against the Y-columns (§2.4).
3. Run `ProveProductK`/`VerifyProductK` (S7) on c_ℓ, producing r_k ∈ Fp2^{ν_k} and the
   chain-end value gf_ℓ.
4. **New binding (the missing piece):** the prover asserts a_ℓ = Ã(r_i,r_k),
   b_ℓ = B̃(r_k,r_j); both are queued as §2.4 opening claims against the *committed*
   operand columns; the verifier checks algebraically
   **gf_ℓ = a_ℓ · b_ℓ** and rejects otherwise. `final_eval` ceases to be a free proof
   field; it is definitionally a_ℓ·b_ℓ.

The vestigial `a_root`/`b_root` (hashes of per-layer operand copies, never opened) are
deleted; operands live once in the batched commitment.

### 3.2 Theorem R1

**Theorem 3.1.** Fix a layer ℓ and condition on Theorems 2.1/2.2 (openings correct).
If c_ℓ ≠ Σ_k Ã(r_i,k)B̃(k,r_j) (sum over the Boolean cube), the verifier accepts the
layer with probability ≤ **2·ν_k / |Fp2|** over the sumcheck challenges (S1/S7, d=2);
ν_k ≤ 20 (SV layer, k = 786432), so ≤ 2^-122.7 per layer, round-by-round 2/|Fp2| = 2^-127.
Consequently, a `final_eval` not equal to the true product Ã(r_i,r_k)·B̃(r_k,r_j) of the
*opened committed* values is rejected with probability 1 (it is an algebraic identity
check), and a passing transcript with a wrong claim c_ℓ requires the 2ν_k/|Fp2| event.
Unconditionally: ε_R1(ℓ) ≤ 2ν_k/|Fp2| + ε_commit + ε_eval.
*Proof.* Standard sumcheck extraction: if the claim is false and every round's
g^(t)(0)+g^(t)(1) = expected holds, then by induction some round has the prover's g^(t) ≠
the true partial-sum polynomial (degree 2), and the challenge avoids their agreement set
except w.p. 2/|Fp2|; if all challenges avoid it, gf_ℓ ≠ Ã(r)·B̃(r), and step 4's identity
check fails because a_ℓ, b_ℓ are the true values by Theorem 2.2. ∎

### 3.3 Recorded attacks (all fail)

- *Free-final_eval attack (works today, F3 in §9):* supply arbitrary sumcheck messages
  and set `final_eval` to the chain-end value — no longer possible: chain-end must equal
  a product of two bound openings.
- *Different-low-degree-operand attack:* commit A' ≠ A; openings then bind to A', but
  relation (2)/(3) ground A' to extract_out of the producing layer / PRF expansion —
  contradiction except with the relation-(2)/(3) errors.
- *Far-word attack:* operand word not low-degree → Theorem 2.1 (FRI).
- *Claim-shift attack:* attack c_ℓ instead — deferred to relation (2), which is exactly
  why R1 alone is not enough (composition in §8).

---

## 4. Relation (2): claim-to-trace binding (wiring) and Relation (4): canonical sequence

These are one mechanism and are presented together; (4)'s theorem is §4.4.

### 4.1 The global trace MLE and the layout map

Define the layout Λ(params): a *verifier-computable* function that enumerates the
canonical layer sequence

  ℓ = 0..R·(2+3L)−1 ↦ (r, kind, l) in the order QKt, SV, Fwd 0..L−1, (Bwd l, Wgrad l)
  for l = L−1..0, per round r,

and assigns to each layer: (i) dims (m,n,k) as fixed functions of params (the existing
M7 table), (ii) the identity of its operand tensors as *references into the column list*
(e.g. operand A of Fwd(r,l) *is* column O[X_{r,l}]; operand B of Bwd(r,l) *is* column
O[W_{r,l}]; operand A of Wgrad(r,l) is the transpose view of O[G_{r,l+1}]), and (iii) the
offsets of its Y chunks. The global trace T̃ is the tuple of column MLEs under Λ; no
separate "concatenated" polynomial is needed (concatenation ≥ 2^33 cells is impossible
per §2.1 anyway, and slicing via Λ is strictly stronger: it *is* the wiring predicate).

**The proof format change that makes ordering non-forgeable:** the proof no longer
carries (kind, round, layer, m, n, k) per layer as prover data. The *verifier* iterates
Λ(params) and processes layer ℓ's sumcheck block in that order. The prover has no
ordering degrees of freedom at all.

### 4.2 Per-layer binding

For each ℓ in Λ-order, after drawing (r_i, r_j):

- **Output binding:** claim c_ℓ := Ỹ_ℓ(r_i,r_j) via §2.4 openings of the Y-chunk columns
  (a 2-chunk Y is glued by one extra top-level variable: Ỹ(x̂, top) with the verifier
  folding the two chunk openings with (1−r_top), r_top).
- **G5 residual (Fwd):** acc_ℓ(r) = c_ℓ + X̃_l(r_i,r_j), the latter an opening of the
  *same column* used as operand A — no free `residual_mle` field remains.
- **Extract linkage:** the Extract AIR of §5 consumes acc/Y cells and produces
  extract_out cells *by column reference*, so "the extract input of layer ℓ is the GEMM
  output of layer ℓ" is definitional (same column), not asserted.
- **Cross-layer wiring:** "operand A of SV(r) = extract_out of QKt(r)" etc. is
  definitional (same column reference in Λ). The only *proved* facts are (a) each column
  is unique-decodable (Thm 2.1), (b) openings are true (Thm 2.2), (c) AIR constraints
  hold (§5–6).
- **Round chaining boundary:** σ_r-chain and prf keys are verified natively
  (O(R + R·L) SHA256 calls); root_r is bound to the extract_out columns by the in-circuit
  tile-tree of §6.3; digest = SHA256d(tag ‖ roots) natively.

### 4.3 Theorem R2 (with proof that root-absorption is insufficient)

**Insufficiency lemma.** Absorbing per-layer roots/commitments into FS (the v6 design)
binds *challenges* to the prover's chosen data but binds the data to *nothing*. Formally:
for the v6 verifier there exists a prover P* (Forgery F0, §9) whose accepted transcripts
carry layer wires with A'B' ≠ any sub-computation of f(header), accepted with probability
1. Hence no theorem of the form "accept ⇒ trace-consistent except negl" holds for v6. ∎

**Theorem 4.1 (layer-to-layer reduction).** In the §4.1–4.2 construction, condition on
Theorems 2.1/2.2 and the AIR relations (§5–6). If any layer's committed Y differs (as a
vector over its logical cells) from ExactGemm of its Λ-designated operand columns (+
residual for Fwd), then the verifier rejects except with probability
ε_R2 ≤ Σ_ℓ 2ν_k(ℓ)/|Fp2| + (openings, already counted)
    ≤ 2·2540/|Fp2| ≈ 2^-115.7 (total sumcheck rounds Σν_k = 2540 at consensus dims).
*Proof.* Fix the first Λ-layer ℓ* with wrong Y. Its operands are earlier columns
(correct by minimality + AIR grounding of leaf operands to seeds, §5.7) or PRF
expansions. Wrong Y ⇒ Ỹ(r_i,r_j) ≠ Σ_k ÃB̃ for all but ≤ (ν_i+ν_j)/|Fp2| of the (r_i,r_j)
(S2 on the difference multilinear — absorbed in the same union) ⇒ Theorem 3.1 event. ∎

### 4.4 Theorem R4 (canonical sequence)

**Theorem 4.2.** Any accepted proof corresponds to the exact canonical sequence
round → phase → layer → Extract → next-state of §1.5. Reordered, repeated, or omitted
layers/rounds/barriers are rejected with probability 1 (deterministically), because
(i) the verifier itself enumerates Λ(params) — the proof cannot express a permuted or
padded sequence; (ii) layer count, dims and operand identities are outputs of Λ, not
inputs from the proof; (iii) round count = |round_roots| is fixed by
digest = SHA256d(tag ‖ roots) (native) and R = params.rounds (native param equality,
arbiter F3); (iv) omission/forgery of the *content* behind a root reduces to breaking
the §6.3 hash binding (ε_hash) or the R2 bound.
For the AIR-internal step ordering (Extract sampler), the transition constraints of §5.4
(pos monotonicity, (32−pos)·inv = 1, final pos = 32) reject early-stop/registration
deviations deterministically once the committed AIR columns are unique-decoded; the
residual probability is the shared ε_commit + ε_eval. ∎

*Remark (transition-polynomial form).* Where an explicit boundary/transition polynomial
over the layer index is preferred (e.g. for an AIR-style implementation), encode the
Λ-enumeration as a step counter s with fixed successor s' = s+1, selector columns
(is_qkt, is_sv, is_fwd, is_bwd, is_wg, l-counter) whose values at each s are *preprocessed
consensus polynomials* (verifier-derivable), and boundary constraints s_first = 0,
s_last = R(2+3L)−1. Since the verifier can evaluate these preprocessed selectors natively
at any point in O(log) time, this adds no committed data and no soundness term beyond S2
on the constraint composition, and is exactly equivalent to §4.1.

---

## 5. Relation (3): the complete Extract lookup relation

### 5.1 What Extract actually is (from the immutable reference)

Per tile τ = (layer ℓ, row i, block bj) on 32 int64 inputs y_0..y_31
(`ExtractMXTileInt64`):

- e_τ = SHA256("…MX_SCALE…" ‖ prf_ℓ ‖ le32(i) ‖ le32(bj))[0] & 3 ∈ {0..3}.
- keystream: ChaCha20 key = prf_ℓ, nonce96 = (bj ⊕ 'MXBL', (i≪32)|bj), block counter =
  remix = 0,1,…; 64-byte blocks → nibble stream κ_0, κ_1, … (low nibble first).
- rejection sampler: state pos ∈ [0,32], per candidate nibble c:
  u = MixBits(y_pos): u = low32(y) if y ∈ [−2^31, 2^31), else low32 ⊕ high32 of the
  two's-complement 64-bit pattern; h = ((u·0x9E3779B9) mod 2^32) ≫ 28;
  mixed = κ_c ⊕ h; (acc, μ) = MantissaTable[mixed] (11 of 16 accepted, μ ∈ M11);
  on accept: mantissa[pos] := μ, pos++.
- output: out[t] = μ_t · 2^{e_τ} ∈ [−48, 48].

**Consequence (this kills the "canonical table" reading):** the input→output map is a
*keyed* function whose key (prf_ℓ, i, bj) varies per tile, with an int64-domain per
element and data-dependent candidate consumption. There is no fixed canonical table t
with committed multiplicities such that "w ∈ t" expresses out = Extract(in). Any sound
LogUp use must apply lookups only to the genuinely tabular *sub-relations* (mantissa map,
4-bit XOR, range checks) inside an AIR that computes the PRF, exactly as below.

### 5.2 Vacuity of the v6 "virtual table" (theorem)

**Theorem 5.1 (the shipped G3 check has zero soundness).** In proof v6 both
`witness_keys` and `table_keys` are prover-computed; the verifier checks only equality of
their FRI roots/DEEP values and the equality of two prover-computed fractional sums. A
cheating prover who sets witness := table := (any self-consistent vector) — in particular
one derived from a *wrong* extract_out — satisfies every verifier equation identically.
Rejection probability of a forged Extract witness in v6: **0**. Moreover, even with an
honestly-fixed table, **aggregate-sum equality alone does not prove the relation**: by S3
the sums only certify *multiset inclusion of keys*; without (a) a binding from keys to
the committed in/out columns, (b) index/position binding, and (c) the PRF computation,
the statement "out = Extract(in) at each position" is not implied — e.g. permuting
(in,out) pairs across positions with equal keys, or reusing one valid pair with
multiplicity, preserves both sums. ∎

### 5.3 Sub-relation inventory (all lookups are against fixed preprocessed tables)

- **T_M (16 rows):** (nib, acc, μ) — the `MantissaTable` graph.
- **T_X (256 rows):** (a, b, a⊕b) for 4-bit a,b.
- **T_R16 (2^16 rows):** range table for 16-bit limbs.
- **T_B (256 rows):** byte range/decomposition helper.
All four are consensus constants; verifier recomputes their commitment roots at build
time (they are ≤ 2^16 rows). *The table side of every LogUp instance is therefore not
prover data* — this is what restores meaning to S3.

### 5.4 The Extract AIR (constraint system)

Columns per tile τ (padded/concatenated across tiles into §2.1 A-columns; all row
indices below are AIR-trace rows, FS-independent):

Sampler rows c = 0..C_τ−1 (candidate order):
- (C-E1) keystream binding: κ(c) equals nibble (c mod 128) of ChaCha block (τ, ⌊c/128⌋)
  — LogUp key (τ, ⌊c/128⌋, c mod 128, κ(c)) against the ChaCha AIR output rows (below),
  multiplicity 1 each side for consumed nibbles.
- (C-E2) position lookup: (τ, pos(c), H(pos(c))) against the per-tile position rows
  (t, H_τ[t]) (32 rows/tile computed once, below).
- (C-E3) mixed(c) = κ(c) ⊕ H(c) via T_X.
- (C-E4) (acc(c), μ(c)) = T_M[mixed(c)] via T_M.
- (C-E5) pos(0) = 0; pos(c+1) = pos(c) + acc(c); pos(C_τ) = 32 (boundary);
  liveness (32 − pos(c))·inv_c = 1 for c < C_τ (no idling past completion; inv_c a
  committed witness).
- (C-E6) acceptance registration: the multiset of acc=1 rows' keys
  {(τ, pos(c), μ(c))} equals, with multiplicity exactly 1, the trace-side multiset
  {(τ, t, M_τ[t]) : t < 32} — one LogUp with unit multiplicities both sides (a
  permutation argument); this simultaneously forces *each position filled exactly once*
  and binds the mantissa column M to the sampler.

Position rows t = 0..31 per tile (computing H from the committed int64 input y):
- (C-E7) two's-complement decomposition: y_t + 2^63·s = lo + 2^32·hi with committed
  lo, hi ∈ [0,2^32) (each two T_R16 limbs), s ∈ {0,1} the sign bit consistent with the
  embedding of y_t in F_p (the int64 column is committed as F_p elements; the
  decomposition constraint is over integers < p, unambiguous since 2^64 < p·2 and the
  range checks pin the branch);
- (C-E8) branch: b ∈ {0,1}, b = 1 iff (hi = 0 ∧ lo < 2^31) ∨ (hi = 2^32−1 ∧ lo ≥ 2^31);
  expressed with the top bit of lo (from its limb decomposition) and two zero-tests with
  inverse witnesses; u = b·lo + (1−b)·(lo ⊕ hi), the 32-bit XOR via 8 T_X lookups on
  nibble limbs;
- (C-E9) golden-ratio mix: u·0x9E3779B9 = q·2^32 + v, with q < 2^32, v < 2^32 range-
  checked; H_τ[t] = top nibble of v (from v's nibble decomposition).
- (C-E10) output: out_τ[t] = M_τ[t]·s_τ where s_τ = (1+e0)(1+3e1), (e0,e1) the two low
  bits of the SHA-derived scale byte (§6.2), booleanity constraints on e0,e1.

ChaCha20 AIR per block (τ, remix): standard ARX AIR — 16-word state, init row bound to
(constants, prf_ℓ (public per layer, native), counter = remix, nonce from (i,bj) — all
public functions of τ); 20 rounds of quarter-rounds: add32 via 16-bit limbs + T_R16
(2 lookups/add), xor32 via 8 T_X lookups, rotations by fixed amounts = limb re-wiring
(free); final feed-forward add; output bytes → nibbles (T_B decompositions) exposed as
the rows consumed by (C-E1). ≈ 3.3k lookup rows/block.

### 5.5 The LogUp instances and the dual-α aggregate

All membership constraints above are compiled as **one** LogUp system per Haböck
(2022/1530) §3–4: witness side = the constraint-generated keys (fingerprinted per
instance with FS-weighted linear combination of tuple coordinates — the tuple-to-field
compression uses a fresh FS challenge γ, adding a (max tuple width)/|F| S2 term);
table side = T_M/T_X/T_R16/T_B with committed multiplicity columns m_j. Prover commits
the fractional columns φ_i = 1/(α − w_i), ψ_j = m_j/(α − t_j) and the running-sum column;
constraints φ_i(α − w_i) = 1, ψ_j(α − t_j) = m_j, Σφ = Σψ enforced at the §2.2/2.4
points. **Amplification:** the entire fractional system is instantiated twice with
independent FS challenges α_1, α_2 (one FS round emitting (α_1,α_2) ∈ Fp2²).

### 5.6 Theorem R3 and the Fp2/Fp3 determination

Let N_L = total LogUp rows (witness + table sides). Consensus-dims accounting
(§0.2, details in the companion table): ChaCha ≈ 2^40.1, scale-SHA ≈ 2^40.9, tile-tree
SHA (§6.3) ≈ 2^40.9, operand-expansion AIR ≈ 2^39, sampler/mantissa ≈ 2^34 ⇒
**N_L ≤ 2^43**.

**Theorem 5.2.** Assume Theorems 2.1/2.2. If for any tile out_τ ≠ ExtractMXTileInt64
(prf_ℓ, i, bj, in_τ) — including any deviation in keystream, scale, branch, mixing,
acceptance pattern, or position assignment — then the verifier rejects except with
probability ε_R3 ≤ 2^40·[ (N_L,w + N_L,t)²/|Fp2|² + (w_max·n_inst)/|Fp2| ] + (shared
ε_commit + ε_eval) ≤ 2^40·2^-170 + … ≈ **2^-130** (dual-α term) for Fp2.
*Proof.* The AIR constraints (C-E1..E10, ChaCha, SHA) are polynomial identities over the
committed columns; §2 binds the columns and their openings, so a violated identity
survives only via the constraint-composition S2 terms already counted in ε_eval. A
satisfied identity system with a wrong output requires a false multiset membership in
some LogUp instance; by S3 the fractional equality at α_s then holds for ≤ (N_w+N_t)/|F|
of each α_s; both must hold: ((N_w+N_t)/|F|)² ≤ (2^44/2^128)² = 2^-168 (bad-pair density
over Fp2²; one FS round ⇒ one rbr term). Completeness: the honest sampler terminates
(acceptance prob 11/16 per candidate ⇒ C_τ finite; the trace length is prover-chosen
data, unbounded-loop is not an issue for an IOP). ∎

**Fp2 vs Fp3 (the forcing term, answered).** The α-collision term N_L/|F| is the unique
term that outgrows the field: single-α over Fp2 gives 128 − 43 = 85 pre-grinding bits ⇒
**45 bits after grinding — insufficient** (and even the bare tile-key count 2^28.4 gives
59.6 bits: still insufficient; the single-α ceiling is N ≤ 2^24). Therefore:
*either* (a) dual-α over Fp2 as constructed (2·(128) − 2·43 = 170 pre-grind, 130 post ✔),
*or* (b) Fp3 single-α: 192 − 43 = 149 pre-grind, 109 post ✔. **Fp2 suffices for the
Extract relation only with the dual-α amplification; a single-challenge LogUp forces
Fp3.** Recommendation: dual-α on Fp2 (Fp3 arithmetic is unbuilt; dual-α costs one extra
fractional column set, ~1.2× LogUp area).

### 5.7 Operand-expansion binding (grounding the induction)

`ExpandMxDequantInt8` (Q, K, V, X₀, W_l, G_L, coupled lobe rows and bank pages) is the
same ChaCha + mantissa-rejection + E8M0-scale machinery; the identical AIR (§5.4 minus
the input-mixing sub-circuit, since expansion mixes no data input) binds each O-column of
seed-derived operands to its public seed (seeds and prf keys native per §4.2).
≈ 2^31.2 cells ⇒ ≈ 2^39 lookup rows, included in N_L. Without this, A/B openings ground
out in *committed but unconstrained* leaf operands (Forgery F0 again). This closes the
last free end of the R2 induction.

### 5.8 Recorded attacks (all fail)

Multiplicity forgery (m_j ≠ true count): changes ψ-side sum ⇒ dual-α S3 event
(≤ 2^-168·2^40). Position permutation (valid pairs, shuffled): (C-E6) unit-multiplicity
permutation LogUp keys include pos ⇒ caught by the same bound. Early stop / idle rows:
(C-E5) liveness+boundary, deterministic. Cross-tile keystream reuse: keys carry τ.
Scale forgery: §6.2 SHA AIR. Pad smuggling into AIR columns: §2.5. α grinding: inside
the 2^40 budget by S6. w:=t cloning (the v6 hole): table side is preprocessed-canonical,
no longer prover data — attack no longer expressible.

---

## 6. Hash bindings (shared by relations 2–5)

### 6.1 Native (verifier-recomputed, no AIR, zero soundness cost beyond ε_hash)

sigma = DeriveSigma(header); round-seed chain; per-layer operand seeds and prf keys;
digest = SHA256d(tag ‖ roots); pow_bind; params equality (arbiter F3); target check.

### 6.2 Scale-SHA AIR

Per tile: ≤ 2 SHA-256 compressions of the fixed-layout message (tag ‖ prf_ℓ ‖ i ‖ bj).
Standard SHA-256 AIR (32-bit modular adds via T_R16, σ/Σ/Ch/Maj via T_X on nibble limbs,
message schedule); output byte 0's two low bits feed (C-E10). ≈ 5k lookup rows/tile-hash.

### 6.3 Tile-tree AIR (binds round_roots to the committed extract streams)

The round stream (Z ‖ per-layer X_{l+1} ‖ G_l ‖ D_l as int8 bytes in the frozen V1
layout) is re-expressed over the O-columns by the fixed byte-offset map (byte b of leaf
= column cell via Λ; int8→byte two's-complement: byte = v mod 256 with v ∈ [−128,128)
range-checked). AIR: leaf hashes SHA256d(0x00 ‖ 1024 bytes) (16+16 compressions), tree
nodes SHA256d(0x01 ‖ l ‖ r), pad leaves 0x02-tagged, root row constrained equal to the
public round_root. ≈ 2^28.4 compressions total ⇒ ≈ 2^41 lookup rows (in N_L).
This is the *only* sound way for the succinct verifier to know that the PoW-winning
roots commit the same bytes the sumcheck layers talk about; absorbing roots into FS
(v6) provides no such binding (Theorem 5.1 / Forgery F0).

---

## 7. Relation (5): coupled arithmetization (`ProveWinnerCoupled`)

Ground truth: `RecomputeCoupledPuzzleReference` (§1.5-analogue): bank pages (template-
seeded, nonce-independent), per barrier b: lobe GEMMs (1×W · W×W int8→int64) against
`SelectCoupledBankPageIds(b,ℓ)`, balanced permutation π_b, butterfly mix (pattern b mod 2,
mask from sigma), Extract, barrier_root = SHA(state); digest = SHA256d(tag ‖ bank_root ‖
barrier_roots).

### 7.1 Public (native) components — no committed index relations needed

π_b (Fisher–Yates over ShaXof(sigma,b)), the mix masks, the page-ID schedule (legacy
(b+ℓ) mod P or the frozen full-bank permutation), and the lobe seeds are all
**verifier-computable in O(barriers·StateBytes)** ≤ 8·65536 steps at production dims —
they are public functions of (header, height, params), like sigma. The "committed index
relation" demanded for page selection therefore degenerates (soundly and preferably) to
*native recomputation + fixed wiring*: the layout Λ_coup wires lobe ℓ's GEMM B-operand to
bank column O[page id(b,ℓ)] as computed by the verifier. A proof claiming a different
page ID is unexpressible (same mechanism as Theorem 4.2). Material exchange (Stage-D
segment_id = lobe index) is likewise fixed offsets in Λ_coup.

### 7.2 Local GEMMs

Per (b, ℓ): Thaler sumcheck (S7) exactly as relation (1), m = 1 (ν_i = 0). Batched
across lobes with FS weights. Operand A = state slice column of barrier b (wired), B =
bank page column (bound to template seeds by §5.7 expansion AIR; see §7.6 for the
amortization option). Accumulation over multiple page IDs (full-bank schedule) is a
native linear fold of the per-page claims.

### 7.3 Balanced permutation (public π)

Claim s̃'(r) = Σ_x eq(r, π_b(x))·s̃-source(x): one ν-round sumcheck (ν = log2 StateBytes
= 16 at production dims) whose weight-MLE ẽq(r, π_b(·)) the verifier evaluates natively
at the sumcheck point in O(StateBytes) — affordable, or precomputed as a preprocessed
column. Since π_b is public and bijective, no permutation *argument* (grand product /
LogUp) is needed; this is wiring, and its soundness is S1 with d = 2.

### 7.4 Butterfly mix (the all-to-all layers)

Pattern 0, stage s, relabel mask m: with logical index y = x ⊕ m,
s'[x] = s[x] + (−1)^{y_s}·s[x ⊕ 2^s] where the sign is + on y_s = 0 branch per the code
(a+b / a−b pairing). MLE identity, using §1.2 (index-XOR by 2^s = coordinate flip; ⊕m =
flips of known coordinates; the descending pattern's rotl relabel = coordinate rotation):

  s̃'(r) = (1 − χ_s(r))·(s̃(r) + s̃(r^{(s)})) + χ_s(r)·(s̃(r^{(s)}) − s̃(r)),

where r^{(s)} flips coordinate s and χ_s(r) is the affine bit-selector (r_s or 1−r_s per
mask bit). Each stage reduces one claim about s' to **two** point-claims about s at
points differing in one coordinate; condense to one claim via the axis-aligned line
restriction (Thaler's two-point trick): prover sends the two values v_0 = s̃(…, r_s := 0),
v_1 = s̃(…, r_s := 1); verifier checks both derived claims as the appropriate affine
combinations of v_0, v_1, then continues from r_s := fresh challenge, claim
(1−r_s)v_0 + r_s v_1. Per stage: degree-1 S2 term 1/|Fp2|; per barrier: 2·log2(n) = 32
stages (production) ⇒ 32/|Fp2|; 8 barriers ⇒ 2^-120 total. Exact int64 range: mix values
stay < 2^62 (state entries < 48·... — the reference's own invariant), so field wraparound
cannot occur; a range constraint per stage output (T_R16 limbs) enforces the int64
semantics against a prover exploiting mod-p wraparound: **required** — recorded attack:
without it, a prover could satisfy the field identity with values that differ by
multiples of p from the integers the SHA barrier-root hashes; the range checks + §6.3
byte binding close it.

### 7.5 Extract, barrier roots, feed-forward, checkpoint

Extract per barrier: §5 verbatim (n/32 = 2048 tiles/barrier at production — negligible
against the episode). Barrier roots: §6.3-style SHA AIR over the state columns
(StateBytes = 64 KiB ⇒ ~2k compressions/barrier). Feed-forward: Λ_coup wires barrier
b+1's GEMM A-operands to barrier b's extract_out column (definitional). The episode-side
backward/checkpoint dependency needs no constraint: checkpoint modes are digest-invariant
execution policy (non-consensus); the backward *data* dependency (Bwd/Wgrad read X_l,
G_{l+1}) is Λ wiring, already relation (2).

### 7.6 Bank binding and Theorem R5

bank_root = SHA256d over all page bytes: at production (48 GiB) that is ≈ 2^30
compressions — in-circuit is possible but dominates everything. **Amortization option
(protocol-level, flagged):** bank_root is nonce-independent (template-committed), so it
may be verified once per template by a separate proof (or by ε=0 native hashing at
template admission) and cached; the per-winner proof then treats bank_root as a verified
public input and binds pages via the §5.7 expansion AIR only for the pages actually
touched. Both variants are sound; the per-winner-only variant at production dims is the
one honest over-budget risk in this relation.

**Theorem 7.1.** With Λ_coup wiring, §7.2–7.5 constraints, and either bank-binding
variant, any digest-accepted coupled proof whose committed execution differs anywhere
from `RecomputeCoupledPuzzleReference` (any lobe GEMM cell, permutation application, mix
stage, Extract tile, barrier root, or page content) is rejected except with probability
ε_R5 ≤ Σ 2ν_k/|Fp2| (lobe sumchecks) + (barriers·2 log n)/|Fp2| (mix stages) + ε_R3-share
+ shared ε_commit/ε_eval/ε_hash ≤ 2^-114 (FS sum, pre-grinding) — absorbed into §8's
global accounting with no new dominant term. *Proof:* first-deviation induction as in
Theorem 4.1, grounded at template seeds (native) and closed at the digest (native SHA of
bound roots). ∎

This replaces `kRCGkrCoupledArithStatement`'s toy-episode stand-in: `ProveWinnerCoupled`
must prove *this* system, not an unrelated toy episode (Forgery table, F-coup).

---

## 8. Composed soundness

Let the adversary make ≤ 2^40 RO queries (repo grinding convention, S6). Rounds and
terms (details per-row in the companion table):

| Term | Count | Per-term (pre-grind) | Total (pre-grind) |
|---|---|---|---|
| Multilinear sumcheck rounds (episode + coupled + pad + eval-agg) | ≤ 2^13 | ≤ 3/|Fp2| ≈ 2^-126.4 | ≤ 2^-113.4 |
| Line-restriction / 2-claim condensations | ≤ 2^9 | 1/|Fp2| | ≤ 2^-119 |
| RLC batchings (λ, μ, γ, quotient weights) | ≤ 2^4 | ≤ 2^12/|Fp2| | ≤ 2^-112 |
| Dual-OOD DEEP (both z's) | 1 | (2κ/|Fp2|)² ≈ 2^-196 | 2^-196 |
| Dual-α LogUp | 1 | (N_L·2/|Fp2|)² ≈ 2^-168 | 2^-168 |
| **FS subtotal** | | | **≤ 2^-112** |
| × grinding 2^40 | | | **≤ 2^-72** |
| Batched FRI queries (S4, already post-grind) | 1 | 2^-65.85 | 2^-65.85 |
| SHA256d bindings (computational, 2^40-query adversary) | | ≤ 2^40·2^-128… | ≤ 2^-88 |

**Theorem 8.1 (whole-protocol).** ε_total ≤ 2^-65.85 + 2^-72 + 2^-88 ≈ **2^-65.7**,
i.e. ≥ 65 bits after grinding: the construction **clears the 2^-64 target with the
existing FRI parameters** (Q=116, ρ=1/16, g=40, Fp2), *provided* (i) single batched FRI
(§2.3), (ii) dual-OOD (§2.2), (iii) dual-α (§5.6). Violating any of (i)–(iii) breaks the
target: 7 instances ⇒ 2^-62.2; single OOD ⇒ 2^-59.6 (worst column); single α ⇒ 2^-45.
Margin is < 1 bit; Q = 128 (⇒ FRI 2^-76.8) is the recommended pre-cutover hardening.
Fp3 is **not** forced anywhere under (i)–(iii); it is forced only if single-challenge
LogUp/OOD is insisted upon. ∎

> **UPDATE (2026-07-22, margin restoration):** the recommended hardening has been
> applied to the bound accounting — the fold ships **Q = 128** (`kRCFriNumQueries`)
> and the FS/algebraic challenges are accounted over **F_{p^3}** (|K| ≈ 2^192).
> The re-derived table and composed total (**≈ 2^-76.8, margin ≈ 12.8 bits over
> 2^-64**) live in Appendix INT; the Fp3 rows are conditional on the challenge
> call-site cutover enumerated in INTEGRATION_REPORT.md. The table above is
> retained as the historical Q=116/Fp2 derivation.

---

## 9. Adversarial section — every listed forgery

"v6" = shipped scaffold; "new" = this construction. Probabilities are acceptance
probabilities of the forgery (lower = better), post-grinding.

| # | Forgery | v6 outcome | New: rejecting constraint | New: accept prob |
|---|---|---|---|---|
| F0 | **Fabricated everything** (grind fake `round_roots` to target; self-consistent fake wires; zero episode work) | **ACCEPTED, prob 1** — the defining hole | §6.3 tile-tree AIR binds roots to columns; §5.7 grounds operands in seeds; Thms 4.1/5.2 | ≤ ε_total ≈ 2^-65.7 |
| F1 | Forge A root (operand commitment) | accepted (roots never opened) | Thm 2.1 (FRI/Merkle) + §5.7/§4.2 grounding | ≤ 2^-65.7 |
| F2 | Forge B root | same as F1 | same | ≤ 2^-65.7 |
| F3 | Forge an A/B opening value | N/A (no openings exist — the gap) | Thm 2.2 (dual-OOD eval binding) | ≤ 2^-76 + FRI |
| F4 | Forge `final_eval` | accepted iff consistent with own fake chain (free) | §3.1 step 4: gf = a·b identity over bound openings; Thm 3.1 | deterministic reject given openings; else ≤ 2ν_k/|Fp2|·2^40 ≈ 2^-82 |
| F5 | Forge trace opening (claim c_ℓ) | accepted (claim prover-supplied) | §4.2 output binding to Y-columns; Thm 4.1 | ≤ 2^-72 (FS share) |
| F6 | Forge Extract witness (out ≠ Extract(in)) | **accepted, prob 1** (Thm 5.1) | §5.4 AIR + dual-α LogUp; Thm 5.2 | ≤ 2^-128+ (α-pair) within ε_total |
| F7 | Forge table multiplicity m_j | accepted (no verifier-side table) | preprocessed tables + S3 dual-α | ≤ 2^-128 within ε_total |
| F8 | Reorder layers | rejected only if dims differ; same-dim swaps (e.g. Fwd(l)↔Fwd(l′) content) accepted | verifier-driven Λ enumeration; Thm 4.2 | 0 (unexpressible) / ≤ ε_R2 for content swaps |
| F9 | Repeat a layer | partially caught (count+dims), content duplication accepted | Λ enumeration + column uniqueness | 0 / ≤ ε_R2 |
| F10 | Omit a barrier (coupled) | accepted (coupled proof is a toy stand-in!) | §7: barrier_roots length + §7.5 SHA binding + Λ_coup | 0 (structural) / ≤ ε_total |
| F11 | Forge a page ID | accepted (no coupled arithmetization) | §7.1 native page schedule; wiring unexpressible | 0 |
| F12 | Forge sigma | rejected in arbiter mode (F3 native check) | same native check retained | 0 |
| F13 | Forge dimensions | rejected (M7 dims + F3 params equality) | same, now Λ-derived | 0 |
| F14 | Forge target compliance | rejected (F3 native digest ≤ target) | same | 0 |
| F15 | Forge claimed digest | rejected only as far as digest = SHA(roots); roots themselves free (→F0) | native SHA(roots) + §6.3 binding + pow_bind | ≤ 2^-88 (hash) |
| F-pad | Smuggle values into MLE padding | (v6 has same hole implicitly) | §2.5 suffix-zero sumcheck | ≤ 2^-72 share |
| F-wrap | Exploit mod-p wraparound vs int64 semantics (esp. §7.4 mix) | N/A | range constraints (T_R16) on every int-semantics column | within ε_total |
| F-coup | Substitute toy episode for coupled work | **accepted by design** (`kRCGkrCoupledArithStatement`) | §7 replaces the stand-in; Thm 7.1 | ≤ ε_total |

**No forgery in the list survives the new construction.** The most important line
remains F0: it is not an edge case but the *generic* break of v6, and it is closed only
by the conjunction {§6.3 hash AIR, §5.7 expansion AIR, §4 wiring} — any one missing
reopens it (this is the precise sense in which per-layer root absorption was proven
insufficient).

---

## 10. Implementation blueprint (`matmul_v4_rc_gkr.cpp` and friends)

Behind the hard-disabled arbiter flag throughout (`kRCGkrFormalSoundnessReady=false`);
proof version bump 6 → 7; int64 reference untouched; shadow-mode first.

**`matmul_v4_rc_fri.{h,cpp}`** (compose-only additions, no redesign):
- `FriBatchCommit(cols, fs_seed) / FriBatchVerify` — §2.2: per-column Merkle roots, RLC
  λ, degree-shift for short columns, dual-OOD (`deep_z2`, second quotient), per-query
  column-consistency openings. Keep `FriCommitAndFold` for the preprocessed-table roots.
- Extend `FriProof` with `deep_z2/deep_eval2/deep_quot2_*`; serialization guards.

**`matmul_v4_rc_gkr.h`**:
- `RCGkrLayerClaim`: delete `a_root/b_root/residual_mle/extract_out_commit` as prover
  fields; add `a_eval, b_eval` (opened values) — `claim/acc_claim` become derived, not
  carried. Delete deprecated synth fields. `kRCGkrProofVersion = 7`.
- New `struct RCGkrOpeningClaim { column_id; point; value; }` and
  `struct RCGkrLayout` + `RCGkrTraceLayout(const RCEpisodeParams&)` /
  `RCGkrCoupledLayout(const RCCoupParams&)` — §4.1/§7.1 canonical enumerations
  (offsets, dims, operand column refs, transpose flags, chunk splits at κ = 2^28).

**`matmul_v4_rc_gkr.cpp`**:
- `ProveFromLayers` → `ProveFromLayout`: iterate `RCGkrTraceLayout` (never a
  prover-side wire list order); build columns per §2.1; call `FriBatchCommit`; per layer
  run `ProveProductK` unchanged, then append the two operand opening claims and the Y
  opening claim; run `EvalArgumentProve` (new, §2.4: eq-kernel q*, Lemma 1.2 f/g columns
  committed in the second FRI epoch); pad-zero sumchecks (§2.5).
- `VerifyWinnerProof`: replace the per-layer trust in `lc.claim` with Λ-driven
  enumeration; after `VerifyProductK` check `Eq(gf, Mul(a_eval, b_eval))`; collect all
  opening claims; `EvalArgumentVerify`; native checks unchanged (seed chain, digest,
  pow_bind, F3 bindings) plus native prf-key derivation per layer.
- Delete the vacuous G3 block (`lookup_fri`/`table_fri` root-equality, prover-side sum
  equality) — superseded by the AIR LogUp of §5.5.

**New files `matmul_v4_rc_gkr_air.{h,cpp}`** (relation 3 + hash bindings):
- `ChaChaBlockAir` (§5.4), `Sha256CompressAir` (§6.2/6.3), `ExtractSamplerAir`
  (C-E1..E10), `MxExpandAir` (§5.7), `TileTreeAir` (§6.3), preprocessed tables
  T_M/T_X/T_R16/T_B with consensus-constant roots + build-time self-check against
  `SampleMantissaNibble` et al.; `LogUpAggregateProve/Verify` with the dual-α interface
  (single FS round emitting α_1, α_2).
- Cross-validation hooks: every AIR gets a unit test that replays
  `ExtractMXTileInt64` / `ChaCha20::Keystream` / `CSHA256` on random tiles and asserts
  the AIR trace satisfies all constraints and reproduces byte-identical outputs of the
  int64 reference (the reference is the oracle, never the AIR).

**`ProveWinnerCoupled`**: replace the toy-episode call with `RCGkrCoupledLayout` +
§7 layers (`ProveButterflyStage` line-restriction condensation, native π/mask/page
schedules, per-barrier Extract AIR, barrier-root `TileTreeAir` variant, bank-binding
variant flag `BTX_RC_GKR_BANK_AMORTIZED`).

**Order of work / verification duties:** (1) FriBatchCommit + dual-OOD + eval argument
with tests vs `RCGkrMleEval1D2`; (2) layout-driven verify + F0/F4/F5 regression forgery
tests (each forgery in §9 becomes a unit test that must REJECT); (3) Extract AIR on toy
dims, cross-checked byte-for-byte vs the int64 reference; (4) tile-tree AIR; (5) coupled.
CI proves toy dims only (consensus-dim prove remains over_budget/PARKED — unchanged
posture).

---

## 11. Honest-park verdict

- **R1 (A/B opening → final_eval): CLOSABLE.** Standard (Thaler sumcheck + PCS opening).
  No obstruction. Previously claimed closed; was not (F3/F4).
- **R2 (claim-to-trace + wiring): CLOSABLE.** Requires the layout-driven verifier and
  the §6.3 hash AIR for the root boundary. No obstruction. Previously claimed closed;
  was not (F0/F5).
- **R3 (Extract): CLOSABLE, heavy.** The "canonical fixed table" framing is *provably
  wrong* (keyed, int64-domain, data-dependent consumption — §5.1), and the shipped
  virtual-table check has exactly zero soundness (Theorem 5.1). The sound construction
  exists (§5.4–5.7) but requires in-circuit ChaCha20 + SHA-256 (≈ 2^43 LogUp rows at
  consensus dims). This is labor, not impossibility: **no obstruction theorem**.
  Shipped G3 status remains **OPEN/PARKED** until the AIR is implemented and audited.
  Field verdict: Fp2 + dual-α suffices; single-α forces Fp3.
- **R4 (canonical sequence): CLOSABLE, essentially free** once R2's layout discipline is
  adopted (verifier-driven enumeration ⇒ deterministic rejection of order forgeries).
- **R5 (coupled): CLOSABLE.** All components reduce to machinery already required
  (sumcheck, public wiring, Extract AIR, SHA AIR); the butterfly layers are unusually
  MLE-friendly (§7.4). One flagged protocol decision: per-winner vs per-template
  bank_root binding at production dims (§7.6) — the per-winner variant is sound but
  budget-hostile; the amortized variant is sound and cheap but is a (minor, explicit)
  protocol addition.
- **No obstruction theorem blocks G1–G5.** Conversely, nothing in G1–G5 was actually
  closed as a succinct relation in v6/v7 scaffolding; the honest status is:
  *constructions specified and proven here; implementation pending; G1–G5 remain
  OPEN/PARKED; arbiter hard-disabled (`kRCGkrFormalSoundnessReady=false`); ExactReplay
  remains the sole authority. v7 defeats independent forges by grounding, not by
  claiming these rows CLOSED.*
- Prover-cost reality (unchanged from the Reality Guardrail): ≈ 2^43 lookup rows plus a
  2^33-cell trace put consensus-dim proving far over the CPU soft budget; the
  `over_budget → ExactReplay` shipping posture and the HBM PARK are unaffected by this
  document.

---

## 12. Construction I — batched multilinear evaluation opening (implemented 2026-07-22)

`src/matmul/matmul_v4_rc_gkr_eval.{h,cpp}` now carries the §2.4 primitive in full,
stated as finite-field algebra over F_p (Goldilocks) and K = F_{p²}:

- **Stage 1 — γ-batched eq-kernel summation-reduction** (`EvalOpenProve/Verify`):
  for claims {(u_c, z_m, y_m)} on root-bound columns, ONE ν-round degree-2
  reduction on F(x) = Σ_m γ^m·u_{c(m)}(x)·eq(z_m, x) with Σ_x F(x) = Σ_m γ^m·y_m,
  ending at a common point r ∈ K^ν with one residual ũ_c(r) per distinct column;
  the checking routine spends O(ν) per round plus O(M·ν) native eq(z_m, r).
  Points shorter than ν are zero-extended (low sub-cube identity); a point that
  does not cover the column's logical length is refused (`point_short` guard —
  the F-pad-adjacent smuggling surface).
- **Stage 2 — root binding of the residuals** (existing `EvalArgumentProve/
  Verify`, Aurora/Lemma-1.2): the reduced claims aggregate under μ into the
  univariate identity whose f/g columns ride the SAME `FriBatchCommit`
  (dual-OOD, degree-shift RLC, Q = 128). One low-degree-proximity instance for
  the whole claim set — no union across per-column instances (§2.3).
- **End-to-end bundle**: `BatchedOpeningProve/Verify` (γ seed bound to the
  epoch-1 column roots; Stage-2 seed = the Stage-1 transcript digest;
  check order: shape → `FriBatchVerify` → Stage-1 replay → Stage-2 identity).
- **G1/G2/G5 pieces** (claim/point builders only; integration wires them):
  `RCGkrMatrixOpeningClaim` (a_at_r = Ã(r_i,r_k), b_at_r = B̃(r_k,r_j), free
  transpose view M̃ᵀ(r,s) = M̃(s,r)) + `RCGkrCheckFinalEvalBinding`
  (gf = a·b, deterministic) for G1; `RCGkrSegmentPoint` (aligned trace-column
  segment via 0/1 high coordinates) + `RCGkrFoldChunkClaims` (two-chunk
  top-variable glue) for G2; `RCGkrResidualAcc`/`RCGkrCheckResidualAcc`
  (acc̃(r) = Ỹ(r) + X̃(r) by MLE linearity, acc derived never carried) for G5.

**Acceptance obligations.**

(a) *Completeness*: a valid assignment (u, z, y = ũ(z)) satisfies every check
as an exact polynomial identity (round sums, chain-end eq identity, Lemma-1.2
coefficient identities, FRI/DEEP openings) — accepted with probability 1.
Test: `constr1_completeness_valid_assignment`.

(b) *Separation bound* (composed, |K| = p² > 2^127.99; caps ν ≤ 28 = log2 κ,
M ≤ 2^12 claims, W ≤ 2^12 columns; grinding budget 2^40):

| term | bound (pre-grinding) |
|---|---|
| γ-batching (powers of one γ) | (M−1)/\|K\| ≤ 2^-116 |
| eq-sumcheck, ν rounds, deg ≤ 2 (S1) | 2ν/\|K\| ≤ 2^-122.2 |
| μ-aggregation of reduced openings (Thm 2.2) | (M−1)/\|K\| ≤ 2^-116 |
| batch RLC λ + DEEP weights (Thm 2.1) | (W+2)/\|K\| ≤ 2^-116 |
| dual-OOD bad-point pairs (S5) | (2κ/(\|K\|−2^32))² ≤ 2^-196 |

FS subtotal ≤ 3·2^-116 + 2^-122.2 ≈ 2^-114.4; ×2^40 ⇒ ≤ 2^-74.4. Adding the
batched-FRI query term 2^-76.8 (Q = 128, post-grinding;
`FriBatchSoundnessBoundBits() = 76`) and the SHA256d binding term ≤ 2^-88:

  **ε_total ≤ 2^-74.4 + 2^-76.8 + 2^-88 < 2^-74, i.e. −log2(ε_total) ≥ 74**,

clearing the 2^-64 target with ≥ 10 bits of margin.

> **UPDATE (2026-07-22, margin restoration):** with the FS challenges drawn from
> F_{p^3} (|K| ≈ 2^192) the FS terms become γ/μ ≤ 2^-180, eq-sumcheck ≤ 2^-186.2,
> λ+weights ≤ 2^-180, dual-OOD ≤ 2^-326; FS subtotal ≤ 2^-178.4, ×2^40 ⇒
> ≤ 2^-138.4, and the composed bound is dominated by the (field-independent)
> batched-FRI query term: **ε_total ≤ 2^-138.4 + 2^-76.8 + 2^-88 < 2^-76 ⇒
> ≥ 76** (`RCGkrConstructionISeparationBits() = 76`, statically asserted
> ≥ 64+10; conditional on the Fp3 challenge cutover per INTEGRATION_REPORT.md).
This instantiates the §8 accounting for the evaluation-opening sub-protocol
alone; composed into the full episode proof it is absorbed by the same rows.

(c) *Counterexamples* (`src/test/matmul_v4_rc_gkr_eval_tests.cpp`, wired into
`src/test/CMakeLists.txt`): the checked identity evaluates NONZERO on every
tested invalid assignment — (i) an internally-consistent transcript for
y′ ≠ ũ(z) (round sums repaired by constant shifts into g(0), chain end
repaired by a fabricated residual; built by the test-only
`BatchedOpeningProveInvalidAssignmentForTest`) satisfies ALL Stage-1 algebra
and is detected exactly at the Stage-2 root binding (`eval:identity_z1/z2` —
the Lemma-1.2 residual is a nonzero constant σ − h_n, deterministic given the
bound openings); (ii) a wrong batched γ-combination (claims permuted, foreign
FS seed, tampered round message, tampered residual) is detected at Stage 1
(`eqopen:round_sum` / `eqopen:final`); (iii) the valid assignment passes.
The plain constructing routine refuses invalid claims outright
("claims disagree with columns").

Consensus posture unchanged: arbiter OFF, activation heights INT32_MAX,
`RecomputeResidentCurriculumReference`/`RecomputeCoupledPuzzleReference`
untouched; `VerifyWinnerProofV7`/`matmul_v4_rc_gkr.cpp` wiring is the
integration wave's job — this section provides the primitive + tests only.

## Appendix W3 (2026-07-22) — Constructions II/III implementation note
## (`matmul_v4_rc_gkr_air.{h,cpp}` §8–§9)

This appendix records the acceptance obligations of the implemented Extract constraint
system (Construction II) and fixed-reference-vector membership (Construction III).
Everything remains behind the OFF arbiter; the int64 reference is untouched and stays
the sole oracle.

### W3.1 What was implemented

**Construction II — the map E as polynomial identities over F_p.** The committed cells
(`ChaChaBlockTrace`, `ShaCompressTrace`, sampler candidate rows in `TileWitness`) are
the column vectors; `EmitTileConstraints` evaluates the full family of identities of
total degree ≤ 4:

- add mod 2^32: `a + b − c − 2^32·carry = 0`, `carry(carry−1) = 0`, operands
  range-bound by bit columns (`Σ 2^i b_i − v = 0`, `b_i(b_i−1) = 0`);
- rotation by r: a fixed index relabeling of the producing xor's bit columns,
  `op − Σ 2^{(i+r) mod 32} b_i = 0` (no new cells — §1.2 / §5.4);
- xor per bit: `x + y − 2xy − z = 0` (degree 2);
- SHA-256 Boolean functions as bit polynomials: `Maj = ab+ac+bc−2abc`,
  `Ch = c + a(b−c)`, Σ/σ as xor-of-relabelings (degree ≤ 3), message-schedule and
  round adds with 2–3-bit carry witnesses, feed-forward, chaining, and public
  message/init binding;
- sampler C-E1..E10: keystream-nibble binding, the acceptance selector as an explicit
  degree-4 polynomial in the four nibble bits (`AirAcceptNibblePoly`, exactly 0 on the
  rejected E2M1 codes {1,3,8,9,11}), liveness `(32−pos)·inv − 1 = 0`, transition
  `pos' − pos − acc = 0`, boundary `pos(0)=0`, `pos_final=32`, the MixBits
  two's-complement embedding `lo + 2^32·hi − y − s(2^32−1) = 0` with zero-test branch
  selectors, the golden-ratio decomposition `u·G − 2^32·q − v = 0`, and the dequant
  output identity `out − M·(1+e0)(1+3e1) = 0`.

All families of one gadget row are combined with ONE challenge η ∈ Fp2:
`Comp(x) = Σ_slot η^slot·C_slot(x)`; the single check is that Comp vanishes on the
whole trace domain (`ComposeConstraints`).

Two integer-vs-field subtleties are closed explicitly (they are genuine invalid-
assignment channels, found during this construction):

- **Golden-mix mod-p alias.** For `u ∈ {0,1}` the field identity
  `u·G = 2^32·q + v (mod p)` admits a second ranged representative
  `(q', v') = (2^32−1, u·G + 1)` since `u·G + p < 2^64`. Every alias has
  `q' = 2^32−1 > G`, so the added canonicity obligation `q ≤ G` — the T_R16 range row
  on `(G − q)` plus the deterministic `C-E9:golden_q_canonical` check — excludes all
  aliases and pins `(q, v)` to the unique integer decomposition.
- **Embedding alias.** The mod-p alias of `lo + 2^32·hi` flips the sign cell `s`
  inconsistently with hi's top bit (`s − hi_31 = 0` is a committed-bit relabel), so the
  embedding identity plus the sign binding is alias-free (proof sketch in the C-E7
  comment of `CheckTileConstraints`).

**Construction III — membership in a FIXED reference vector.**
`BuildPreprocessedLogUpTables(γ)` regenerates the T_M/T_X/T_R16 fingerprint vectors
from consensus constants only (no assignment data), and
`VerifyLookupAgainstPreprocessed` enforces, in order: (i) the supplied table side
equals the regenerated canonical vector fingerprint-for-fingerprint — the Theorem-5.1
clone `table := witness` is rejected here even though its fractional sums balance
identically (the accompanying test demonstrates both halves); (ii) multiplicity
accounting `Σ_j m_j = |W|` exactly (deterministic, overflow-guarded; the per-row
occurrence counts are then certified by the dual-α identity itself, S3 with
char F_p ≫ N); (iii) the dual-α log-derivative identity with the existing FAIL-CLOSED
pole handling (`FracSum`/`FracSumMult` reject any α that collides with a key rather
than computing through `Inv(0)`) — retained unchanged.

### W3.2 Acceptance obligations

**(a) Completeness.** `TraceTile` populates the committed cells by evaluating the
reference primitives, so on an honest assignment every emitted identity evaluates to
the zero field element and both log-derivative sums agree exactly at every non-pole α
(the multiset relation holds by construction, so equality is an identity of rational
functions, not a probabilistic event). Tests: `air_construction2_composition_polynomial`
(honest branch), `air_construction3_fixed_reference_vector` (honest branch), plus the
pre-existing byte-exactness suites against `ExtractMXTileInt64` /
`ExpandMxDequantInt8` / `RoundMerkleStream`.

**(b) Separation bound (explicit numbers over F_{p^2}, |F_{p^2}| = p² with
2·log2(p) = 127.99999999932).**

| Term | Pre-grinding | Post-grinding (g = 40) |
|---|---|---|
| Composition polynomial: an invalid assignment survives uniform η iff η hits the root set of the slot polynomial, ≤ (n_slots−1)/|Fp2| with n_slots ≤ 256 | ≤ 2^8/2^128 = **2^-120.0** | **2^-80.0** |
| Lookup (Thm 5.2 / S3, dual-α): false multiset inclusion survives both α's with prob ≤ ((N_w+N_t)/|Fp2|)², N_L = 2^43 at consensus dims | ≤ (2^43/2^128)² = **2^-170.0** | **2^-130.0** |
| **Composed (union bound)** | 2^-120 + 2^-170 ≈ **2^-120.0** | 2^-80 + 2^-130 ≈ **2^-80.0** |

The composed Construction-II/III algebraic term is ≈ 2^-80.0, i.e. **80.0 bits**
post-grinding — 16 bits above the 2^-64 target. (These are the R3-local algebraic
terms; the whole-protocol bound of §8 remains dominated by the batched-FRI query term
and is unchanged by this appendix.)

> **UPDATE (2026-07-22, margin restoration):** with η/α drawn from F_{p^3}
> (|K| ≈ 2^192) the same closed forms give composition ≤ 2^8/2^192 = 2^-184
> pre-grind → **2^-144** post, and dual-α lookup ≤ (2^43/2^192)² = 2^-298
> pre-grind → **2^-258** post (conservative (N_w+N_t ≤ 2^44) form: 2^-256,
> the `kRCGkrLookupSepBits` pin). `ComputeSeparationBound` now reports the
> Fp3 numbers programmatically and `air_separation_bound_numbers` pins them in
> CI; the numbers are conditional on the challenge-site cutover per
> INTEGRATION_REPORT.md.

**(c) Counterexamples (each is a unit test that must reject).** A fabricated
(in,out) tuple absent from the reference vector — with the multiplicity sum patched to
stay consistent — leaves the log-derivative difference a nonzero rational function and
is separated at both α's. A self-manufactured "table" (`table := witness`, m_j := 1)
balances the raw sums but is rejected by the reference-vector regeneration
(`table_not_canonical`) — the v6 hole, now unexpressible. A single edited ARX/SHA
intermediate cell (quarter-round add result, operand cell with locally-consistent
identity, SHA round variable, schedule word, liveness inverse, golden-mix limb) makes
a specific constraint polynomial evaluate to a nonzero field element, and the
composition polynomial is nonzero at that row. Tests:
`air_construction2_composition_polynomial`, `air_construction3_fixed_reference_vector`,
plus the pre-existing tamper suites.

### W3.3 Emulation caveats (explicit)

- Bit columns are derived in the emitter from the committed 32-bit word cells (their
  booleanity/recomposition identities are emitted but hold by construction); in the
  committed layout of §2.1 the bits are their own columns and the same identities do
  the binding. The cross-cell identities (add/xor/rotation/copy) carry the separation
  force in both layouts and are what the counterexample tests break.
- `ComposeConstraints` checks Comp(x) = 0 row-by-row over the explicit trace; in the
  committed system the same statement is "Comp is divisible by Z_D", delegated to the
  §2 quotient/FRI machinery with the identical η-collision term.
- T_R16 range obligations (limbs, and the `(G − q)` canonicity row) are membership
  relations routed through Construction III, not identities; the deterministic
  structural guards in `CheckTileConstraints` mirror them 1:1.

## Appendix W — Construction IV: copy / permutation wiring constraints (implemented, 2026-07-22)

*Implementation: `src/matmul/matmul_v4_rc_gkr_wiring.{h,cpp}`; tests:
`src/test/matmul_v4_rc_gkr_wiring_tests.cpp`. Framing: this appendix is
finite-field algebra over F_p (Goldilocks) and its quadratic extension Fp2 —
polynomial identities that force two vectors to be equal, or to be related by
a fixed public permutation π, as identities over the whole Boolean hypercube
(never a Fiat–Shamir hash chain; cf. the §4.3 insufficiency lemma).*

### W.1 Equality (copy) identity

For vectors u, u' ∈ F^(2^ℓ) (canonically extract_out(L) and input(L+1)):
u = u' ⟺ the difference multilinear d̃ = ũ − ũ' is the zero polynomial. The
checking routine draws ρ ∈ Fp2^ℓ (FS-derived after both vectors are
committed) and tests ũ(ρ) = ũ'(ρ) — two MLE opening claims at a shared point
with a shared value (`WiringEqualityOpeningClaims` emits them for the §2.4
evaluation argument; the direct whole-hypercube form evaluates both MLEs over
the raw vectors, as the unit tests do).

- **Completeness:** exact. u = u' ⇒ identical MLEs ⇒ the identity holds at
  every ρ, with probability 1.
- **Separation probability** (S2, Schwartz–Zippel): an invalid assignment
  (u ≠ u' in ≥ 1 entry) makes d̃ a nonzero ℓ-variate multilinear (total
  degree ≤ ℓ); it vanishes at uniform ρ ∈ Fp2^ℓ with probability ≤ ℓ/|Fp2|.
  Numbers at the κ = 2^28 column cap (ℓ = 28, log2|Fp2| = 127.99999999932):
  **2^-123.19 pre-grinding, 2^-83.19 after the 2^40 grinding budget** —
  clears the 2^-64 target with ≥ 19 bits of margin. Unequal logical lengths
  are a structural mismatch: deterministic reject (probability-0 event).
- Zero-padding both sides to the common 2^ℓ preserves the identity (pads are
  equal by construction); pad smuggling is separately closed by §2.5.

### W.2 Permutation identity (grand product, Plonk-style)

Claim: u'_j = u_{π(j)} for a fixed public bijection π (e.g. the materialized
transpose remap `MakeTransposePermutation`; the free-transpose fact of §1.2
makes this unnecessary for the canonical layout, where transposed reuse is a
point manipulation on one commitment). For FS challenges β, γ ∈ Fp2 drawn
after commitment, the running-product column z enforces

  z_0 = 1,  z_{i+1}·(u'_i + β·π(i) + γ) = z_i·(u_i + β·i + γ),  z_N = 1,

i.e. Π_i (u_i + β·i + γ) = Π_j (u'_j + β·π(j) + γ).

- **Completeness:** exact. u'_j = u_{π(j)} makes right factor j equal left
  factor π(j) (same value, same index tag), so the factor multisets coincide
  and z telescopes to 1 for every (β, γ) with no zero factor.
- **Separation probability:** by unique factorization in Fp2[β,γ] (the
  factors are monic in γ and pairwise non-associate for distinct (tag, value)
  pairs; index tags are injective since N ≤ 2^28 < p), the two products agree
  as polynomials iff the multisets {(i, u_i)} and {(π(j), u'_j)} coincide —
  which, π being a bijection, holds iff u'_j = u_{π(j)} for all j. Otherwise
  the difference is a nonzero polynomial of total degree ≤ N and S2 gives
  acceptance probability ≤ N/|Fp2| per challenge pair. Numbers:
  - single (β, γ), N = 2^28: **2^-100.0 pre-grinding, 2^-60.0 post — BELOW
    the 2^-64 target**; single-challenge ceiling is N ≤ 2^23
    (`kRCGkrWiringSingleChallengeMaxN`: 2^-105 pre / 2^-65 post).
  - **dual (β, γ)** (two independent pairs from one FS round, the same
    amplification pattern as the dual-α LogUp of §5.6): (N/|Fp2|)² =
    **2^-200.0 pre-grinding, 2^-160.0 post** at N = 2^28 — the shipping form
    at κ-sized columns.
- **Zero factors fail closed** (same posture as the LogUp denominators): any
  vanishing factor rejects with a resample reason (completeness resample
  probability ≤ 2N/|Fp2| per pair); it is never an accept path.

> **UPDATE (2026-07-22, margin restoration):** with ρ/β/γ drawn from F_{p^3}
> (|K| ≈ 2^192) the same closed forms give: equality (ℓ = 28)
> **2^-187.19 pre / 2^-147.19 post**; grand product at N = 2^28 single
> 2^-164 pre / 2^-124 post, **dual 2^-328 pre / 2^-288 post**. The Fp2
> single-challenge record (2^-60 post, BELOW 2^-64) is retained
> (`kRCGkrWiringPermutationSingleSepBitsFp2`) and **the dual mandate stays in
> force structurally** — the Fp3 lift does not reopen the single path.
> `kRCGkrWiringFieldBits` now carries 3·log2 p; the numbers are conditional on
> the `WiringChallengeFp2` cutover per INTEGRATION_REPORT.md.

### W.3 Cross-layer binding helper

`BindAdjacentLayerWires(wires)` binds extract_out(L) to the shape-designated
input of layer L+1 for every adjacent pair in Λ order (direct copy → W.1;
transposed copy → W.2 with the transpose π; no shape-compatible input →
reported "Λ-definitional", i.e. the pair shares a column reference per §4.2
and needs no copy constraint). `VerifyLayerBindings(bindings, fs_seed)`
checks every emitted constraint with FS-derived challenges. The choice of
consumer operand is by SHAPE only — values are never consulted, so a value
mismatch always surfaces as a failed identity, never a silent re-route.

### W.4 Acceptance obligations (tested)

- (a) Completeness: honest equality and honest permutation instances pass
  EXACTLY (multiple independent challenge points/pairs per test).
- (b) Separation bounds: the numbers of W.1/W.2 are asserted by
  `wiring_separation_bound_numbers`, including the explicit check that the
  single-challenge grand product at N = 2^28 is below target (the dual
  mandate) and the dual form clears it at 2^-160.
- (c) Counterexamples (invalid assignments): a one-entry difference fails
  equality (difference-MLE nonzero at ρ); a non-permutation fails the grand
  product three ways (faithful z from wrong data ⇒ z_N ≠ 1; boundary
  overwritten to 1 ⇒ a step identity fails; interior z perturbed ⇒ a
  neighboring step fails); position swaps with an unchanged value multiset
  fail (index tags bind positions); non-bijective π and zero factors reject
  structurally / fail closed.

Consensus posture unchanged: arbiter OFF, heights INT32_MAX, the int64
reference (`RecomputeResidentCurriculumReference`,
`RecomputeCoupledPuzzleReference`) untouched and authoritative.

---

## Appendix INT (2026-07-22) — G1–G5 integration + the COMPOSED separation bound

Constructions I–IV (`matmul_v4_rc_gkr_eval`, `_air`, `_wiring`) are merged and
wired into `VerifyWinnerProofV7` as the in-circuit relations **G1–G5**
(`CheckWinnerProofRelationsV7` in `matmul_v4_rc_gkr.cpp`). Each winner-proof
relation is now bound by a polynomial identity over the committed columns rather
than solely by native int64 re-derivation:

| Relation | Construction | Binding checked |
|---|---|---|
| **G1** | I (matrix opening) | `a_at_r = Ã(r_i,r_k)`, `b_at_r = B̃(r_k,r_j)` recomputed from the committed A/B columns must equal the carried `a_eval/b_eval`; `final_eval = a_at_r·b_at_r` (`RCGkrCheckFinalEvalBinding`); every **leaf** operand bound to its Λ MxExpand PRF expansion. |
| **G2** | I (segment point) | `c_ℓ = Ỹ(r_i,r_j)` recomputed from the committed Y trace-column segment (`RCGkrSegmentPoint`) must equal the carried `c_claim`. |
| **G3** | II + III | the prover-manufactured lookup is REPLACED by the Extract composition polynomial `Comp ≡ 0` (`EmitTileConstraints`/`ComposeConstraints`) + fixed-reference-vector membership (`BuildPreprocessedLogUpTables`/`VerifyLookupAgainstPreprocessed`, canonical T_M/T_X regenerated, never prover-chosen) + the sampler out-binding. |
| **G4** | IV (dual wiring) | `extract_out(L) == input(L+1)` over the true Λ provenance: direct copies via the equality identity, transposed copies via the **DUAL-challenge** grand product (`BuildWiringPermutationDual`/`VerifyWiringPermutationDual`) — the single-challenge form is UNREACHABLE on the ship path; plus the §6.3 round-root↔stream binding. |
| **G5** | I (residual binder) | Fwd `acc = claim + X̃(pt)` (`RCGkrCheckResidualAcc`); `extract_in == Y` for the non-residual layers. |

The relation gate runs **after** the existing §5.4/§5.7/§6.3 native grounding, so
it never changes which relation an already-rejected forgery *first* fails (the
base v7 soundness suite still observes `v7:ground:*`/`v7:logup:*`). The
integration red-team (`matmul_v4_rc_gkr_integration_tests.cpp`) additionally feeds
the five internally-consistent episode forgeries to the **standalone** relation
module and asserts each rejects at its `v7:g<N>:*` construction relation
(ArbitraryAbFactorization/FabricatedTraceWires → `v7:g1`, IdenticalFabricatedLookup
→ `v7:g3`, FabricatedExtractIO → `v7:g5`, UnrelatedLayerRoots → `v7:g4`) — the
constructions catch the forgery, **not only** the int64 re-derivation. Consensus
posture unchanged: arbiter OFF, heights INT32_MAX,
`RecomputeResidentCurriculumReference`/`RecomputeCoupledPuzzleReference`
untouched; `VerifyWinnerProofV7` is never consensus-authoritative and ExactReplay
remains the sole authority.

### The composed separation bound (`RCGkrComposedSeparationBits`) — Q = 128 + Fp3 (margin restored, 2026-07-22)

`RCGkrComposedSeparation(fri_proximity_bits)` combines the four constructions +
the batched-FRI backend + the SHA256d bindings by a log-sum-exp of the
per-relation acceptance probabilities, **PARAMETRIC in the FRI proximity bound**.
All values are −log2(acceptance), post the g = 40 grinding convention.

**The two margin levers of the previous revision are now APPLIED to the bound
accounting:** the fold query count is raised **Q = 116 → 128**
(`kRCFriNumQueries`, live in this tree), and every FS/algebraic challenge is
accounted over the **CUBIC extension K = F_{p^3}**, log2|K| = 3·log2 p =
191.999999999 (`kRCGkrChallengeFieldBits`), instead of F_{p^2} (≈ 128). The
Fp3-dependent rows below **hold only once the challenge-derivation call-sites
enumerated in INTEGRATION_REPORT.md ("Fp2 → Fp3 challenge sites") actually draw
from Fp3** — the F_{p^3} implementation is a parallel workstream; the FRI query
term (query repetitions) and the SHA term are field-independent and already
hold.

Per-term closed forms and old-vs-new numbers (post-grind g = 40 unless marked
"pre"):

| Term | Closed form (−log2, pre-grind) | Old (Q=116, Fp2) pre → post | New (Q=128, Fp3) pre → post |
|---|---|---|---|
| FRI fold proximity (v5, unique decoding α = 17/32) | Q·log2(32/17) | 105.85 → **65.85** | 116.80 → **76.80** |
| FRI batched query term (`FriBatchSoundnessBoundBits`, Q = 128 both revisions) | Q·log2(32/17) | 116.80 → 76.8 | 116.80 → 76.8 |
| Whole-protocol FS subtotal (sumcheck ≤ 2^13 rounds · 3/\|K\| + condensations 2^9/\|K\| + RLC γ/μ/λ/weights ≤ 2^16/\|K\| + dual-OOD + dual-α) | −log2(Σ …) | 111.5 → **72** (pinned) | 175.5 → **135.5** |
| — sumcheck rows alone | 3·2^13/\|K\| | 113.4 | 177.4 |
| — RLC batchings (γ, μ, λ, DEEP weights) | 2^16/\|K\| | 112 | 176 |
| — dual-OOD DEEP (z1, z2) | (2κ/(\|K\|−\|D\|))², κ = 2^28 | 196 | 326 |
| — dual-α LogUp (inside FS) | ((N_w+N_t)/\|K\|)², ≤ 2^44 | 168 | 296 |
| Construction I (eval opening, standalone sub-bound) | FS′×2^40 ⊕ FRI query ⊕ SHA | → **74** (FS-dominated) | → **76** (FRI-query-dominated) |
| Construction II composition (n_slots ≤ 256) | (n_slots−1)/\|K\| | 120 → **80** | 184 → **144** |
| Construction III dual-α membership (conservative N_w+N_t ≤ 2^44) | ((N_w+N_t)/\|K\|)² | 168 → **128** | 296 → **256** |
| Construction IV equality (ℓ = 28) | ℓ/\|K\| | 123.19 → **83.19** | 187.19 → **147.19** |
| Construction IV grand product, DUAL (N = 2^28) | (N/\|K\|)² | 200 → **160** | 328 → **288** |
| Construction IV grand product, SINGLE (excluded) | N/\|K\| | 100 → **60 (< 64!)** | 164 → 124 |
| SHA256d bindings (computational, 2^40-query adversary) | — | **88** | **88** |
| **COMPOSED (log-sum-exp of included terms)** | | **≈ 65.8** (margin **1.8** — INADEQUATE) | **≈ 76.80** (margin **12.8** — adequate; ≥ 74 bar cleared) |

Composed total at the Q = 128 fold floor (`kRCGkrFriProximityBitsV5 = 76.80`):

  **ε_total = Σ 2^-term ⇒ −log2(ε_total) ≈ 76.80 bits (ε_total ≤ 2^-76.79),
  margin over 64 ≈ 12.8 bits, over the 74-bit restored-margin bar
  (`kRCGkrComposedTargetBits`) ≈ 2.8 bits.**

The bound is **FRI-dominated** (the field-independent query-repetition term is
the floor; the next terms are SHA 88 and FS 135.5) and NON-VACUOUS on the sound
v5 fold. Honesty markers, stated plainly:

- **The fold floor and the batched query term now coincide** (both Q = 128).
  Plugging the conservative integer `FriBatchSoundnessBoundBits()` = 76 still
  composes to ≈ 76.0 ≥ 74 — the margin does not hinge on the fractional 0.80.
- **No included term is below 64**; the smallest algebraic term (FS subtotal
  135.5) is far above the bar. The historical Q = 116 floor (65.85) and Fp2 FS
  subtotal (72) are retained in the test as a pinned record.
- The **single-challenge** grand-product wiring netted only **60 bits over
  Fp2** — the origin of the dual mandate. Over Fp3 the single form would be
  124, but the **dual mandate is structural and is NOT relaxed** (G4 enforces
  the dual form; `kRCGkrWiringPermutationSingleSepBitsFp2 = 60` keeps the
  below-64 record asserted).
- **Arbiter posture unchanged:** `kRCGkrFormalSoundnessReady = false`,
  ExactReplay is the sole authority. This bound is audit accounting for the
  parameterization, not a consensus switch; the Fp3 rows are conditional on
  the challenge-site cutover listed in INTEGRATION_REPORT.md.

`RCGkrComposedSeparationBits()` returns ≈ 76.80; the term pins, the total, the
margin, the `!inadequate_margin` flag, and the ≥ 74 bar are asserted in
`gkr_integration_composed_separation_bound`.
