> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX MatMul v4.2 / BMX4 — Small-Alphabet Algorithmic-Shortcut Cryptanalysis (FINAL)

*Status: STUDY + DETERMINATION (final small-alphabet cryptanalysis deliverable). Not a
code change, not a spec edit, not an activation decision. Companion to
`doc/btx-matmul-v4-committed-object-redesign.md` (the alphabet choice and the §4.5
Four-Russians flag this document adjudicates), `doc/btx-matmul-v4-frontier-native-format.md`
(the BMX4 format definition), and `doc/btx-matmul-v4-design-spec.md` (authoritative,
UNCHANGED; §A.6, §C, §E.3, §D, §L.4, Appendix C-15 referenced throughout). Per spec
§0.7-(4) no market price appears anywhere below; per repo posture every hardware
throughput number is illustrative and measurement-gated, but the *closure arguments* in
this document are arithmetic/counting arguments that do not depend on any peak figure
being exact. Written 2026-07-16.*

---

## 0. Final verdict and per-shortcut table

**VERDICT: the alphabet is CRYPTOGRAPHICALLY SAFE for the PoW hardness argument, with
the conditions of §7.3.** Every small-alphabet shortcut channel is either **closed**
(non-viable by a counting or bandwidth argument with ≥ 2 orders of magnitude of margin)
or **bounded** at a small, difficulty-absorbable constant. The combined worst-case
honest-work reduction from all channels is **≤ ~20 % on legacy-INT8 hardware and ≈ 0 %
on the frontier FP4/FP8 path** — inside the program's existing "constant-factor,
difficulty-absorbed" posture (§A.6/§N.3-ii) and far below anything that would underprice
the PoW. No alphabet revision is *required*; one optional hardening (§7.4) is quantified
with its trade-off.

**Alphabet-variant note (scope pin).** Two nearby alphabets exist in the companion docs:
the redesign's reference **F\*** = `𝓜₁₁ = {0, ±1, ±2, ±3, ±4, ±6}` (11 values,
min-entropy log₂11 = 3.46 bits/element, scales 2^e, e ∈ [0,3], E_max = 48), and the
frontier-format doc's as-specified **BMX4** = the full ×2-normalized E2M1 set
`𝓜₁₅ = {0, ±1, ±2, ±3, ±4, ±6, ±8, ±12}` (15 values, 3.91 bits, S = 4, E_max = 192).
This document analyzes **𝓜₁₁ (the tasked alphabet) as primary** and states where 𝓜₁₅
differs; every closure below holds for both (𝓜₁₅ is strictly farther from every cliff,
at the cost of wider accumulation bounds — §7.4). The format owner must pin ONE of the
two in the v4.2 edition; the current doc-pair discrepancy is itself a finding (§7.5).

| # | Shortcut | Verdict | Quantified bound (𝓜₁₁, n = 4096, b = 4, m = 1024) |
|---|---|---|---|
| 1 | Four-Russians / table lookup vs template-scoped V (and mailman variant) | **CLOSED** | Best adversarial variant (t = 4, s16 entries, L2-resident per-chunk tables): ≥ ~30–100× slower than the tensor path on the same silicon; DRAM variant ≥ ~240×. The flagged ~23 GB/nonce figure **CONFIRMED** at its stated parameters (t = 3, 4-byte entries); adversary-optimal tightening reaches 8.6 GB/nonce — conclusion unchanged. Opening condition: effective alphabet ≤ ~1.1–1.5 symbols (§2.6) — i.e. only at/below the ternary cliff |
| 2 | Strassen / Winograd / bilinear recursion | **BOUNDED; mantissa-plane subcase REOPENED quantitatively** | Exactly **one** recursion level on INT8-path hardware (⌊log₂(127/48)⌋ = 1); **zero** levels on the FP4/FP8-exact frontier path (level-1 operand sums are not E2M1/E4M3-exact). The pre-axis-correction ≥5× mantissa-plane estimate used the former scale orientation and must not be quoted for the corrected object (§3.3). |
| 3 | Low-rank / structured operands (I2/I3) | **CLOSED** | Singularity ≤ (1/√2 + o(1))ⁿ ≈ 2⁻²⁰⁴⁸; no near-rank-deficiency (σ_min ≳ n^(−1/2) whp); 2:4 structured sparsity impossible by counting (needs ≥ 50 % zeros/row; alphabet gives 9.09 %); fine zero-skip ≤ 9.1 % |
| 4 | BNN/XNOR popcount collapse (the cliff) | **CLOSED — safely above** | Exact bit-plane decomposition needs 3 signed planes/operand → 9 plane-pairs ≈ 27 binary-GEMM passes ≈ the cost of the real ≤3-bit multiply itself; ~9× above a ternary object, ~18–27× above sign-only in bit-ops. Non-power-of-two magnitudes {3, 6} (mass 4/11 = 36 %) forbid a shift-only datapath. No popcount path beats the real multiply |
| 5 | Other bilinear / precompute / memoization | **CLOSED / absorbed** | t-run memoization = channel #1 (same traffic bound); product-histogram, scale-plane masking, cross-nonce block collisions (2⁻⁷⁵ per template sweep), AlphaTensor-class bilinear algorithms (same range barrier as #2), estimate-then-patch (I6) — each individually bounded in §6 |

---

## 1. The object and the priced work unit

Committed object (v4.2/BMX4 candidate): exact integer matmul `C = Â·B̂` with
`Â[i,k] = μ_A[i,k]·2^(e_A(⌊i/32⌋,k))` and
`B̂[k,j] = μ_B[k,j]·2^(e_B(k,⌊j/32⌋))`, `μ ∈ 𝓜₁₁`, `e ∈ [0,3]`; sketch
`Ĉ = U·C·V ∈ F_q^{m×m}`, q = 2⁶¹−1, digest `H(σ‖Ĉ)`, Freivalds R = 3. Seed scoping per
spec §A.2 v4.1 / I1′: **A, U, V template-scoped; B, σ nonce-fresh.** U, V drawn over 𝓜
(|u|,|v| ≤ 6, scale-free) per the redesign F\* row.

The unit difficulty prices is the **marginal per-nonce unit** (spec §E.3/I1′):

| Stage | Size (n = 4096, m = 1024) | Unit |
|---|---|---|
| Expand B̂ (wide SHA XOF) | ≈ 0.39 M compressions (≈ 5.9 bits/element) | SHA/int |
| `Q = B̂·V` | n²m ≈ 1.72×10¹⁰ MACs | tensor (FP4-native) |
| Combine `P·Q` | n·m² ≈ 4.3×10⁹ mod-q MACs (ALU) or 16 limb GEMMs ≈ 6.9×10¹⁰ s8 MACs (tensor) | ALU / tensor |
| Serialize + digest | SHA over 8 MiB | SHA |

Two standing facts frame everything below: (i) **Freivalds soundness is
alphabet-blind** (redesign §2 — error ≤ 2/q per round regardless of operand entropy;
distinct committed entries differ by ≤ 2·E_max²·n = 2·2304·4096 < 2²⁵ ≪ q, so no
aliasing); a shortcut can therefore only attack the *work*, never the *verifier*.
(ii) Any candidate shortcut must produce the **bit-exact** committed object (I6) — all
approximation channels are structurally out.

**Amortization scoping (which stages a shortcut can even touch).** Anything that speeds
the template-scoped stage S0 (expand A/U/V, `P = U·Â`) saves *nothing* from the marginal
unit — S0 is already amortized across the nonce sweep by design (I1′). A small-alphabet
shortcut is only material if it attacks **expand-B, `B̂·V`, the combine, or the digest**.
The digest and XOF are SHA (no alphabet lever beyond the already-counted 28 % XOF-bit
shrink, priced in the redesign §2). The combine's factors P, Q are **not**
small-alphabet objects (entries up to n·6·48 ≈ 2²¹; limb digits are 64-valued) — no
table channel exists there (§2.5). So the entire small-alphabet attack surface reduces
to **`B̂·V`: a nonce-fresh 11-symbol matrix times a template-fixed 11-symbol projector**
— which is exactly the channel the redesign flagged and this document closes.

---

## 2. Shortcut 1 — Four-Russians / table lookup against template-scoped V

### 2.1 The construction, stated adversarially

[Arlazarov–Dinic–Kronrod–Faradzhev's method](https://en.wikipedia.org/wiki/Method_of_Four_Russians)
(and its matrix-vector form, the
[Liberty–Zucker mailman algorithm](https://edoliberty.github.io/papers/mailmanAlgorithm.pdf),
which computes an n×n small-alphabet matvec in O(n²/log n) after O(n²) preprocessing —
[IPL 2009](https://www.sciencedirect.com/science/article/abs/pii/S0020019008002949))
is *the* textbook small-alphabet shortcut. Applied to `Q = B̂·V`:

- Partition the reduction dimension into ⌈n/t⌉ chunks of t consecutive rows of V.
- Per chunk, precompute ALL |𝓜|^t = 11^t coefficient combinations
  `T_chunk[c] = Σ_{j<t} c_j·V[k+j, :]` (each an m-vector). Tables depend **only on V**
  → **template-scoped, amortized across the whole nonce sweep** — this is what makes
  the channel I1′-adjacent and new relative to nonce-fresh-everything v4.0.
- Per nonce: for each row i of B̂ and each chunk, read the t-symbol mantissa pattern,
  gather the precomputed m-vector, shift by the (chunk-constant¹) block scale
  `2^(e_B)`, and add into the accumulator row. Replaces `t·m` MACs with **one m-vector
  gather + m adds**.

¹ Scales are per 32-element block; t | 32 (t = 4) keeps every chunk inside one scale
block. t = 3 straddles ~1 chunk in 11 (two sub-gathers) — a small constant against the
attacker; ignored below (adversary-favoring).

Table entries: |Σ| ≤ t·6·6 = 36t → **int16 suffices for t ≤ 910** (w = 2 bytes), int32
(w = 4) conservative.

### 2.2 CONFIRMING the flagged ~23 GB/nonce figure

At the redesign's stated point (t = 3, w = 4):

- Chunks: ⌈4096/3⌉ = 1366. Table size: 1366 · 11³ · 1024 · 4 B = **7.4 GB** (the
  redesign's "~15 GiB" used w = 8 F_q words — a sizing inconsistency in that doc, but
  in the attacker's favor either way; tables fit HBM at every w).
- Traffic: each of n = 4096 rows × 1366 chunks does one gather of m·w = 4 KiB →
  4096 · 1366 · 4 KiB = **22.9 GB of table reads per nonce.**

**The ~23 GB/nonce figure is CONFIRMED — it is exactly n·(n/t)·m·w at t = 3, w = 4.**

### 2.3 Tightening it for the adversary (the redesign under-optimized the attack)

The honest adversarial question is not "is 23 GB big" but "what is the *cheapest*
variant." Optimizing every free parameter:

| Variant | t | w | Table total | Per-nonce table traffic | Feasible where |
|---|---|---|---|---|---|
| Flagged (redesign §4.5) | 3 | 4 | 7.4 GB | 22.9 GB | HBM |
| int16 entries | 3 | 2 | 3.7 GB | 11.5 GB | HBM |
| **Adversary-optimal DRAM** | 4 | 2 | 30.7 GB | **8.6 GB** | HBM (fits 192 GB B200-class) |
| t = 5 | 5 | 2 | **270 GB — exceeds any HBM** | — | infeasible |
| **Adversary-optimal SRAM** | 4 | 2 | one chunk's table = 11⁴·1024·2 = **30 MB, L2-resident**; stream chunk-by-chunk | 8.6 GB *from L2*, + 4.3×10⁹ vector-ALU adds | L2 ~50 MB parts |

Cost of the best variants against the honest tensor evaluation of the same stage
(B200-class illustrative rates; the *ratios* are what matter and they are ≥ 10²
everywhere):

- **Honest `B̂·V`:** 2·1.72×10¹⁰ ops at dense FP4 ≈ 7.7×10¹⁵ ops/s → **≈ 4.5 µs**,
  streaming ~25 MiB (packed B̂ nibbles 8 MiB + scales + Q writeback).
- **DRAM variant:** 8.6 GB at 8 TB/s → **≥ 1.07 ms ≈ 240× slower**, and 340× the
  honest bytes.
- **SRAM variant:** 8.6 GB of *random-indexed* L2 gathers at an optimistic ~15–20 TB/s
  → ≥ 0.43 ms, **plus** the surviving adds — n²m/t = 4.3×10⁹ int adds on vector ALUs
  (~3×10¹³ add/s optimistic) → ≥ 0.14 ms. Total **≥ ~0.5 ms ≈ 100× slower**, even
  granting perfect gather throughput.

### 2.4 Why the closure is structural, not parametric

Two independent inequalities, either fatal:

1. **The multiply→add trade targets the wrong bottleneck.** Four-Russians replaces
   multiplies with table adds — but on tensor-core hardware a tensor MAC is ~50–250×
   *cheaper* than a vector-ALU add (tensor:vector op-rate ratio R_v ≈ 250 on
   B200-class). The lookup path keeps n²m/t adds on vector units; beating the tensor
   path needs **t ≥ R_v/2 ≈ 125**, hence a table of 11¹²⁵ ≈ 10¹³⁰ entries.
2. **The gather traffic replaces arithmetic with bytes at a losing exchange rate.**
   Each gather trades 2t·m tensor ops for m·w bytes: a saving rate of 2t/w ops/byte
   (t = 4, w = 2: **4 ops/byte**) against a machine balance of ~400–960 tensor
   ops/byte (L2/HBM). Break-even needs t ≥ w·R_b/2 ≈ 400–960 → table 11⁴⁰⁰.

The same two inequalities kill the **mailman** form (its op reduction is
log₁₁ 4096 ≈ **3.5×** at this dimension — a t ≈ 3.5 chunking in disguise — executed on
units ≥ 50× slower per op), and the **transposed** form (tabulating B̂'s column-chunk
combinations indexed by V's patterns: identical traffic n·(n/t)·m·w by symmetry, plus a
per-nonce table-build of (n/t)·11^t·n adds ≈ 7.4×10⁹ vector adds at t = 3 — already
≥ the honest stage cost before any gather).

**Amdahl backstop (independent of all of the above):** the channel attacks only the
`B̂·V` stage — ~20–50 % of marginal MACs depending on the combine path, and on
FP4-native parts only ~10 % of marginal wall-time (§1 table: 4.5 µs of a ~40–100 µs
unit dominated by the limb combine + SHA). Even a **zero-cost oracle** for `B̂·V` would
reduce honest work by at most that share; the actual table path is instead 10²× slower.

### 2.5 The analogous channels, checked one by one

- **Against template-scoped A/U (`P = U·Â`):** computed once per template (stage S0,
  amortized, excluded from the marginal unit by I1′-4). A table shortcut there saves
  nothing that difficulty prices. **No channel.**
- **Against the combine `P·[Q₁|…|Q_Q]`:** neither factor is small-alphabet — P, Q
  entries are ≤ n·6·48 ≈ 2²¹ integers; the C-13 limb decomposition's digits are
  64-valued (base-2⁶/2⁷ balanced), so a table is 64^t — strictly worse than 11^t at
  every t. **No channel** (a fortiori by §2.4).
- **Against nonce-fresh B̂ (tables over B̂):** table build cost is per-nonce
  (unamortizable), ≥ the honest stage cost by itself (§2.4 transposed form). **No
  channel.**
- **Verifier-side four-Russians/mailman** (matvecs over small-alphabet A, B in §E.2):
  would make *verification* marginally cheaper — hardness-neutral, harmless, requires
  no action.

### 2.6 The precise condition under which this channel would open

This is the closest-to-viable channel in the whole family, so the opening condition is
stated exactly. The channel opens iff there exists a chunk depth t with

```
|𝓜|^t · m · w  ≤  SRAM        (per-chunk table residency)
2t              ≥  R           (op-exchange break-even, R = tensor:scalar ratio)
```

i.e. `|𝓜| ≤ (SRAM/(m·w))^(2/R)`. With SRAM = 50 MB, m·w = 2 KB, R ≈ 100–250 (any
tensor-core-era part): `|𝓜| ≤ 24,400^(0.008..0.02) ≈ 1.1–1.5`. **Only effective
alphabets of ~1.5 symbols or fewer — i.e. heavily-zero-massed binary/ternary objects —
open the table channel on tensor-class hardware.** That is the same boundary as the BNN
cliff (§5): the two hazards are one hazard, and 𝓜₁₁ (11 symbols, 3.46 bits) sits ~3
octaves above it. On table-optimized *custom* hardware the channel is bandwidth-bound
by construction (8.6 GB/nonce of mandatory gather traffic vs ~25 MiB honest streaming —
~340× the bytes), which is precisely the §L.4 bandwidth-collapse regime the spec
already closes: a table ASIC would need ≥ ~100 TB/s of random-gather bandwidth to
merely tie a B200's 4.5 µs tensor stage, on > n× the silicon of a MAC array.

Residual obligation: **this family must still be named in the C-15 external
adversarial review scope** (spec Appendix C-15 / ACTIVATION B4) — the closure above is
an engineering-inequality argument over known algorithm families, not a lower-bound
theorem for `M·Bᵢ·V` evaluation, and the redesign's condition ledger #8 already
requires exactly this. Confirmed as the correct disposition.

---

## 3. Shortcut 2 — Strassen / Winograd / bilinear recursion

### 3.1 The recursion-depth arithmetic (the range barrier, re-derived)

Strassen-level linear combinations sum two operand blocks per level, so after d levels
operand entries reach `E_max·2^d`. Eligibility per exact path:

| Path | Exact-operand constraint | d_max for 𝓜₁₁ (E_max = 48) | d_max for 𝓜₁₅@S=4 (E_max = 192) | d_max today (s8, E_max = 125) |
|---|---|---|---|---|
| INT8 tensor (s8 operands, ±127) | 48·2^d ≤ 127 | **1** (96 ✓; 192 ✗) | **0** (already 192 > 127 → 2-slice; sums 384 need 3 limbs) | **0** (250 > 127 — spec §A.6) |
| FP4 E2M1 pipe | sums must BE E2M1 values | **0** — 45+32 = 77 ∉ E2M1·2^e grid | 0 | n/a |
| FP8 E4M3 pipe | sums exactly E4M3-representable (ints ≤ 16, then even-only, …) | **0** — e.g. 77 needs 7 significand bits > E4M3's 4 | 0 | n/a |
| Accumulator (int32) | level-1 products ≤ n·96² = 3.77×10⁷ < 2³¹ | ✓ (not binding) | ✓ | ✓ |

**Confirmed: exactly one recursion level, and only on the INT8-path.** The prior claim
(≤ ~12.5 %, one level, difficulty-absorbed) is correct and is now shown to be
**class-restricted**: the FP4/FP8 frontier path gets **zero** levels, because Strassen's
operand sums leave the exact-representable envelope of the narrow FP formats entirely
(the same no-rounding discipline that admits the hardware forbids the recursion on it).
A frontier miner choosing Strassen must drop to its INT8 pipe: on B200-class parts that
is 3,927·(8/7) ≈ 4,488 effective TOPS vs 7,702 direct FP4 — **Strassen is never the
optimal frontier strategy at all**. On INT8-only legacy parts, one level saves ≤ 1/8 of
tensor multiplies minus O(n²) extra add passes and worse locality (practical gains at
n = 4096 tile sizes are historically well under the theoretical 12.5 % — cf.
[Strassen on GPUs, ACM TOMS 2020](https://dl.acm.org/doi/fullHtml/10.1145/3372419);
[CUTLASS Strassen, arXiv:1808.07984](https://arxiv.org/pdf/1808.07984) — 1-level
implementations report single-digit-% net wins at these sizes, with operand-count and
memory-op growth eating the margin).

The same limb arithmetic applies to the combine's 16 limb GEMMs (digits [−32,31]:
32·2 = 64 ≤ 127 → one level there too) — so the global theoretical cap on the whole
marginal unit is (7/8) of tensor multiplies = **12.5 %**, on INT8-path hardware only.

### 3.2 Winograd and modern bilinear algorithms (AlphaTensor-class)

Winograd's 7-multiply variant has the same combination structure (same range growth).
Rank-48-and-below 4×4 algorithms (AlphaTensor's mod-2 rank-47 is char-2 only;
general-field improvements use non-integer/complex coefficients) either (a) use ±1
integer combinations → same `E_max·2^d` barrier, d ≤ 1; or (b) use fractional
coefficients → intermediates leave the exact-s8/E4M3 operand envelope, inadmissible on
any narrow exact path (they would be exact only in ≥ int32 operand arithmetic, which
has no tensor unit). **The range barrier is coefficient-structural: it caps every
bilinear-recursion family at the same one level, not just classical Strassen.**

### 3.3 The adversarial mantissa-plane variant (axis correction; quantitative bound open)

Because mantissas alone are ≤ 6, mantissa-plane Strassen could in principle recurse to
6·2^d ≤ 127 → **d = 4** (0.586× multiplies). The pre-activation axis correction changes
the algebra used by the earlier closure. For an output row block `rb` and column block
`cb`, the corrected object has

`C[rb,cb] = Σ_k 2^{e_A(rb,k)+e_B(k,cb)} μ_A[rb,k] μ_B[k,cb]`.

The scale still depends on the contraction index and both output blocks, so it cannot
be factored into one global pure-mantissa GEMM. However, the old n×32×n slab argument
and its derived `16·(7/8)^4 = 9.4×` / `≥5×` estimates described the transposed scale
layout and are not evidence for this corrected object. Re-run the adversarial masked-
GEMM/Strassen search against the formula above before calling this subcase closed. The
direct dequantized-INT8 range bound in §3.1 (at most one recursion level) is unchanged.

### 3.4 Disposition

Bounded-advantage: **≤ 12.5 % of tensor multiplies, INT8-path only, ~0 % frontier
path**, uniform across miners (hardware-agnostic within the class), absorbed by the
§I.4 difficulty calibration exactly like today's ≤ 1.2–1.3× posture. The spec's §A.6
text must be rewritten for v4.2 (the s8-range sentence is false under E_max = 48) — the
redesign's invariant-table row and condition #9 already require this; confirmed.

---

## 4. Shortcut 3 — low-rank / structured operands (I2/I3)

**Singularity/low-rank probability.** Operand entries are i.i.d. uniform over 𝓜₁₁
(symmetric, mean 0, variance 132/11 = 12, max atom probability 1/11). For i.i.d.
discrete non-degenerate entries the singularity probability of an n×n matrix is
exponentially small: ≤ (1/√2 + o(1))ⁿ generally
([Bourgain–Vu–Wood, JFA 2010](https://arxiv.org/abs/0905.0461)), (1/2 + o(1))ⁿ even in
the hardest ±1 case ([Tikhomirov, Annals 2020](https://arxiv.org/abs/1812.09016)); with
max atom 1/11 the truth is ≈ (1/11)^n-order (dominated by single-row/column-collision
events). At n = 4096: **≤ 2⁻²⁰⁴⁸, in truth ≈ 2⁻¹⁴¹⁷⁰-order**. The prior claim (singularity
≤ 2^−Ω(n), full-rank whp) is **confirmed with ~three orders of magnitude of exponent to
spare**. Near-low-rank is equally dead: smallest-singular-value bounds for i.i.d.
subgaussian entries give σ_min ≳ c·n^(−1/2) except with probability Cε + cⁿ
(Rudelson–Vershynin class), and I6 forbids approximate products anyway, so even a
*near*-deficiency would be unusable — the only exploitable structure would be an exact
algebraic one, and none exists in an i.i.d. draw except with the probabilities above.

**Zero mass and sparsity units.** P(0) = 1/11 = 9.09 %:

- **Fine-grained zero-skipping:** ≤ 9.09 % MAC discount, bespoke-hardware-only
  (commodity dense tensor pipes skip nothing), difficulty-absorbed; matches the
  redesign's ≤ P(0) bound. Confirmed.
- **2:4 structured sparsity (the only commodity sparse speedup):** requires *every*
  group of 4 along K to hold ≤ 2 nonzeros. Per-group probability
  P(Bin(4, 1/11) ≥ 2) = 0.0438; all n²/4 groups conform with probability
  ≈ 0.0438^(n²/4) → **0 at cosmological precision**. Stronger, by *counting*: legal 2:4
  use needs ≥ 50 % zeros per row; the alphabet supplies 9.09 % (≈ 372 zeros per
  4096-row) — no permutation or re-blocking the miner applies can manufacture the
  deficit, because consensus fixes the entries and zero-count is
  permutation-invariant. **Closed by counting, not by probability.**
- **I3 (additive split):** B̂ — mantissas AND scale plane — is wholly nonce-fresh.
  Under the corrected axes each output-block pair sums K-indexed terms weighted by
  `2^{e_A(rb,k)+e_B(k,cb)}`; every term still contains nonce-fresh B mantissa and scale
  data, so there is no nonce-invariant additive term. The (M, E) pair is multiplicative
  per-entry structure, not a cacheable split. Confirmed.

**Cross-nonce entropy floor (the structural-collision check).** The smallest
independently-reusable unit is the 32-element scale block: ≈ 32·3.46 + 2 = 112.7 bits.
Per operand there are n²/32 = 2¹⁹ blocks; over a Q = 2²⁰-nonce template sweep,
collision expectation ≈ (2³⁹)²/2·2⁻¹¹²·⁷ ≈ **2⁻³⁵** — no memoizable repetition above
the t ≤ 6 short-run scale, and short-run repetition *is* the table channel, already
priced (§2). I2/I3 survive with the stated floor (min-entropy ≥ 3.4 bits/element,
≥ 4 nonzero magnitudes, P(0) ≤ 10 %) — 𝓜₁₁ sits exactly at 3.46/5/9.09 %, satisfying
all three with no slack to give away (a reason to prefer 𝓜₁₅'s 3.91 bits if margin is
wanted, §7.4).

---

## 5. Shortcut 4 — the BNN/XNOR cliff, and the margin above it

**The cliff, defined.** For sign-only {±1} operands a MAC is 1 XNOR + popcount
(1 bit-op); for ternary {0,±1}, ~2–3 bit-ops with masks
([XNOR-Net lineage](https://arxiv.org/pdf/1705.09864); FPGA/CIM BNN fabrics post
~15×–1000× energy/op vs INT8 —
[BNN-vs-INT8 hardware surveys](https://pmc.ncbi.nlm.nih.gov/articles/PMC10675041/),
[HyBNN, ACM TRETS](https://dl.acm.org/doi/10.1145/3631610)). An s8 MAC is ~49–64
partial-product bit-ops. The cliff is real and is why sign/ternary committed objects
are categorically rejected (redesign §4.2). The question: can 𝓜₁₁ be *reduced* to the
cheap side?

**The exact decomposition cost (the margin, quantified).** The general principle —
bit-serial/composable-precision hardware costs ∝ the *product of operand bit-widths*
([Bit Fusion, ISCA 2018](https://arxiv.org/pdf/1712.01507)) — makes the reduction
attempt calculable:

1. Magnitudes {0..6}\{5} span bits 0–2 (3 = 011₂, 6 = 110₂): **3 binary planes**
   minimum; with sign, 3 signed-ternary planes `d_p ∈ {−1,0,1}`, `μ = Σ 2^p·d_p`.
2. The bilinear product then needs **9 plane-pairs** (3×3), each a ternary×ternary
   GEMM ≈ 2–3 binary passes (support-mask AND + sign XNOR + popcounts) → **≈ 18–27
   binary-GEMM passes + shift-add recombination**, vs 1–1.5 passes for a sign object
   and ~3 for ternary.
3. Equivalently in multiplier-area terms: a direct exact 𝓜₁₁ MAC is a ~3×3-bit
   multiply ≈ 9–12 bit-ops — **the bit-plane decomposition reconstitutes the multiplier
   exactly (9 plane-pairs ≈ 9 partial products); the popcount route offers ~0×
   advantage over just building the small multiplier.**

**Margin statement: 𝓜₁₁ sits a factor ≈ 9× above the ternary collapse and ≈ 18–27×
above the sign-only collapse in bit-operation count, and — decisively — the collapse
is not merely expensive but *pointless*: decomposition costs ≥ the real multiply it
would replace.** Cross-check on real silicon: Turing/Ampere 1-bit tensor cores (BMMA,
XOR/AND popcount) ran at ~8× the INT8 MMA rate
([Bit-Tensor-Core BNN work](https://www.researchgate.net/publication/347849600_Accelerating_Binarized_Neural_Networks_via_Bit-Tensor-Cores_in_Turing_GPUs));
27 passes ÷ 8× ≈ **3.4× slower** than one direct INT8 GEMM — and INT1/INT4 tensor
support was dropped from Hopper-generation documentation onward
([Hopper microbenchmark, arXiv:2402.13499](https://arxiv.org/pdf/2402.13499),
[SemiAnalysis tensor-core evolution](https://newsletter.semianalysis.com/p/nvidia-tensor-core-evolution-from-volta-to-blackwell))
— the commodity hardware constituency for the cliff is *shrinking*, not growing.

**The shift-only sub-hazard (load-bearing alphabet property, previously implicit).**
An alphabet of powers of two {0,±1,±2,±4} collapses multiplication to a barrel shift —
no multiplier at all, a distinct (weaker) cliff adjacent to BNN. 𝓜₁₁ escapes it
through **3 and 6 — the non-power-of-two magnitudes, combined mass 4/11 = 36.4 %** —
which force a genuine add-limb (μ·x = (x≪1)+x for 3; ((x≪1)+x)≪1 for 6) in any exact
datapath. This is the single most load-bearing structural feature of the alphabet and
must be pinned as a consensus-design condition (§7.3-c): **never reduce the alphabet to
powers of two; keep ≥ 2 non-power-of-two magnitudes at ≥ ~25 % combined mass.** (𝓜₁₅
keeps {3, 6, 12} at 6/15 = 40 % — also fine.)

**What the alphabet honestly concedes (and where it is priced).** A real 𝓜₁₁ MAC *is*
~5–7× cheaper in bit-ops than an s8 MAC (3×3 ≈ 9–12 vs 7×7 ≈ 49–64) — that is the
intended frontier-native narrowing, visible in commodity FP4 = ~2× INT8 rates, and its
bespoke-silicon consequence is the redesign §4.3 ASIC residual (~1.5–2× → ~2–3×), owned
by the companion ASIC/FPGA deep-dive. It is a *hardware-ratio* question, not an
absolute-work shortcut: the MAC count is unchanged, every class's MAC got cheaper by
roughly the same factor, and difficulty absorbs the level shift. **No popcount,
bit-serial, or LUT-fabric evaluation strategy computes the committed object in fewer
bit-operations than the direct narrow multiply — the alphabet is safely above the
cliff.**

---

## 6. Shortcut 5 — remaining precompute/memoization channels, enumerated

| Channel | Analysis | Verdict |
|---|---|---|
| **t-run memoization** ("same t-symbol pattern recurs, cache its contribution") | Identical to §2 with implicit tables: patterns of length t ≤ 6 do recur (11^t < #instances for t ≤ 6), but each reuse trades tensor MACs for gathers/adds at the §2.4 losing exchange rate | Closed (≡ §2) |
| **Product histogram** (`C_ij = Σ_v v·N_ij(v)` over the 13 distinct \|product\| values) | Computing the counts N_ij(v) requires classifying every (i,k,j) triple — ≥ the MAC work in comparisons | Closed |
| **11×11 product LUT in registers** | Standard; equals "a real multiply" in cost on every unit (the multiply is not the bottleneck — the accumulate is); no asymptotic change | Neutral |
| **Scale-plane masking / per-class GEMM splitting** | 16-fold GEMM explosion vs 25 % density — ≥ 5× loss even with idealized sparse units (§3.3) | Closed |
| **Scale grinding / footprint variation (I8)** | Scale planes are fixed-size, block-aligned, footprint-invariant; work is magnitude-independent (MAC count does not depend on values), so no nonce-selection discount exists to grind | Closed |
| **Cross-nonce B collisions / birthday memoization** | 112.7-bit blocks: 2⁻³⁵ expected collisions per 2²⁰-nonce sweep (§4); finding sub-block collisions costs more indexing traffic than the ~4 ns of tensor work each would save | Closed |
| **Estimate-then-patch / approximate GEMM** | I6: digest equality demands the exact Ĉ; Freivalds catches any wrong word with 1−2/q | Closed (unchanged) |
| **XOF-structure shortcuts** (correlated elements, lazy expansion) | Elements are rejection-sampled SHA-256 counter-mode output (C-12); any exploitable structure is a PRF break, out of model; any correct Ĉᵢ must read all of B̂ᵢ (n²·3.46 bits of fresh entropy) — the expand-B floor stands, 28 % cheaper than s8 in SHA bits and already re-priced | Closed / re-priced |
| **Freivalds-side small-field tricks** | Soundness is alphabet-blind (§1); the sketch/challenge algebra lives over F_q, untouched | Closed (unchanged) |
| **Batch algebra over fixed (P, V) beyond tables** | No sub-n²m evaluation of `M·Bᵢ·V` for dense pseudorandom Bᵢ is known; the small alphabet's only known lever on it was §2 (closed). "No known" ≠ theorem — stays under C-15 external review, scope explicitly including the small-alphabet family | Open-risk, inherited, review-gated (not alphabet-created: the redesign is correct that the alphabet adds the §2 candidate and §2 closes it) |

---

## 7. Combined determination

### 7.1 Total honest-work reduction from all shortcuts

| Class | Applicable shortcuts | Combined worst case |
|---|---|---|
| Frontier FP4/FP8 path (the intended winners) | none (Strassen d = 0; tables 10²× losers; zero-skip unavailable on dense pipes) | **≈ 0 %** |
| Legacy INT8 path | Strassen level-1 (≤ 12.5 % of tensor multiplies, practically less) | **≤ 12.5 % theoretical** |
| Bespoke silicon (bounding case) | Strassen level-1 × perfect fine zero-skip (9.09 %) | **≤ 1 − 0.875·0.909 ≈ 20.5 % theoretical** |

All components are hardware-class-uniform within their class, known in advance,
constant-factor, and absorbed by the §I.4 marginal-unit difficulty calibration — the
same disposition as the existing ≤ 1.2–1.3× §A.6 posture. **Nothing here underprices
the PoW**, and none of the viable residues is memory/table-bound (the only
table-shaped channel is closed at ≥ 10²×), so nothing favors table-optimized custom
hardware either.

### 7.2 FINAL answer

**The {0,±1,±2,±3,±4,±6} × 2^e committed alphabet is cryptographically SAFE for the
BMX4/v4.2 PoW hardness argument.** Every small-alphabet shortcut that dense-s8
forecloses and BMX4 could have reopened is either closed with ≥ 2 orders of magnitude
of margin (tables/four-Russians/mailman, BNN collapse, low-rank/sparsity) or bounded at
a small difficulty-absorbable constant (one Strassen level, ≤ 12.5 %, legacy path
only). The alphabet sits ~9× above the popcount cliff in bit-op terms and ~3 octaves
above the table-channel opening condition (~1.5 effective symbols). **No alphabet
revision is required.**

### 7.3 Conditions (normative for v4.2 adoption; extends the redesign §8 ledger)

- (a) **C-15 external review scope** must name, verbatim: four-Russians/mailman tables
  over template-scoped V, the transposed and SRAM-resident variants of §2.3, and batch
  algebra over fixed (P, V) — with §2.6's opening condition as the reviewers' target
  to attack. (Restates redesign condition #8 with the sharpened scope.)
- (b) **§A.6 rewrite** for the one-level Strassen fact (E_max = 48 ⇒ d = 1 on INT8
  paths, d = 0 on FP4/FP8 paths); difficulty calibration measured on the optimal miner
  per §I.4 (which absorbs it automatically).
- (c) **Alphabet floor, sharpened** (supersedes the redesign's floor with one addition):
  min-entropy ≥ ~3.4 bits/element; ≥ 4 distinct nonzero magnitudes; P(0) ≤ 10 %;
  sign/ternary rejected; **and ≥ 2 non-power-of-two magnitudes with ≥ ~25 % combined
  mass** (the anti-shift-only clause, §5 — {3, 6} at 36.4 % satisfies it). Any future
  re-weighting of the sampler must re-check all four.
- (d) **No template-scoped structure on B's planes** (mantissa or scale) — restates
  redesign condition #6; it is what keeps §2's tables confined to the V side.

### 7.4 Optional hardening, quantified (NOT required)

Adopting the full 15-value E2M1 set 𝓜₁₅ = {0,±1,±2,±3,±4,±6,±8,±12} (the
frontier-format doc's literal BMX4) would: raise per-element min-entropy 3.46 → 3.91
bits; enlarge tables to 15^t (t = 4 table ≈ 106 GB — DRAM-marginal); raise E_max to 96
(S = 3) or 192 (S = 4), **closing even the single INT8 Strassen level** (96·2 = 192 >
127); add a 4th bit-plane (16 plane-pairs, further from the cliff); and cost nothing on
FP4 hardware (it IS the native value set, with one fewer rejected nibble pattern).
**Trade-off:** at S = 3 the base-GEMM bound becomes n·E_max² = 9216n ≈ 2²⁵·² at
n = 4096 — the sub-2²⁴ envelope is lost, and with it the redesign §4.4 "FP32-accumulate
eligible by bound" property (t = 24 still suffices with a K′ ≈ 448-style promotion
cadence, but no longer with *zero* promotions). The choice is a format-owner decision
between shortcut margin (𝓜₁₅) and accumulator-eligibility margin (𝓜₁₁); **both are
safe against every channel in this document.**

### 7.5 Doc-pair discrepancy (finding, for the v4.2 editor)

`btx-matmul-v4-committed-object-redesign.md` (F\* = 𝓜₁₁, S = 3, E_max = 48, "±5 is not
an E2M1 value; larger E2M1 values excluded") and
`btx-matmul-v4-frontier-native-format.md` (BMX4 = 𝓜₁₅, S = 4, E_max = 192, INT8
2-slice tax dial) specify **different committed alphabets under the same v4.2 banner**.
Every hardness conclusion here covers both, but they are different consensus objects
(different samplers, bounds, golden vectors, and old-chip tax: 𝓜₁₁@S=3 keeps INT8
parts 1-GEMM native; 𝓜₁₅@S=4 deliberately forces the 4× slice tax). The v4.2 edition
must pin one before any golden vector is generated.

---

## 8. Confidence, and what could not be verified

| Claim | Confidence | Basis / caveat |
|---|---|---|
| ~23 GB/nonce table-traffic figure confirmed; adversary-optimal variant 8.6 GB/nonce; both ≥ 10²× off viability | **High** | Pure arithmetic (n·(n/t)·m·w) + machine-balance inequalities that hold at any plausible tensor:ALU:bandwidth ratio (§2.4 needs only R ≥ ~10 to close; real R ≈ 10²–10³) |
| Table channel opens only at ≤ ~1.5 effective symbols | **High (as an inequality)** | §2.6; the boundary's exact location moves with SRAM/R but stays ≥ 2 octaves below \|𝓜\| = 11 for any tensor-era parameters |
| Strassen capped at one level (INT8) / zero (FP4/FP8); mantissa-plane recursion closed | **High** | Exact representability arithmetic; format value-sets from the OCP MX spec via the companion docs |
| Practical Strassen gain well under 12.5 % at n = 4096 | **Medium** | Literature-based ([TOMS 2020](https://dl.acm.org/doi/fullHtml/10.1145/3372419), [arXiv:1808.07984](https://arxiv.org/pdf/1808.07984)); not measured on this workload — but the *bound* (12.5 %) is arithmetic and does not need the measurement |
| Singularity ≤ 2⁻²⁰⁴⁸; 2:4 sparsity impossible; zero-skip ≤ 9.1 % | **High** | [Bourgain–Vu–Wood](https://arxiv.org/abs/0905.0461) / [Tikhomirov](https://arxiv.org/abs/1812.09016) + counting arguments |
| BNN-cliff margin ≈ 9× (ternary) / 18–27× (sign); decomposition ≥ direct multiply | **High** | Bit-plane counting + the [Bit Fusion](https://arxiv.org/pdf/1712.01507) width-product law; Turing BMMA 8× rate cross-check is **Medium** (vendor-era figure; INT1 units absent from current silicon anyway) |
| No further small-alphabet channel exists | **Medium-High** | §6 enumeration is exhaustive over the known algorithm literature (four-Russians/Kronrod, mailman, combinatorial BMM, bilinear rank, BNN/bit-serial); "no known algorithm" is not a lower bound — hence condition 7.3-(a) keeps C-15 external review as the mainnet blocker, unchanged |

**Could not verify:** any number on real FP4/FP8 silicon (this repo has no frontier
hardware — same posture as ACTIVATION B2a/B2g; all closure ratios were therefore
derived as inequalities with ≥ 10× slack rather than as point estimates); exact L2
gather throughput under random 11^t-indexed access on any Blackwell-class part (bounded
optimistically in the attacker's favor at streaming peak); the true current INT1/BMMA
status beyond its removal from Hopper-generation documentation.

## References

Repo: `doc/btx-matmul-v4-design-spec.md` (§A.2, §A.6, §C/I1′–I8, §D, §E.3, §K.2a-WT,
§K.2b, §L.4, §S.2, Appendix C-13/C-15) · `doc/btx-matmul-v4-committed-object-redesign.md`
(§2, §4.2, §4.4, §4.5, §8) · `doc/btx-matmul-v4-frontier-native-format.md` (§4, §5).

External:
[Method of Four Russians (Arlazarov–Dinic–Kronrod–Faradzhev)](https://en.wikipedia.org/wiki/Method_of_Four_Russians) ·
[Four-Russians BMM optimality in its class (SIGACT News)](https://dl.acm.org/doi/10.1145/1008591.1008593) ·
[Bard — Four Russians in cryptanalysis (eprint 2006/251)](https://eprint.iacr.org/2006/251.pdf) ·
[Liberty–Zucker — The Mailman algorithm (IPL 2009)](https://www.sciencedirect.com/science/article/abs/pii/S0020019008002949) ([PDF](https://edoliberty.github.io/papers/mailmanAlgorithm.pdf)) ·
[Strassen's Algorithm Reloaded on GPUs (ACM TOMS 2020)](https://dl.acm.org/doi/fullHtml/10.1145/3372419) ·
[Strassen with CUTLASS on Volta (arXiv:1808.07984)](https://arxiv.org/pdf/1808.07984) ·
[Bourgain–Vu–Wood — Singularity of discrete random matrices (JFA 2010)](https://arxiv.org/abs/0905.0461) ·
[Tikhomirov — Singularity of random Bernoulli matrices (Annals 2020)](https://arxiv.org/abs/1812.09016) ·
[Bit Fusion — bit-level composable DNN acceleration (ISCA 2018)](https://arxiv.org/pdf/1712.01507) ·
[BMXNet / XNOR-popcount GEMM (arXiv:1705.09864)](https://arxiv.org/pdf/1705.09864) ·
[BNNs in FPGAs — architectures & hardware comparisons (PMC)](https://pmc.ncbi.nlm.nih.gov/articles/PMC10675041/) ·
[HyBNN — hardware efficiency of BNNs (ACM TRETS)](https://dl.acm.org/doi/10.1145/3631610) ·
[Bit-Tensor-Cores for BNNs in Turing GPUs](https://www.researchgate.net/publication/347849600_Accelerating_Binarized_Neural_Networks_via_Bit-Tensor-Cores_in_Turing_GPUs) ·
[Hopper microbenchmarks — INT4/binary absent (arXiv:2402.13499)](https://arxiv.org/pdf/2402.13499) ·
[SemiAnalysis — tensor core evolution Volta→Blackwell](https://newsletter.semianalysis.com/p/nvidia-tensor-core-evolution-from-volta-to-blackwell) ·
[Blackwell microbenchmarks (arXiv:2512.02189)](https://arxiv.org/html/2512.02189v1) ·
[OCP Microscaling Formats MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf).
