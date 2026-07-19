# BTX MatMul v4.2 — ENC-BMX4C Normative Encoding Specification & Consensus Profile-Versioning Design

*Status: NORMATIVE SPEC for the v4.2 / BMX4-C committed-operand encoding profile
(**ENC-BMX4C**) and for the consensus **encoding-profile versioning machinery**
(L0/L1/L2). This document is the implementable, auditable contract derived from
`doc/btx-matmul-v4.2-consolidated-design.md` (the finalized BMX4-C design — every
parameter below is that document's pinned decision, restated normatively) and
`doc/btx-matmul-v4.2-longevity-threat-model.md` (the migration governance framework,
whose L0/L1/L2 split and Frontier Exactness Ratio trigger are codified here). It
follows the § conventions of `doc/btx-matmul-v4-design-spec.md` (v4.1, authoritative
and UNCHANGED — nothing here edits it) and the C-1 discipline of
`doc/btx-matmul-v4-accumulator-eligibility.md`. Consensus params land (inert) in
`src/consensus/params.h`; gates are tracked in `ACTIVATION.md` Gate C. Per spec
§0.7-(4), no market price appears anywhere below. Written 2026-07-16.*

**Activation status: STAGED and parameter-frozen; `nMatMulBMX4CHeight` is UNSET
(INT32_MAX = disabled) on every network.** Activation is gated per §9 and
ACTIVATION.md Gate C (M-t24 measurement + joint C-15 review + G-1 trigger +
supermajority signaling). RFC-2119 keywords (MUST/MUST NOT/SHOULD/MAY) are
normative.

**Public activation model (updated 2026-07-16, second external audit): unified,
direct v3 → v4.2/ENC-BMX4C.** On every activated public network the invariant is
`nMatMulBMX4CHeight == nMatMulV4Height`: the upgrade forks straight from v3 to
ENC-BMX4C at ONE height, with the single calibrated v3→v4.2 rescale carried by the
BMX4-C rescale (the v4 rescale stays inert `1/1`). **There is NO public ENC-S8
(v4.1) activation interval.** A strictly-greater `nMatMulBMX4CHeight >
nMatMulV4Height` (a non-empty ENC-S8 interval) is retained ONLY as a regtest/testing
option to exercise both sides of the boundary — never as the public activation
model. Mainnet and all public testnets remain DISABLED (both heights INT32_MAX)
until every activation gate passes; no activation date is scheduled.

---

## §0. Scope, hard requirements, and the invariant map

### §0.1 What this profile is

ENC-BMX4C replaces exactly one thing: **how header seeds become exact integer
operands** (and projectors). Everything the v4.1 spec fixes about the machine —
verifier, field, payload, header, digest, Fiat–Shamir, DoS budgets, pooling,
difficulty mechanism — is carried over **byte-for-byte in form**. A v4.2 block is
"new operands into the same machine".

### §0.2 Hard requirements (inviolate, restated as acceptance criteria)

1. **MatMul core.** The per-nonce unit remains one dense n×n exact-integer matmul
   over seed-derived operands (marginal form under I1′: expand B̂, `B̂·V`, combine,
   digest).
2. **Cheap O(n²) Freivalds verification UNCHANGED** (§4): q = 2⁶¹−1, R = 3, b = 4,
   m = n/b = 1024, 8 MiB sketch payload, digest `H(σ‖Ĉ)`, Fiat–Shamir challenges
   from `H(σ‖H(Ĉ))`, per-round error ≤ 2/q, total ≤ 2⁻¹⁸⁰.
3. **Universal bit-exact determinism — no rounding, ever** (§5, C-1′). Every value
   on the committed path is an exactly held integer on every conforming device;
   a device that would round is INELIGIBLE and fails closed.
4. **Scaled-reward ladder, price-independent** (§6, spec §0.7-(4)). Datacenter >
   high-end consumer > M-class-pooled; no market price is an input to any
   parameter.

### §0.3 Invariant core (unchanged from v4.1; normative NON-surface of this fork)

The following MUST be byte-identical in form to the v4.1 spec and MUST NOT be
modified by any ENC-BMX4C implementation: the `SketchFreivalds` verifier structure
and O(n²) cost; q = 2⁶¹−1; R = 3; b = 4 / m = 1024 / 8 MiB sketch payload at
n = 4096 (b = 8 if n is ever retargeted to 8192, m stays 1024); digest form
`H(σ‖Ĉ)` and the Fiat–Shamir rule; the 182-byte header (`matmul_dim` uint16, range
n ≤ 65,535 — preserved by this profile, §2.4); the I1′ seed-scoping rule
(template-scoped A/U/V; nonce-fresh B/σ); invariants I2–I8; the DoS-budget
framework (spec §E.4/§I.5); §L.4's capacity-gate impossibility; §O.2 pooling; the
work-unit-neutrality theorem (§L.2.1); the C-13 fold form
`Ĉ = Σᵢⱼ 2^{w(i+j)}·S_ij mod q`; the verify+fallback dispatcher contract
(`accel_v4.h`); price-independence (§0.7-(4)).

### §0.4 Fork surface (exactly what changes)

Operand/projector derivation and domain tags (§1); the consensus magnitude
constants (§2.4); the combine digit base and its bound check (§3); all golden and
C-1′ adversarial vectors, regenerated at the new boundaries (§5.3, §9); the
one-time ASERT rescale to the measured new marginal unit (§8.4); backend kernels
and self-tests; the §S.2.2/§A.6 re-disclosures. Classification: **hard fork**
(committed-object change — same header ⇒ different operands ⇒ different Ĉ ⇒
different digest), height-gated by `nMatMulBMX4CHeight`, no dual-algorithm grace
period (G.1 precedent).

---

## §1. The ENC-BMX4C operand encoding (normative)

### §1.1 The 𝓜₁₁ mantissa alphabet

Each operand element carries a mantissa

```
μ ∈ 𝓜₁₁ = {0, +1, −1, +2, −2, +3, −3, +4, −4, +6, −6}      (|𝓜₁₁| = 11)
```

— the exact-**integer** subset of FP4 E2M1 (OCP MX v1.0). Structural holes
(the E2M1-hole rule): **±5 is not an E2M1 value and never occurs; ±0.5, ±1.5,
and −0 are excluded** to stay on the integer grid. No committed-path value may
ever take a non-𝓜₁₁ mantissa (enforced by the §5.3 alphabet-hole vectors).

Distribution (i.i.d. uniform over 𝓜₁₁ per element): min-entropy log₂11 ≈ 3.46
bits/element (+0.06 from the scale plane); 5 distinct nonzero magnitudes;
P(μ = 0) = 1/11 ≈ 9.09 %; non-power-of-two mass P(|μ| ∈ {3,6}) = 4/11 ≈ 36.4 %.
These sit at/inside the §7.4 hardness floor (cryptanalysis §7.2/§7.3: SAFE, all
floor conditions met). 𝓜₁₅@S=4 is the documented **hardening reserve** only — a
different consensus object, NOT this profile.

### §1.2 The nibble↦𝓜₁₁ bijection (pinned: identity on the E2M1 bit pattern)

The sampler (§1.5) consumes one 4-bit nibble per element. The accept/decode rule
is **the E2M1 encoding itself** — an accepted nibble IS the element's E2M1 bit
pattern (sign ‖ 2-bit exponent ‖ 1-bit mantissa), so frontier FP4 paths consume
sampler output with zero translation and the CPU reference decodes via this
16-entry table:

| nibble | E2M1 value | action | | nibble | E2M1 value | action |
|---|---|---|---|---|---|---|
| `0x0` | +0   | **accept → 0**  | | `0x8` | −0   | reject |
| `0x1` | +0.5 | reject          | | `0x9` | −0.5 | reject |
| `0x2` | +1   | **accept → +1** | | `0xA` | −1   | **accept → −1** |
| `0x3` | +1.5 | reject          | | `0xB` | −1.5 | reject |
| `0x4` | +2   | **accept → +2** | | `0xC` | −2   | **accept → −2** |
| `0x5` | +3   | **accept → +3** | | `0xD` | −3   | **accept → −3** |
| `0x6` | +4   | **accept → +4** | | `0xE` | −4   | **accept → −4** |
| `0x7` | +6   | **accept → +6** | | `0xF` | −6   | **accept → −6** |

11 of 16 codes accepted (acceptance 11/16 = 68.75 %; expected 16/11 nibbles ⇒
≈ 5.82 XOF bits/element); rejected set = {0x1, 0x3, 0x8, 0x9, 0xB} (exactly the
±0.5/±1.5/−0 holes). Each accepted code has probability 1/16 before rejection, so
the conditional distribution over 𝓜₁₁ is exactly uniform. Zero has a single
representation (+0); −0 is rejected, never canonicalized.

### §1.3 The scale plane (operands only)

Each operand element additionally carries a **per-block power-of-two scale**:

- Block length **L = 32 along the contraction dimension** (OCP MX v1.0
  discipline): for Â in row i, blocks are runs of 32 consecutive columns
  k ∈ [32j, 32j+31]; for B̂ in column j, runs of 32 consecutive rows. One scale
  exponent per (row, block) of A and per (block, column) of B: n²/32 exponents
  per operand at n ≡ 0 (mod 32) (all accepted dims are; n % b == 0 and
  n % 32 == 0 MUST both hold — every v4 window dim 4096/8192 qualifies).
- Exponent **e ∈ {0, 1, 2, 3}** (S = 3). Scale format: E8M0 restricted to codes
  **127..130** (code = e + 127); on consumer hardware hosting scales in UE4M3
  slots, 2^e for e ≤ 3 is exactly representable (exactness verified by the §5.3
  scale-exactness vectors).
- **Fractional scales are permanently excluded** from committed objects (L0 rule,
  §7.2): any profile scale MUST be an exact power of two.
- **U and V carry NO scale plane** (scale-free projectors, §1.4).

The dequantized committed operand entry is the exact integer

```
Â[i,k] = μ_A[i,k] · 2^(e_A(i, ⌊k/32⌋)),      |Â| ≤ E_max = 6·2³ = 48
```

(and symmetrically B̂). E_max = 48 ≤ 127 is the load-bearing inequality: every
INT8 device runs the whole object as **one** s8 GEMM on pre-shifted operands.

### §1.4 The U/V projectors (scale-free 𝓜₁₁; profile P-B, ADOPTED)

`U (m×n)` and `V (n×m)`, m = n/b, are drawn i.i.d. uniform over 𝓜₁₁ via the same
nibble sampler (§1.2), **with no scale plane** (all entries at scale 2⁰), and are
**template-scoped** exactly as v4.1 §A.2/I1′. Consequences (normative bounds):

- `S2: Q = B̂·V` is one block-scaled FP4-rate GEMM on MX hardware, one plain s8
  GEMM on INT8 hardware, one plain FP8 GEMM on E4M3 hardware — 1 GEMM everywhere.
- `|P| = |U·Â| ≤ n·6·48 = 288n` and `|Q| = |B̂·V| ≤ 288n` (< 2²¹ at n = 4096;
  ≈ 2²¹·¹⁷ at n = 8192) — the input bound of the §3 combine.
- Soundness is unaffected: the Freivalds proof never uses the U/V distribution
  (Schwartz–Zippel lives over the F_q challenges). U/V must supply rank m, and
  i.i.d. 11-symbol m×n matrices are rank-m except with probability 2^−Ω(n)
  (Bourgain–Vu–Wood; Tikhomirov) — the same argument as I2.
- The small-alphabet batch-algebra surface this opens is in the mandatory C-15
  review scope (§9, condition R-3).

### §1.5 Seed derivation, domain separation, and the sampler (consensus-normative)

Seed scoping is v4.1's I1′ rule **verbatim** — the template hash binds everything
but the nonce (it zeroes `nNonce64` and the §H.4 per-nonce seed fields and binds
`hashPrevBlock`, height, `hashMerkleRoot`, `nBits`, `matmul_dim`, parent-MTP);
B and σ are nonce-fresh — with v4.2 domain tags:

```
seed_A = SHA256("BTX_MATMUL_SEED_V42"     || template_hash    || 0x41)   # TEMPLATE-scoped
seed_B = SHA256("BTX_MATMUL_SEED_V42"     || full_header_hash || 0x42)   # NONCE-fresh
seed_U = SHA256("BTX_MATMUL_V42_SKETCH_U" || template_hash)              # TEMPLATE-scoped
seed_V = SHA256("BTX_MATMUL_V42_SKETCH_V" || template_hash)              # TEMPLATE-scoped
sigma  = SHA256d(header)                                                 # NONCE-fresh
```

Domain tags are ASCII, no NUL terminator; `0x41`/`0x42` are the single bytes
'A'/'B'. The tags differ from every v4.1 tag, so no keystream byte is shared
between profiles for any header.

**XOF.** The keystream primitive is the v4.1 §A.2/C-12 **wide SHA-256
counter-mode XOF, unchanged**, with one added per-plane domain byte:

```
keystream(seed, plane) = SHA256(seed_bytes(32) ‖ plane ‖ ctr_le64),  ctr = 0,1,2,…
```

concatenated, with plane = `0x6D` ('m') for the mantissa plane and `0x65` ('e')
for the scale plane. Per matrix, each plane draws its own independent
domain-separated keystream from that matrix's seed — so the scale plane's
stream position never depends on the mantissa plane's (data-dependent)
rejection count, and the planes are never correlated (keep in sync with
`matmul_v4_bmx4.cpp::{ExpandMantissaStream, ExpandScaleStream}`).

**Consumption order (pinned).**

1. **Mantissa plane** (all of A, B, U, V; plane byte 'm'). Elements in
   row-major order. Nibbles are consumed low-nibble-first within each keystream
   byte, bytes in stream order. For each element, draw nibbles until one is
   accepted per the §1.2 table (rejection sampling; rejected nibbles are
   discarded and the stream advances). U and V stop here.
2. **Scale plane** (A and B only; plane byte 'e', same seed). One 2-bit code
   per 32-element block, 4 codes per keystream byte consumed from the LSB up
   (bits [1:0], then [3:2], [5:4], [7:6]), bytes in stream order; blocks in
   row-major block order (A: n × n/32 by rows; B: n/32 × n by block-rows —
   i.e. blocks run along each operand's contraction dimension, §1.3). The
   2-bit value IS e (rejection-free).

**No template-scoped structure on B's planes** (redesign condition #6,
restated normative): B̂'s mantissa AND scale planes both derive from `seed_B`
(nonce-fresh). A's, U's, V's planes derive from their own template-scoped seeds.

**XOF volume** (informative): ≈ 5.82 + 2/32 ≈ 5.88 bits/element ⇒ per-nonce
expand-B ≈ 385 k SHA compressions at n = 4096 (~28 % below ENC-S8's 535 k). The
SHA anti-amortization freshness floor survives; verification regeneration gets
cheaper.

**Digest domain tag — decision (F-L2): reuse the v4.1 tag, defer explicit
per-profile separation to fork-time.** The sketch digest is
`H(σ‖Ĉ) = SHA256d("BTX_MATMUL_V4" ‖ σ ‖ payload)` — `ComputeDigestBMX4C` reuses
`matmul::v4::ComputeSketchDigest`, i.e. the **same `"BTX_MATMUL_V4"` digest
domain tag as ENC-S8**, rather than a profile-specific tag.

* **Why it is SAFE today (no per-profile tag required for correctness).** The two
  profiles are **height-disjoint** (a node runs exactly one active profile per
  height, §7.3), and even setting height aside they can never collide: the digest
  binds σ = SHA256d(header) and the payload `Ĉ`, and every ENC-BMX4C operand
  derives from **v4.2 seed/XOF domain tags** (`BTX_MATMUL_SEED_V42`,
  `…_V42_SKETCH_U/V`, plane bytes 'm'/'e') that share no keystream byte with any
  v4.1 tag. So for any fixed header the ENC-S8 and ENC-BMX4C payloads (hence
  digests) differ with overwhelming probability; there is no cross-profile
  collision or replay surface. The reuse is a **defense-in-depth gap, not a
  live bug** (audit F-L2, Low).
* **Why explicit separation is deferred to fork-time rather than landed now.**
  The digest tag is a **shared consensus-encoding parameter reproduced
  byte-for-byte by ≥ 3 independent code paths that MUST stay in lockstep**: the
  single-nonce reference (`ComputeDigestBMX4C`), the batched miner
  (`matmul_v4_bmx4_batch.cpp`, which today calls the shared
  `ComputeSketchDigest`), and every accelerated backend's bit-exactness contract
  (`cuda/hip/metal … _accel`). Threading a profile tag cleanly means changing all
  of them **together** and regenerating the pinned golden digests plus the
  batch/accel bit-exactness fixtures — a coordinated pre-activation encoding
  change, not the "one-line" isolated hardening it first appears to be. Because
  it is SAFE today and ENC-BMX4C is **unactivated**, this is deferred to the
  §7.5 migration pipeline (it can still land before ENC-BMX4C activates). **When
  it lands**, the profile tag (e.g. `"BTX_MATMUL_V42_BMX4C"`) MUST be threaded
  through the digest for the single-nonce, batched, AND accelerated paths in one
  change, and the golden + batch/accel fixtures regenerated against the new
  reference. Tracked in ACTIVATION.md alongside the §7.5 L1 surface.

---

## §2. The committed object and its magnitude bounds

### §2.1 The committed object

The committed product is the **exact integer matrix** `C̄ = Â·B̂` over ℤ, committed
via the unchanged sketch `Ĉ = U·C̄·V` evaluated in F_q (equivalently, and
byte-identically, `Ĉ = P·Q mod q` with `P = U·Â`, `Q = B̂·V` — the §3 combine),
digest `H(σ‖Ĉ)` over the 8 MiB payload. Nothing about payload shape, canonical
residue encoding, or the digest construction changes from v4.1 — including the
digest **domain tag**, which ENC-BMX4C deliberately reuses (`"BTX_MATMUL_V4"`);
see the §1.5 F-L2 decision for why this is safe today and why an explicit
per-profile tag is deferred to fork-time.

### §2.2 Element and product exactness

Mantissa products |μ·μ′| ≤ 36; per-MAC dequantized product |Â·B̂ entry-product|
≤ E_max² = 2304; scale application is a pure exponent add (no significand bits
change) — exact in every format that hosts it (E8M0 by construction; UE4M3 slots
for e ≤ 3; int shift on integer paths).

### §2.3 In-block structure

In-block mantissa dot products (L = 32) are bounded by 32·36 = 1152 < 2¹¹ — the
basis of the mantissa-plane fallback path (§5.2 row 4), exact even at t ≈ 14.

### §2.4 The consensus magnitude table (normative; every gate tests against it)

| Stage | Bound (general n) | n = 4096 | n = 8192 |
|---|---|---|---|
| Dequantized operand `Â`, `B̂` | E_max = 48 | 48 (≤ 127 ⇒ s8-native) | 48 |
| Base product `C̄ = Â·B̂` (full-C / CPU reference) | 2304·n | 9,437,184 ≈ 2²³·¹⁷ **< 2²⁴** | ≈ 2²⁴·¹⁷ |
| Projections `P = U·Â`, `Q = B̂·V` | 288·n | 1,179,648 ≈ 2²⁰·¹⁷ **< 2²¹** | ≈ 2²¹·¹⁷ |
| Limb-pair GEMM `S_ij` (§3) | 1024·n | 4,194,304 = **2²²** | 2²³ |
| In-block mantissa sum (L = 32) | 1152 | < 2¹¹ | < 2¹¹ |
| int32 ceiling from base product | n ≤ ⌊(2³¹−1)/2304⌋ | **932,067** ⇒ full header range n ≤ 65,535 preserved | — |
| Full-C aliasing gap vs q | 2·2304·n | < 2²⁵ ≪ q | < 2²⁶ ≪ q |

Consequences: (i) the **marginal unit** (P/Q and the limb pairs — what difficulty
prices) is ≤ 2²³ at both production dims and ≤ 2²² at mainnet n = 4096; (ii) the
**base product** is < 2²⁴ at n = 4096 ⇒ zero-promotion eligibility by bound on any
proven-t = 24 unit, and ≤ 1 promotion per output at n = 8192 (K′ = 7,264);
(iii) all stages < 2³¹ ⇒ a true int32 accumulator covers the whole pipeline in
one pass at every header dimension.

**Note (F-L1, normative constraint on FP-native backends).**
FP-native accumulator-exactness-*by-bound* is a property of the **marginal unit
that difficulty prices — never of a direct base product `C̄`**:

* The **marginal** GEMMs a committed miner actually forms — the projections
  `P = U·Â`, `Q = B̂·V` (≤ 288·n) and the limb-pair products `S_ij` (≤ 1024·n) —
  stay **< 2²⁴ at every header dimension, n = 8192 included** (288·8192 =
  2,359,296; 1024·8192 = 8,388,608 = 2²³). They are therefore exact-by-bound on
  any proven-t = 24 unit across the whole 4096–8192 window.
* The **direct base product** `C̄ = Â·B̂` is bounded by `2304·n`, which **exceeds
  2²⁴ at n = 8192** (2304·8192 = 18,874,368 > 16,777,216 = 2²⁴). A hypothetical
  *direct-C* FP-native evaluation would thus be **ineligible-by-bound at
  n = 8192** (it needs promotion / a true int32 accumulator — consequence (ii)).

The committed miner path (§2.1, §3) and the CPU reference **never form `C̄` on an
FP unit**: they evaluate `Ĉ = (U·Â)(B̂·V)` through the marginal `P`/`Q`/limb-pair
GEMMs and never materialize the n × n product. **A future accelerated backend
MUST NOT form `C̄` on an FP-native (mantissa-bounded) accumulator at n = 8192**
either — the direct-C shape is only eligible on a true ≥ 32-bit integer
accumulator (the §5.1 C-1′ eligibility invariant; the full-C reference is exact
because it accumulates in int32/int64, not because `C̄` is bounded by 2²⁴). This
constrains only the (non-committed) full-C compute shape; the verifier (§4) is
unaffected — it never forms `C̄`.

---

## §3. The combine (C-13′): base-2⁶ limb-tensor fold, remainder-top rule

The combine computes `Ĉ = P·Q mod q` exactly via the C-13 limb-tensor fold —
retained deliberately (it is the alphabet-independent exact-reduction floor and
~80 % of the marginal unit's tensor MACs) and re-pinned to the new magnitudes:

1. **Digits.** Each entry of P and Q (|·| ≤ 288n ≤ 2²³−1, enforced by §3.4) is
   decomposed into **4 digits in balanced base-2⁶** with the **remainder-top
   rule**: digits d₀..d₂ ∈ [−32, 31] chosen balanced (round-to-nearest with the
   carry convention of the v4.1 reference, base 2⁶ substituted for 2⁷), and the
   top digit d₃ carries the exact remainder, d₃ ∈ [−32, +32], so that
   `x = Σᵢ dᵢ·2^(6i)` exactly for every |x| < 64⁴/2 = 2²³.
2. **Coverage (corrected constants — normative).** A *pure* balanced base-2⁶
   scheme (all four digits ∈ [−32, 31]) covers positive values only up to
   `31·(64⁴−1)/63 = 8,255,455` (note: 8,255,455, not 8,255,527 — the redesign
   doc's figure is off by 72), i.e. 288n only to n ≤ **28,664**. The
   remainder-top rule removes the asymmetric-coverage caveat entirely: totality
   and uniqueness hold for all |x| ≤ 2²³−1, i.e. 288n up to n = **29,127**,
   covering the whole 4096–8192 window with ~3.5× margin.
3. **Pair GEMMs and fold (form unchanged).** 16 limb-pair GEMMs
   `S_ij = P_i·Q_j` (each per-entry bounded by n·32² = 1024n; ≤ 2²² at n = 4096,
   ≤ 2²³ at n = 8192), folded as `Ĉ = Σᵢⱼ 2^{6(i+j)}·S_ij mod q` with weights
   `2^{6(i+j)} mod q` precomputed — O(m²) int-ALU, byte-identical to the direct
   mod-q combine. The stacked §K.2b cross-nonce shape carries over unchanged.
4. **Limb base is miner-local in effect** (any exact re-basing that reproduces
   the committed bytes is legal, e.g. balanced base-2⁴ / 6 digits / 36 pair-GEMMs
   for FP8-only silicon, per-MAC ≤ 64 ⇒ K′ = 256 even at t ≈ 14), but the **CPU
   reference pins base-2⁶** (C-13 discipline) and the golden vectors pin the fold
   bytes.
5. **`CheckCombineLimbBound` successor (normative check).** The v4.1
   `matmul_v4::CheckCombineLimbBound` (base-2⁷, n ≤ 8522-era discipline) is
   superseded on the ENC-BMX4C path by a check pinning

   ```
   288·n ≤ 2²³ − 1        (⇔ n ≤ 29,127)
   ```

   evaluated at chainparams construction and in the reference decomposition's
   debug assertions. Consensus constant: `Consensus::BMX4C_COMBINE_INPUT_BOUND`.

The combine is deliberately NOT made 4-bit-native (an E2M1-digit combine would
cost ~64 pair-GEMMs ≈ 32 FP8-equivalents vs 16 s8 GEMMs — strictly worse on every
part with an INT8 pipe). It runs on whatever exact pipe the device proves.

---

## §4. The verifier — UNCHANGED (normative restatement)

The verifier never touches FP and never sees the compute path. From the header
it re-derives seeds (§1.5), expands the (μ, e) streams, forms `Â = μ·2^e` and `B̂`
as integers via exact shifts, and runs the identical v4.1 machinery:

1. Recompute `H(σ‖Ĉ)` over the shipped 8 MiB sketch payload (m² = 1024² words,
   each a canonical residue mod q; non-canonical ⇒ invalid) and compare to
   `matmul_digest`.
2. For t = 1..R = 3, derive challenges `(xₜ, yₜ)` from `H(σ‖H(Ĉ))` (Fiat–Shamir
   rule unchanged) and check over F_q, q = 2⁶¹−1:

   ```
   xₜᵀ · Ĉ · yₜ  ==  (Uᵀxₜ)ᵀ · Â · (B̂ · (V·yₜ))
   ```

O(n²) per round; per-round false-accept ≤ 2/q (bilinear Schwartz–Zippel —
format-blind: the proof consumes only (P1) canonical F_q object, (P2) bilinear
identity, (P3) nonce-fresh challenges, none of which mention the operand
encoding); total ≤ 2⁻¹⁸⁰ (full-C profile ≤ 2⁻¹⁸³). Per-MAC verify cost is one
64-bit Mersenne multiply-fold with a ≤ 48-magnitude integer — the identical
constant to v4.1. Operand regeneration is ~28 % cheaper in SHA compressions
(§1.5); the verify budget MUST be re-benched ≤ the current v4.1 budget (expected
strictly cheaper; ACTIVATION Gate C item C-B2e′). DoS budgets, payload plumbing,
node tiers, SPV: unchanged.

**The verifier is compute-path-agnostic by construction** (spec §D.3): it would
pass a correct Ĉ from an abacus. Inherited honestly and unchanged: the §E.3
work-binding gap and I1′'s NEEDS-EXTERNAL-REVIEW status (C-15, §9).

---

## §5. Determinism and the accumulator-eligibility gate C-1′

### §5.1 The invariant (normative; generalizes C-1)

> **Exact-integer-arithmetic eligibility (C-1′).** Every backend MUST compute
> every operation on the committed path — scale application, slice/mantissa
> products, every accumulation (base GEMM, `B̂·V`, each limb-pair GEMM),
> extraction, promotion — such that every intermediate value is an exactly held
> integer, whether the unit is nominally integer or floating point. **No
> operation on the committed path may ever round.** A device is eligible for a
> stage iff the stage's §2.4 consensus magnitude bound is ≤ the device's
> **proven** exact-integer capacity for that datapath (2^t for an FP-mantissa
> accumulator; 2^(w−1) for a w-bit two's-complement accumulator), or the backend
> imposes a blocked extract-and-promote schedule (K′) that keeps every partial
> sum inside it. A device that would round anywhere on the committed path is
> INELIGIBLE for that path and MUST fail the determinism self-test loudly; the
> verify+fallback dispatcher (`accel_v4.h`, contract unchanged) re-verifies every
> device result, so a mis-rounding device can only lose throughput, never split
> the chain.

Datasheet claims are never trusted (Hopper's "FP32-accumulate" FP8 path retained
~14 mantissa bits — the standing precedent): "proven" means the device passed the
§5.3 vectors on real silicon, at qualification, with the vectors demonstrably
entering the regime.

**The exactness/determinism argument, in full.** (i) Every committed operand is
an integer with |Â| ≤ 48, exactly representable in E2M1×E8M0, E4M3, FP16/BF16,
s8, and int32. (ii) Every product is an integer ≤ 2304, exact in any multiplier
with ≥ 12 significand bits and in every integer unit. (iii) Every accumulation is
a sum of integers whose running value is bounded by §2.4; below the proven exact
capacity, floating-point addition of exactly representable integers is exact
(the no-rounding theorem, exact-int-on-float doc §2), and integer addition is
exact below 2^(w−1). (iv) Exact integer addition is associative and commutative,
so the result is the same integer under **every** summation order, tiling,
promotion cadence K′, and limb re-basing — committed bytes are
schedule-independent by construction; K′, block ordering, and promotion cadence
are miner-local free choices (L2). (v) Therefore all conforming paths produce
bit-identical committed bytes, and any nonconforming path is rejected by the
dispatcher's re-verification. No rounding function is ever evaluated on the
committed path; there is nothing to canonicalize.

### §5.2 Exactness envelopes per native path (the K′ table; normative bounds)

`K′ = ⌊2^t / per-MAC bound⌋`, floored to a multiple of 32 where the schedule is
MX-block-granular:

| Path | Per-MAC bound | K′ at proven t = 24 | K′ at t ≈ 14 | Verdict |
|---|---|---|---|---|
| Block-scaled FP4/MX, operand GEMM (full-C/reference) | 2304 | 7,264 ⇒ zero promotions at n = 4096; one at n = 8192 | 7 → **0** | **t = 24 REQUIRED** for the native hardware-scaled path |
| Block-scaled FP4/MX, S2 `B̂·V` (the marginal stage) | 288 | 58,254 ⇒ zero promotions at every header n | 56 → 32 (1 MX block; throughput-hostile) | t = 24 for native rate; t ≈ 14 ⇒ fallback |
| FP8 E4M3 scale-fold (values ≤ 48 exact) | 2304 / 288 | as above | as above | t = 24 required |
| FP16/BF16 fold (FP32-accum simdgroup / systolic) | 2304 / 288 | as above | — | eligible with proven t |
| INT8 s8×s8→s32 (IMMA/MFMA/TensorOps/int32-MXU) | operands ≤ 48 ⊂ s8 | true int32: whole pipeline in one pass, no K′ | n/a | the C-1 gate as today; **1 GEMM, no slicing** |
| Limb-pair GEMMs on FP8 (base-2⁴ digit re-slice) | 64 | 2¹⁸ | **256** | the one stage that tolerates t ≈ 14 |

**The eligibility rule for the native block-scaled path: proven t = 24, or fail
closed to the next rung.** The fallback ladder (graceful, fail-closed, bounded):

| Fails | Falls to | GEMM-count tax |
|---|---|---|
| FP4 block-scaled t = 24 unproven | its FP8 fold (needs t ≥ 17 for K′ ≥ 32) | 1× |
| FP8 fold too (t ≈ 14) | **INT8 1-GEMM on pre-shifted operands** (dequant shift is O(n²) int work) — the device's full INT8 rate | **1×** |
| No INT8 tensor unit and FP t unproven | mantissa-plane K′ = 32 extraction (in-block sums ≤ 1152 < 2¹¹, exact even at t ≈ 14), scales applied at promotion | 1× GEMM + heavy extraction |
| Everything | CPU reference via dispatcher | excluded from competitive mining |

This is the profile's headline structural property: under 𝓜₁₁@S=3 the
backwards-compat path is a **single** s8 GEMM (no 4-GEMM slice), which halves the
worst-case accumulator-cliff exposure relative to any E_max > 127 alphabet. The
Ozaki slice machinery remains in the toolbox for hypothetical future pipes
narrower than E2M1 — miner-local, verifier-invisible.

### §5.3 The C-1′ adversarial vector set (regenerated — normative)

The v4.1 HM-A/HM-B/HM-C vectors force accumulations in (2²⁴, 2³¹) that BMX4-C
operands **cannot produce**; replayed verbatim they certify nothing. The v4.2 set
MUST cover, per backend and per claimed path, with analytic expected values and
cross-path byte-equality:

1. **t-discrimination vectors** — rail operands (all-blocks e = 3, extreme
   mantissas) driving base-product partial sums in odd steps across 2¹⁴ and up to
   exactly 2304n (2²³·¹⁷ at n = 4096): a t ≈ 14 device MUST round
   deterministically and FAIL; a t = 24 device MUST be bit-exact with zero
   promotions.
2. **Boundary-pin vectors** — partial sums at exactly the claimed 2^t; limb-pair
   sums at exactly 2²² (n = 4096) and 2²³ (n = 8192); for any miner-local
   base-2⁷ limb variant, sums at exactly 2²⁴ (the FP32-boundary-exact case).
3. **Scale-exactness vectors** — mixed-exponent K-runs; E8M0 application as a
   pure exponent add (no significand change) for all (μ, e) pairs; 2^e hosted in
   UE4M3 scale slots verified exact.
4. **Alphabet-hole vectors** — no slice/mantissa value of ±5 (or any non-𝓜₁₁
   value) may appear anywhere on the committed path; sampler rejection verified
   against pinned keystreams (including pinned rejected-nibble positions).
5. **Sign-extreme / promotion-cadence sweeps** — byte-identity across
   K′ ∈ {32, 256, spec-pinned, unbounded-at-t=24} and across block orders.

Rules carried over verbatim: a log that never entered the regime is NOT a PASS
(`verify-backend.sh` MUST fail if the vectors did not run); backends become
mining-capable only after bit-for-bit replay (M-2/B2a discipline, extended to
FP4/FP8-path devices); the CPU integer reference is the sole source of truth.

---

## §6. The reward ladder and the per-tier tax table

GEMM-count taxes are exact arithmetic (width-ratio law); rate figures are
illustrative cited peaks/measurements, **never load-bearing** — ordering ships
only after the §9 measurements (§K.2b posture; two prior model-based orderings
in this program were falsified by measurement).

| Tier | Devices (examples) | Native path under ENC-BMX4C | GEMMs | Tax vs own frontier rate |
|---|---|---|---|---|
| Frontier DC FP4 | B200/B300/GB300 (mxf4/UE8M0), Rubin-class, MI355X (CDNA4 MX), Trainium3 (Matmul-MX) | native block-scaled FP4, zero promotions at proven t = 24 | **1** | ≈ 1× — the 4–9× Ozaki inversion delivered |
| Frontier DC FP8-only | TPU v7, Trainium2 | scale-fold → 1 plain FP8 GEMM (t = 24 to prove) | 1 | FP8-vs-FP4 gap only |
| INT8 DC legacy | H100/H200, TPU v5e/v6e, Gaudi 3 | pre-shift → 1 s8 GEMM, true int32 | **1** | ≈ 0 — unchanged from today (the 𝓜₁₁ dividend) |
| Consumer frontier | RTX 5090/5080 | FP4 with 2^e in UE4M3 scale slots (exact embed) or INT8 | 1 | ≈ 1× |
| Consumer legacy | RTX 40/30 | INT8 1-GEMM (Ada may prove an FP8 fold) | 1 | ≈ 0 |
| M-class (pooled) | M5-family INT8→INT32; pre-M5 int-ALU tile path | INT8 1-GEMM; pre-M5 general-ALU path preserved (values ≤ 48 trivially in-range) | 1 | ≈ 0; pooled per §O.2 |
| Excluded | CMP/pre-tensor, SHA ASICs, FPGAs | none competitive | — | FPGAs ≥ 13× behind; table/BNN channels closed |

The ladder steepens toward the frontier purely through absolute frontier FP4
throughput, with no punitive tax anywhere: every current miner keeps
approximately current throughput at fork time — which also makes the one-time
ASERT rescale (§8.4) a clean single-population calibration. Availability at fork
time: the entire existing INT8 installed base mines at 1 GEMM.

---

## §7. The consensus profile-versioning architecture (L0/L1/L2)

This section is the normative codification of the longevity framework
(`btx-matmul-v4.2-longevity-threat-model.md` §3) into consensus-facing rules.

### §7.1 The three layers

| Layer | Contents | Change discipline |
|---|---|---|
| **L0 — FIXED FOREVER (the constitution)** | The `SketchFreivalds` verifier structure and its O(n²) cost; **q = 2⁶¹−1**; **R = 3**; the **exact-integer commitment** (the committed object is always an exact integer matmul — no float/stochastic/analog sketch, ever); digest form `H(σ‖Ĉ)` and the Fiat–Shamir rule; the single-thread verify budget that caps n; **price-independence** (§0.7-(4)); invariants I2, I3, I5, I6, I8 and the I7 residue; the §L.4 capacity-gate closure; the **hardness floor** (§7.4); §O.2 proportional pooling; the **C-1′ rule** ("no operation on the committed path may ever round"). | **Never.** A proposal touching L0 is not a format migration — it is a different coin. |
| **L1 — VERSIONED (the encoding profile)** | Everything that defines how header seeds become exact integer operands: mantissa alphabet 𝓜; block length L; scale set / e_max / E_max; U/V alphabet; XOF sampling rule + domain tags; derived magnitude constants (§2.4); limb-combine base + its bound check; n and b *within* the L0 verify budget; **all golden and C-1′ adversarial vectors**; the one-time ASERT rescale Num/Den. **v4/v4.1 pins profile `ENC-S8`** (balanced s8 in [−125, 125], no scales); **v4.2 pins profile `ENC-BMX4C`** (§1–§3). | Only via the §7.5 migration pipeline: trigger → shelf candidate → measurement gates → external review → height-gated hard fork + supermajority signaling. Each version is "parameters and vectors into the same machine", never a fork of the machine. |
| **L2 — MINER-LOCAL (free, no governance)** | The compute path: INT8 IMMA vs FP8/FP4 block-scaled vs Ozaki slices vs mantissa-plane extraction; slice width/count; K′ and promotion cadence; assumed/proven t; limb-base variants; backend Kind; batching window Q. | None — byte-identical committed objects are indistinguishable at every consensus surface. L2 absorbs most frontier motion with zero consensus action; the dispatcher + C-1′ self-tests keep L2 unable to split the chain by construction. |

The load-bearing property: a frontier shift requires L1 action only when the L2
tax it imposes is structural and large (the width-ratio law's k² landing on the
chips the ladder wants to win). Everything smaller stays in L2 forever.

### §7.2 Profile registry (normative)

| Profile ID | enum value | Committed operands | Status |
|---|---|---|---|
| `ENC-S8` | `MatMulEncodingProfile::ENC_S8` = 1 | balanced s8 ∈ [−125, 125], no scale plane; s8 U/V; base-2⁷ limbs (v4.1 spec §A.2/App. C-13) | defined profile; **NOT a public activation candidate** — under the unified direct-to-v4.2 model (`nMatMulBMX4CHeight == nMatMulV4Height`) it has no public height interval; reachable only under a regtest staged config |
| `ENC-BMX4C` | `MatMulEncodingProfile::ENC_BMX4C` = 2 | 𝓜₁₁ × per-32-block 2^e, e ∈ {0..3}; scale-free 𝓜₁₁ U/V; base-2⁶ remainder-top limbs (this doc §1–§3) | staged, parameter-frozen; disabled by default |
| (reserve) `ENC-M15` | — (unassigned) | 𝓜₁₅@S=4 hardening reserve | shelf only; different consensus object; NOT specified here |

Rules: profile IDs are never reused or redefined; a profile, once activated on
any network, is frozen (bug-fix forks define a NEW profile ID). Every future
profile MUST satisfy the §7.4 floor before golden vectors are generated.

### §7.3 Height-based profile selection (how a node picks the active profile)

Exactly **one** profile is live at any height (no dual-profile acceptance
window — multi-format windows would fragment difficulty semantics and hand the
fastest format's miners a within-window monopoly). Selection is a pure function
of height over the consensus params:

```
profile(h) = v3 rules                 for h <  nMatMulV4Height
           = ENC_S8                   for nMatMulV4Height    <= h < nMatMulBMX4CHeight
           = ENC_BMX4C                for h >= nMatMulBMX4CHeight
```

implemented as `Consensus::Params::GetMatMulEncodingProfile(height)` with
`IsBMX4CActive(height)` the underlying predicate (§8.1). **Public activation
model (updated 2026-07-16): unified.** On every activated public network
`nMatMulBMX4CHeight == nMatMulV4Height`, so the `ENC_S8` interval above is EMPTY
and the fork goes directly v3 → ENC_BMX4C at one height. Constraints (enforced at
chainparams construction): `nMatMulBMX4CHeight`, when set, MUST be
`>= nMatMulV4Height` (`==` on every public network — the unified direct-to-v4.2
model; `>` only as a regtest testing option to open a non-empty ENC-S8 interval),
above every already-mined height at release, and never lowered. Reorgs across the
boundary re-validate each block under its own height's profile (pure height
function; no state). Default on every network: INT32_MAX (disabled). A public
network never runs ENC-S8: it either sets both heights equal (unified activation)
or leaves both disabled.

### §7.4 The floor any future profile must satisfy (L0-anchored, normative)

Before any golden vector of an ENC-vNext is generated:

1. **Scales**: powers of two only (E8M0-class), consensus-pinned small exponent
   range; fractional (E4M3-valued) block scales and FP32 tensor scales are
   permanently excluded from committed objects.
2. **Alphabet floor** (anti-BNN/anti-table): min-entropy ≥ ~3.4 bits/element;
   ≥ 4 distinct nonzero magnitudes; P(0) ≤ 10 %; ≥ 2 non-power-of-two magnitudes
   at ≥ ~25 % combined mass (the anti-shift-only clause); sign/ternary objects
   categorically rejected.
3. **Exactness envelope**: all committed-path bounds derivable and pinned (a
   §2.4 analogue); the marginal pipeline sized ≤ the weakest broadly-proven
   commodity exact accumulator class (today 2²⁴); C-1′ vectors regenerated at
   the new boundaries.
4. **Verifier untouched**: q, R, sketch shape, digest, Fiat–Shamir, O(n²)
   budget — re-benched ≤ the current budget.
5. **Gates re-run**: §K.2a-WT/§K.2b analogues on the profile's reference
   silicon; C-15-class external review of any new algebraic surface; §S.2.2
   ASIC re-disclosure.

### §7.5 Migration activation: trigger, pipeline, signaling (normative governance)

**The standing trigger — G-2, the Frontier Exactness Ratio (FER).** For each new
datacenter-class hardware generation g and the live profile v:

```
FER(g, v) = max over L2 paths p [ measured marginal nonce/s on g via p ]
            ─────────────────────────────────────────────────────────────
            measured marginal nonce/s g would achieve if its fastest native
            low-precision pipe ran the committed object at tax 1 (k² = 1)
```

Measured with the pinned instrument (`contrib/matmul-v4/measure-hardware.sh` /
`matmul-v4-report` JSON), never inferred from peak TOPS; published quarterly
together with the **exactness-envelope register** (proven t/K′ per commodity
path). The on-chain corroborator (difficulty-growth vs published compute-stock
envelope) is an audit aid only and can never fire an activation. Per §0.7-(4)
the protocol reads neither signal; humans do.

**Signal states and required actions:**

| State | Condition | Action |
|---|---|---|
| GREEN | FER ≥ ~0.5 on the newest DC generation | none; keep publishing |
| WATCH | FER < 0.5 on one generation, or any commodity fastest-path K′ collapse | fund/refresh the shelf candidate profile |
| ARM | FER < ~0.25 across **two consecutive** DC generations AND the measured marginal nonce/s ordering has flattened/inverted against design intent | take the shelf candidate into the migration pipeline (measurement gates + external review) |
| FIRE | ARM plus the candidate's own gates all green | set the height, run signaling, activate |

Thresholds 0.5/0.25 are governance defaults, re-pinnable in the open **before**
an episode, never retroactively during one.

**The pipeline (every `OperandFormat`/profile version):** (1) shelf phase —
candidate fully specified, hardness re-derived, CPU-reference-implemented before
it is needed; (2) measurement gates — cross-vendor golden vectors byte-identical
on ≥ 2 independent vendors' silicon (and ≥ 3 jurisdictions represented in the
passing set); §K.2a-WT wall-time majority + §K.2b GO/NO-GO on frontier +
consumer + legacy anchors; verify budget re-confirmed; marginal nonce/s measured
for the ASERT rescale; (3) **external adversarial review (C-15 analogue) — a
blocker every time**, scoped to the new alphabet's algebra; (4) activation
mechanics — height-gated hard fork with ≥ 2 release cycles of runway and
**supermajority miner/version signaling as a readiness gate** (a flag-day with no
adoption check risks a split; signaling converts a contentious fork into a
measured upgrade); one-time ASERT rescale from the measured marginal unit on the
path rational miners actually run; (5) pre-committed fallback — if ARM fires but
the candidate fails its gates, the honest fallback is the L2 bridge (Ozaki-class
k² tax) plus difficulty absorbing it; no gate-failed profile may activate
"because the frontier moved".

**Cadence bound:** at most one committed-object migration per two datacenter
hardware generations — in practice ≥ 4 years between activation heights. The
only exception class is a determinism/chain-split defect, handled as an
emergency bugfix under ordinary security process, outside this framework (there
is no soundness-emergency path because soundness is L0-unconditional).

**For ENC-BMX4C specifically**, activation requires BOTH: (a) the roadmap G-1
decoupling trigger confirmed **on shipped silicon** (not launch slides), and
(b) the measured GO/NO-GO passes — M-t24 on ≥ 2 independent vendors' frontier
parts; §K.2a-WT marginal wall-time tensor-majority at Q ≥ 32 on a real FP4 part;
cross-vendor golden vectors including FP4/FP8 devices; the joint C-15 review
closed; the ASERT rescale computed from measurement. **Activation model (updated 2026-07-16, second external audit): the "leapfrog"
is now the adopted public model, not a conditional option.** The upgrade
activates as a single unified fork v3 -> ENC-BMX4C at one height
(`nMatMulBMX4CHeight == nMatMulV4Height`) — one fork instead of two, at no cost
to the INT8 installed base (which mines ENC-BMX4C at 1 GEMM). There is no public
ENC-S8 interval and no separate v4.1 activation. This stays gated on the same
measurements (M-t24 on the frontier parts above, the FP-silicon wall-time split,
the joint C-15 review, the calibrated rescale); until they pass, mainnet and all
public testnets remain DISABLED (both heights INT32_MAX), with no scheduled
activation date. A staged two-fork config (`nMatMulBMX4CHeight > nMatMulV4Height`,
a non-empty ENC-S8 interval) survives only as a regtest testing option.

---

## §8. Consensus parameters and the validation-wiring design

### §8.1 `Consensus::Params` additions (landed, inert; this document's contract)

Namespace-scope profile definitions (compile-time; changing any is a NEW
profile, §7.2):

```cpp
enum class MatMulEncodingProfile : uint8_t { ENC_S8 = 1, ENC_BMX4C = 2 };

BMX4C_MANTISSA_ALPHABET_SIZE = 11      // |M11|
BMX4C_MANTISSA_MAX           = 6       // max |mu|
BMX4C_SCALE_BLOCK_LENGTH     = 32      // OCP MX L, contraction dimension
BMX4C_SCALE_EXPONENT_MAX     = 3       // e in {0..3} (S = 3; E8M0 codes 127..130)
BMX4C_OPERAND_MAG_MAX        = 48      // E_max = 6·2^3  (<= 127: s8-native)
BMX4C_BASE_PRODUCT_BOUND_PER_N = 2304  // |C|  <= 2304·n  (< 2^24 at n = 4096)
BMX4C_PROJECTION_BOUND_PER_N   = 288   // |P|,|Q| <= 288·n (< 2^21 at n = 4096)
BMX4C_COMBINE_LIMBS          = 4       // C-13' digits (16 pair-GEMMs)
BMX4C_COMBINE_LIMB_BASE      = 64      // balanced base-2^6, remainder-top rule
BMX4C_COMBINE_INPUT_BOUND    = 2^23−1  // require 288·n <= 2^23−1 (n <= 29,127)
BMX4C_LIMB_PAIR_BOUND_PER_N  = 1024    // per-entry limb-pair bound (2^22 at 4096)
BMX4C_NATIVE_PATH_PROVEN_T   = 24      // C-1': proven mantissa bits for the native MX path
BMX4C_FALLBACK_INT8_ACCUMULATOR_BITS = 32   // C-1 floor for the 1-GEMM INT8 fallback
```

Per-network `Params` fields and accessors:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `nMatMulBMX4CHeight` | int32 | INT32_MAX (disabled) | ENC-BMX4C profile fork height; when set MUST be `>= nMatMulV4Height` and above every mined height. Public networks set it **`== nMatMulV4Height`** (unified direct-to-v4.2); strictly `>` (a non-empty ENC-S8 interval) is a regtest-only testing option |
| `nMatMulBMX4CAsertRescaleNum` / `Den` | int64 | 1 / 1 | One-time ASERT rescale + re-anchor at the profile fork (B2b analogue; calibrated from the measured ENC-BMX4C marginal unit; 1/1 = no rescale) |
| `nMatMulBMX4CMinProvenAccumulatorBits` | uint32 | 24 | C-1′ qualification threshold t for the native block-scaled path (consensus-protecting: consumed by self-tests/qualification, never by block validation) |
| `IsBMX4CActive(height)` | accessor | — | `IsMatMulV4Active(height) && height >= nMatMulBMX4CHeight` (with the standard INT32_MAX disabled guard) |
| `GetMatMulEncodingProfile(height)` | accessor | — | `ENC_BMX4C` iff `IsBMX4CActive`, else `ENC_S8` (meaningful at v4 heights; §7.3) |

Everything else v4 (dimension, bounds, b, R, budgets, pending caps) is **shared
with ENC-S8 unchanged** — deliberately: the profile versions the encoding, not
the machine.

### §8.2 Validation-wiring design (NOT implemented here; the integration contract)

The integration principle: `GetMatMulEncodingProfile(height)` is the **single
selector**; every profile-dependent call site takes the profile (or the height)
as an argument and contains no second height comparison. The v4 validation
cascade (spec §I.2) is structurally UNCHANGED; only the marked steps become
profile-dispatched:

| Surface | Function(s) | ENC-BMX4C behavior |
|---|---|---|
| Seed derivation | `SetDeterministicMatMulSeeds` / new `DeterministicMatMulSeedV42` (pow.cpp, alongside V1–V4) | at `IsBMX4CActive` heights emit the §1.5 seeds/domain tags; `ContextualCheckBlockHeader` keeps its recompute-and-compare equality check (`bad-matmul-seeds`), dispatching by profile |
| Operand/projector expansion | `ExpandOperand` / projector expansion in `matmul_v4` (consumed by miner AND verifier) | gains a profile argument; ENC_BMX4C path = §1.2 nibble sampler + §1.3 scale plane + exact-shift dequant to int operands (the foundation agent's `matmul_v4_bmx4.*` owns the implementation) |
| Phase1 / structural checks | `CheckMatMulProofOfWork_Phase1`, `ContextualCheckBlockHeader` dim bounds | unchanged (same n, b, dim bounds); add `n % 32 == 0` to the accepted-dim invariant at BMX4C heights (§1.3; trivially true for 4096/8192) |
| Expensive check | `CheckMatMulProofOfWork_V4ProductCommitted` (spec §I.2 cascade steps 1–4) | steps 1 (Phase1), 3 (digest recompute) unchanged; step 2 payload canonicality unchanged for the sketch profile (canonical mod-q residues) — under full-C the per-word magnitude bound becomes `2304·n` (was `15,625·n`); step 4 Freivalds unchanged in form, operands regenerated via the profile-dispatched expander |
| Combine reference | `matmul_v4::CheckCombineLimbBound` successor (e.g. `CheckCombineLimbBoundBMX4C`) | pins `288·n <= 2^23−1`; base-2⁶ remainder-top `DecomposeLimbPlanes` variant; golden vectors pin the fold bytes |
| Difficulty | `GetNextWorkRequired` / ASERT | one-time rescale + re-anchor at `nMatMulBMX4CHeight` via `nMatMulBMX4CAsertRescaleNum/Den`, mechanically identical to the `nMatMulV4AsertRescale*` / `nMatMulAsertRetune2*` pattern |
| Mining | `SolveMatMulV4` / batched miner (`matmul_v4_batch`) | profile-dispatched expansion + pre-shift/native path selection; winner re-derived through the single-nonce reference before sealing (A14 discipline, unchanged) |
| Chainparams | `src/kernel/chainparams.cpp` (5 networks) | assign the §8.1 fields; construction asserts: `nMatMulBMX4CHeight >= nMatMulV4Height` when set (public networks set them **equal** — unified direct-to-v4.2; strictly `>` is a regtest-only staged config); `BMX4C_PROJECTION_BOUND_PER_N · MaxDimension <= BMX4C_COMBINE_INPUT_BOUND`; regtest MAY set a strictly-greater height to exercise both sides of the (otherwise empty) ENC-S8 boundary |
| Self-tests / qualification | `matmul_v4_backend_determinism_tests`, `verify-backend.sh` | §5.3 vector families added per profile; PASS requires the vectors to have entered the regime; `nMatMulBMX4CMinProvenAccumulatorBits` gates the native-path claim |
| Explicitly NOT touched | verifier internals (`SketchFreivalds`), payload plumbing, DoS budget mechanism, header serialization, pooling RPC | — |

Error codes reuse the v4 set (`missing-product-payload`, `invalid-product-payload`,
`bad-matmul-seeds`, `high-hash`); no new reject codes are required — the profile
changes which bytes are correct, not the failure taxonomy.

### §8.3 What is consensus vs miner-local (classification recap)

Consensus (L1, this profile): 𝓜₁₁ + bijection, L = 32, S = 3, U/V alphabet,
domain tags, sampler order, §2.4 constants, base-2⁶ reference combine bound,
golden/C-1′ vectors, `nMatMulBMX4CHeight`, ASERT rescale. Consensus-protecting
(not consensus-changing): C-1′ vectors and the proven-t threshold. Miner-local
(L2): K′, schedules, limb re-basings, embeddings, backend choice, batching Q.

### §8.4 The ASERT rescale (calibration duty)

The ENC-BMX4C marginal unit differs from ENC-S8's (~28 % less XOF; different
GEMM rates per class), so attempts/s shifts by a hardware-dependent factor at
the fork. `nMatMulBMX4CAsertRescaleNum/Den` MUST be calibrated pre-release from
the measured marginal nonce/s on the path rational miners actually run (B2b
analogue; the §6 note that no tier's GEMM count changes makes this a
single-population calibration), and MUST NOT ship at 1/1 on a network with
pre-fork history unless measurement shows the units equal.

---

## §9. Gates, golden vectors, and review (normative preconditions)

Tracked in ACTIVATION.md Gate C; summarized normatively:

1. **M-t24 (THE gating measurement).** The §5.3 t-discrimination and
   boundary-pin vectors run on real block-scaled silicon — B200 and RTX
   5090-class now; extend to B300, MI355X, Trainium3 (NKI) as access permits.
   Decides native-path eligibility per vendor path, which side of the
   ASIC-residual band applies, and whether the FP8-fold tier exists. ENC-BMX4C
   MUST NOT activate without M-t24 PASS on ≥ 2 independent vendors' frontier
   parts.
2. **Joint C-15 external adversarial review (mainnet blocker, commissioned once
   for v4.1 + v4.2).** Scope MUST name verbatim: the I1′ marginal-work floor;
   small-alphabet batch algebra over fixed (P, V) (four-Russians/mailman/table
   family, opening condition ≤ ~1.5 effective symbols); 𝓜-valued template-scoped
   U/V; difficulty-calibration gaming between template refreshes.
3. **Cross-vendor golden vectors** regenerated for ENC-BMX4C (B2a analogue) on
   NVIDIA + AMD + Apple + ≥ 1 FP4/FP8-path device, including the full §5.3
   adversarial set; a replayed s8-era vector set is void; ≥ 2 vendors and ≥ 3
   jurisdictions represented in the passing set.
4. **§K.2a-WT/§K.2b wall-time split** at Q ≥ 32 on a real FP4 part
   (tensor-majority required; the combine's predicted ~70–80 % share is a model,
   not a result).
5. **Verify-budget re-bench** ≤ the v4.1 budget (B2e analogue; expected cheaper).
6. **Spec-text debts due at fork time**: §A.6 Strassen rewrite (**done in design
   spec**: exact alternatives allowed; “≤12.5% / absorbed” posture retired —
   calibrate to fastest known exact; see combine tournament doc); §S.2.2
   ASIC-residual re-disclosure (including the halved t-cliff mechanism:
   ~3–5× under the 1-GEMM INT8 fallback); C-1 → C-1′ codification in the code
   comments (`int8_field.h` / `matmul_v4.h` successors); ρ re-measured on FP4
   rental centrals (disclosure, never a parameter).

---

## §10. Residual open questions (inherited; owners in ACTIVATION.md)

M-t24 outcomes per vendor path (genuinely uncertain on Blackwell TMEM; predicted
PASS on CDNA4/Trn3); mxf4-E8M0 rate parity with NVFP4 and E8M0 survival on
Rubin; NKI explicit committed-scale-tensor support on Trainium3; entropy-floor
slack if the C-15 review demands margin (the pre-analyzed 𝓜₁₅ reserve exists,
with its §2.1-documented costs); the bespoke-ASIC cell/array numbers no
pre-tapeout measurement settles.

## References

`doc/btx-matmul-v4.2-consolidated-design.md` (source of every pinned parameter) ·
`doc/btx-matmul-v4.2-longevity-threat-model.md` (§3 governance, codified in §7) ·
`doc/btx-matmul-v4-design-spec.md` (§0.7, §A.2, §C, §D, §E, §G, §H.4, §I, §K.2a-WT/§K.2b, §L.4, §O.2, App. C-12/C-13/C-15) ·
`doc/btx-matmul-v4-committed-object-redesign.md` (§2 soundness, §3 determinism, §6 migration surface, §8 conditions) ·
`doc/btx-matmul-v4-accumulator-eligibility.md` (C-1) ·
`doc/btx-matmul-v4-bmx4-shortcut-cryptanalysis.md` (§7 floor) ·
`doc/btx-matmul-v4-bmx4-asic-fpga-deepdive.md` (residual/cliff) ·
`doc/btx-matmul-v4-exact-int-on-float.md` (no-rounding theorem) ·
[OCP Microscaling Formats MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf) ·
`src/consensus/params.h` (the §8.1 fields) · `src/matmul/matmul_v4.h`
(`kTileB`, `CheckCombineLimbBound` — the v4.1 constants this profile supersedes
on its own path) · `ACTIVATION.md` Gate C.
